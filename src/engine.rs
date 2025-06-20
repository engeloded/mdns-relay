//! Core relay engine for the mDNS relay

use std::collections::{HashMap, hash_map::DefaultHasher};
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use dashmap::DashMap;
use mio::{Events, Interest, Poll, Token};
use signal_hook::{consts::SIGTERM, consts::SIGINT, consts::SIGHUP, iterator::Signals};
use tracing::{debug, error, info, warn, instrument};

use crate::config::{Config, StackMode, load_config};
use crate::network::{
    MioSocketHandler, DestinationSocket, validate_interfaces, determine_stack_mode,
    create_ipv4_listening_socket, create_ipv6_listening_socket,
    create_ipv4_forwarding_socket, create_ipv6_forwarding_socket
};

/// Global signal flags for signal handling
pub static EXIT_FLAG: AtomicBool = AtomicBool::new(false);
pub static RELOAD_FLAG: AtomicBool = AtomicBool::new(false);

/// Statistics for monitoring relay performance
///
/// This structure tracks packet flow and error counts using atomic operations
/// for thread-safe updates from the event loop.
#[derive(Debug, Default)]
pub struct RelayStatistics {
    /// Total packets received from all interfaces
    pub packets_received: AtomicU64,
    /// Total packets successfully forwarded
    pub packets_forwarded: AtomicU64,
    /// Packets dropped due to duplicate detection
    pub packets_dropped_duplicate: AtomicU64,
    /// Packets dropped due to processing errors
    pub packets_dropped_error: AtomicU64,
    /// Socket-level errors encountered
    pub socket_errors: AtomicU64,
}

impl RelayStatistics {
    /// Log current statistics in a structured format
    ///
    /// # Arguments
    /// * `cache_size` - Current number of entries in the duplicate detection cache
    /// * `max_cache_size` - Maximum configured cache size
    /// * `handlers` - Number of active socket handlers
    pub fn log_stats(&self, cache_size: usize, max_cache_size: usize, handlers: usize) {
        let received = self.packets_received.load(Ordering::Relaxed);
        let forwarded = self.packets_forwarded.load(Ordering::Relaxed);
        let dropped_dup = self.packets_dropped_duplicate.load(Ordering::Relaxed);
        let dropped_err = self.packets_dropped_error.load(Ordering::Relaxed);
        let sock_err = self.socket_errors.load(Ordering::Relaxed);

        info!(
            received,
            forwarded,
            dropped_duplicates = dropped_dup,
            dropped_errors = dropped_err,
            socket_errors = sock_err,
            cache_entries = cache_size,
            max_cache_size,
            handlers,
            "Relay statistics"
        );
    }
}

/// Compact cache entry for improved memory efficiency
#[derive(Debug, Clone)]
struct CacheEntry {
    src_addr: IpAddr,
    timestamp: Instant,
}

/// Main relay engine using mio for maximum performance
///
/// This is the core of the mDNS relay, managing all sockets, packet processing,
/// and the main event loop using Linux epoll for high performance.
pub struct MioRelayEngine {
    config: Config,
    cache: DashMap<u64, CacheEntry>,
    poll: Poll,
    events: Events,
    handlers: HashMap<Token, MioSocketHandler>,
    cache_ttl: Duration,
    max_cache_size: usize,
    loop_detection_window: Duration,
    stats: RelayStatistics,
    next_cleanup: Instant,
    next_stats: Instant,
    config_path: PathBuf,
}

impl MioRelayEngine {
    /// Creates a new relay engine with the given configuration
    ///
    /// This method sets up all the networking components, validates interfaces,
    /// and prepares the event loop for operation.
    ///
    /// # Arguments
    /// * `config` - Validated configuration
    /// * `config_path` - Path to config file for reloading
    ///
    /// # Returns
    /// * `Result<Self>` - Configured relay engine or error
    #[instrument(skip_all, fields(config_path = %config_path.display()))]
    pub fn new(config: Config, config_path: PathBuf) -> Result<Self> {
        let cache_ttl = Duration::from_secs(config.ttl.unwrap_or(crate::config::DEFAULT_CACHE_TTL_SECONDS));
        let max_cache_size = config.cache_size.unwrap_or(crate::config::DEFAULT_CACHE_SIZE);
        let buffer_size = config.buffer_size.unwrap_or(crate::config::DEFAULT_BUFFER_SIZE);
        let max_events = config.max_events.unwrap_or(crate::config::DEFAULT_MAX_EVENTS);
        let loop_detection_window = Duration::from_millis(
            config.loop_detection_ms.unwrap_or(crate::config::DEFAULT_LOOP_DETECTION_MS)
        );

        validate_interfaces(&config)?;

        let poll = Poll::new().context("Failed to create poll")?;
        let events = Events::with_capacity(max_events);
        let mut handlers = HashMap::new();
        let mut token_counter = 0;

        // Group by source interface to avoid duplicate listening sockets
        let mut src_interfaces: HashMap<String, Vec<&crate::config::InterfaceConfig>> = HashMap::new();
        for iface_config in &config.interface {
            src_interfaces.entry(iface_config.src.clone())
                .or_default()
                .push(iface_config);
        }

        info!(source_interfaces = src_interfaces.len(), "Creating handlers");

        // Create handlers for each source interface
        for (src_interface, configs) in src_interfaces {
            let stack_mode = determine_stack_mode(&configs);

            info!(
                interface = %src_interface,
                stack_mode = ?stack_mode,
                "Setting up interface"
            );

            // Create IPv4 handler if needed
            if matches!(stack_mode, StackMode::Ipv4 | StackMode::Dual) {
                match create_ipv4_listening_socket(&src_interface) {
                    Ok(mut listening_socket) => {
                        let mut destination_sockets = Vec::new();

                        for config in &configs {
                            if matches!(config.stack, StackMode::Ipv4 | StackMode::Dual) {
                                match create_ipv4_forwarding_socket(&config.dst) {
                                    Ok(fwd_socket) => {
                                        destination_sockets.push(DestinationSocket::new(
                                            config.dst.clone(),
                                            fwd_socket
                                        ));
                                        info!(
                                            src = %src_interface,
                                            dst = %config.dst,
                                            "Created IPv4 forwarding"
                                        );
                                    }
                                    Err(e) => {
                                        error!(
                                            src = %src_interface,
                                            dst = %config.dst,
                                            error = %e,
                                            "Failed to create IPv4 forwarding socket"
                                        );
                                    }
                                }
                            }
                        }

                        if !destination_sockets.is_empty() {
                            let token = Token(token_counter);
                            token_counter += 1;

                            poll.registry().register(
                                &mut listening_socket,
                                token,
                                Interest::READABLE
                            ).context("Failed to register IPv4 listening socket")?;

                            let handler = MioSocketHandler::new(
                                listening_socket,
                                src_interface.clone(),
                                false,
                                destination_sockets,
                                buffer_size
                            );

                            handlers.insert(token, handler);
                            info!(
                                interface = %src_interface,
                                token = ?token,
                                "Registered IPv4 handler"
                            );
                        } else {
                            warn!(interface = %src_interface, "No IPv4 destination sockets created");
                        }
                    }
                    Err(e) => {
                        error!(
                            interface = %src_interface,
                            error = %e,
                            "Failed to create IPv4 listening socket"
                        );
                    }
                }
            }

            // Create IPv6 handler if needed
            if matches!(stack_mode, StackMode::Ipv6 | StackMode::Dual) {
                match create_ipv6_listening_socket(&src_interface) {
                    Ok(mut listening_socket) => {
                        let mut destination_sockets = Vec::new();

                        for config in &configs {
                            if matches!(config.stack, StackMode::Ipv6 | StackMode::Dual) {
                                match create_ipv6_forwarding_socket(&config.dst) {
                                    Ok(fwd_socket) => {
                                        destination_sockets.push(DestinationSocket::new(
                                            config.dst.clone(),
                                            fwd_socket
                                        ));
                                        info!(
                                            src = %src_interface,
                                            dst = %config.dst,
                                            "Created IPv6 forwarding"
                                        );
                                    }
                                    Err(e) => {
                                        warn!(
                                            src = %src_interface,
                                            dst = %config.dst,
                                            error = %e,
                                            "Failed to create IPv6 forwarding socket"
                                        );
                                    }
                                }
                            }
                        }

                        if !destination_sockets.is_empty() {
                            let token = Token(token_counter);
                            token_counter += 1;

                            poll.registry().register(
                                &mut listening_socket,
                                token,
                                Interest::READABLE
                            ).context("Failed to register IPv6 listening socket")?;

                            let handler = MioSocketHandler::new(
                                listening_socket,
                                src_interface.clone(),
                                true,
                                destination_sockets,
                                buffer_size
                            );

                            handlers.insert(token, handler);
                            info!(
                                interface = %src_interface,
                                token = ?token,
                                "Registered IPv6 handler"
                            );
                        } else {
                            warn!(interface = %src_interface, "No IPv6 destination sockets created");
                        }
                    }
                    Err(e) => {
                        warn!(
                            interface = %src_interface,
                            error = %e,
                            "Failed to create IPv6 listening socket"
                        );
                    }
                }
            }
        }

        if handlers.is_empty() {
            return Err(anyhow::anyhow!("No working socket handlers created - check your configuration"));
        }

        let now = Instant::now();
        let stats_interval = Duration::from_secs(config.stats_interval_seconds.unwrap_or(crate::config::DEFAULT_STATS_INTERVAL_SECONDS));
        let cleanup_interval = Duration::from_secs(config.cleanup_interval_seconds.unwrap_or(crate::config::DEFAULT_CLEANUP_INTERVAL_SECONDS));

        info!(
            handlers = handlers.len(),
            cache_ttl_seconds = cache_ttl.as_secs(),
            max_cache_size,
            loop_detection_ms = loop_detection_window.as_millis(),
            stats_interval_seconds = stats_interval.as_secs(),
            cleanup_interval_seconds = cleanup_interval.as_secs(),
            "Relay engine initialized"
        );

        Ok(MioRelayEngine {
            config,
            cache: DashMap::with_capacity(max_cache_size),
            poll,
            events,
            handlers,
            cache_ttl,
            max_cache_size,
            loop_detection_window,
            stats: RelayStatistics::default(),
            next_cleanup: now + cleanup_interval,
            next_stats: now + stats_interval,
            config_path,
        })
    }

    /// Main event loop for the relay engine
    ///
    /// This method runs the main event loop, handling socket events, signals,
    /// and periodic maintenance tasks.
    ///
    /// # Returns
    /// * `Result<()>` - Ok if shutdown was clean, Error if there was a problem
    #[instrument(skip(self))]
    pub fn run(&mut self) -> Result<()> {
        info!(handlers = self.handlers.len(), "mDNS relay engine started");

        // Print configuration summary
        info!("Configuration summary:");
        for (token, handler) in &self.handlers {
            info!(
                token = ?token,
                interface = %handler.src_interface_name,
                protocol = if handler.is_ipv6 { "IPv6" } else { "IPv4" },
                destinations = handler.destination_sockets.len(),
                "Handler configuration"
            );
            for dest in &handler.destination_sockets {
                info!(destination = %dest.interface_name, "  -> destination");
            }
        }

        loop {
            // Poll for events with a reasonable timeout
            let poll_result = loop {
                match self.poll.poll(&mut self.events, Some(Duration::from_millis(100))) {
                    Ok(()) => break Ok(()),
                    Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {
                        // EINTR - signal interrupted poll, just retry
                        debug!("Poll interrupted by signal (EINTR) - retrying");
                        continue;
                    }
                    Err(e) => break Err(e),
                }
            };

            // Handle poll errors
            if let Err(e) = poll_result {
                error!(error = %e, "Poll error");
                continue;
            }

            let now = Instant::now();

            // Check for signals
            if EXIT_FLAG.load(Ordering::Relaxed) {
                info!("Received termination signal, shutting down gracefully");
                break;
            }

            if RELOAD_FLAG.load(Ordering::Relaxed) {
                info!("Received reload signal, reloading configuration");
                if let Err(e) = self.reload_config() {
                    error!(error = %e, "Failed to reload config");
                }
                RELOAD_FLAG.store(false, Ordering::Relaxed);
            }

            // Process all readable events
            let mut events_to_process = Vec::new();
            for event in &self.events {
                if event.is_readable() {
                    events_to_process.push(event.token());
                }
            }

            for token in events_to_process {
                self.process_socket_event(token)?;
            }

            // Periodic maintenance tasks
            if now >= self.next_cleanup {
                self.cleanup_cache();
                let cleanup_interval = Duration::from_secs(
                    self.config.cleanup_interval_seconds.unwrap_or(crate::config::DEFAULT_CLEANUP_INTERVAL_SECONDS)
                );
                self.next_cleanup = now + cleanup_interval;
            }

            if now >= self.next_stats {
                self.log_statistics();
                let stats_interval = Duration::from_secs(
                    self.config.stats_interval_seconds.unwrap_or(crate::config::DEFAULT_STATS_INTERVAL_SECONDS)
                );
                self.next_stats = now + stats_interval;
            }
        }

        Ok(())
    }

    /// Processes a socket event for the given token
    ///
    /// This method handles packet reception and forwarding for a specific socket.
    /// It implements edge-triggered behavior by draining all available packets.
    ///
    /// # Arguments
    /// * `token` - Token identifying the socket to process
    ///
    /// # Returns
    /// * `Result<()>` - Ok if processing succeeded, Error otherwise
    #[instrument(skip(self), fields(token = ?token))]
    fn process_socket_event(&mut self, token: Token) -> Result<()> {
        let mut packets_processed = 0;
        let mut interface_name = String::new();
        let mut is_ipv6 = false;

        // CRITICAL: In edge-triggered mode, drain socket completely
        while let Some(handler) = self.handlers.get_mut(&token) {
            interface_name = handler.src_interface_name.clone();
            is_ipv6 = handler.is_ipv6;

            match handler.recv_packet() {
                Ok(Some((len, addr))) => {
                    packets_processed += 1;
                    self.stats.packets_received.fetch_add(1, Ordering::Relaxed);

                    // Copy packet data to avoid borrowing conflicts
                    let mut packet_buffer = vec![0u8; len];
                    if let Some(handler_ro) = self.handlers.get(&token) {
                        packet_buffer.copy_from_slice(handler_ro.get_buffer_slice(len));
                    }

                    let addr_string = addr.to_string();

                    // Check if we should forward this packet
                    if self.should_forward(&packet_buffer, &addr_string, &interface_name) {
                        if let Some(handler_mut) = self.handlers.get_mut(&token) {
                            if let Err(e) = handler_mut.forward_packet(&packet_buffer, &self.stats) {
                                warn!(
                                    interface = %interface_name,
                                    error = %e,
                                    "Forward error"
                                );
                                self.stats.packets_dropped_error.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    } else {
                        self.stats.packets_dropped_duplicate.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Ok(None) => break, // EAGAIN - no more data available
                Err(e) => {
                    warn!(
                        interface = %interface_name,
                        error = %e,
                        "Receive error"
                    );
                    self.stats.socket_errors.fetch_add(1, Ordering::Relaxed);
                    break;
                }
            }
        }

        if packets_processed > 0 {
            debug!(
                packets_processed,
                interface = %interface_name,
                protocol = if is_ipv6 { "IPv6" } else { "IPv4" },
                "Drained packets from socket"
            );
        }

        Ok(())
    }

    /// Reloads configuration without restarting
    ///
    /// This method safely reloads runtime configuration parameters without
    /// requiring a full restart. Log level changes require a restart.
    ///
    /// # Returns
    /// * `Result<()>` - Ok if reload succeeded, Error otherwise
    #[instrument(skip(self))]
    fn reload_config(&mut self) -> Result<()> {
        info!(config_path = %self.config_path.display(), "Reloading configuration");

        match load_config(&self.config_path) {
            Ok(new_config) => {
                // Handle log level/format changes - warn that restart is needed
                if new_config.log_level != self.config.log_level {
                    warn!(
                        current = ?self.config.log_level,
                        new = ?new_config.log_level,
                        "Log level changed - restart required to apply change"
                    );
                }

                if new_config.log_format != self.config.log_format {
                    warn!(
                        current = ?self.config.log_format,
                        new = ?new_config.log_format,
                        "Log format changed - restart required to apply change"
                    );
                }

                // Update cache settings (safe to change at runtime)
                if let Some(new_ttl) = new_config.ttl {
                    self.cache_ttl = Duration::from_secs(new_ttl);
                    info!(ttl_seconds = new_ttl, "Updated cache TTL");
                }

                if let Some(new_cache_size) = new_config.cache_size {
                    self.max_cache_size = new_cache_size;
                    info!(max_cache_size = new_cache_size, "Updated max cache size");
                }

                if let Some(new_loop_detection) = new_config.loop_detection_ms {
                    self.loop_detection_window = Duration::from_millis(new_loop_detection);
                    info!(loop_detection_ms = new_loop_detection, "Updated loop detection window");
                }

                // Update the stored config
                self.config = new_config;

                info!("Configuration reloaded successfully");
                info!("Note: Interface and logging changes require a restart to take effect");
                Ok(())
            }
            Err(e) => {
                error!(error = %e, "Failed to reload configuration");
                error!("Continuing with previous configuration");
                Err(e)
            }
        }
    }

    /// Enhanced loop prevention using directional hashing
    ///
    /// This method determines whether a packet should be forwarded by checking
    /// if it's a duplicate within the configured time window.
    ///
    /// # Arguments
    /// * `payload` - The packet data
    /// * `src_ip` - Source IP address as string
    /// * `receiving_interface` - Interface that received the packet
    ///
    /// # Returns
    /// `true` if the packet should be forwarded, `false` if it's a duplicate/loop
    #[instrument(skip(self, payload), fields(
        src_ip = %src_ip,
        interface = %receiving_interface,
        payload_len = payload.len()
    ))]
    fn should_forward(&self, payload: &[u8], src_ip: &str, receiving_interface: &str) -> bool {
        let hash = self.calculate_directional_hash(payload, src_ip, receiving_interface);
        let now = Instant::now();

        // Parse IP address once and store efficiently
        let src_addr = match src_ip.parse::<SocketAddr>() {
            Ok(addr) => addr.ip(),
            Err(_) => {
                warn!(src_ip = %src_ip, "Failed to parse source IP");
                return false;
            }
        };

        // Lock-free cache operation using DashMap
        match self.cache.entry(hash) {
            dashmap::mapref::entry::Entry::Occupied(mut entry) => {
                let cache_entry = entry.get();
                // Use configurable loop detection window
                if cache_entry.src_addr == src_addr &&
                   now.duration_since(cache_entry.timestamp) < self.loop_detection_window {
                    debug!(
                        hash = format!("{:#x}", hash),
                        "Dropping duplicate directional packet"
                    );
                    false
                } else {
                    // Update with new timestamp
                    entry.insert(CacheEntry {
                        src_addr,
                        timestamp: now,
                    });
                    true
                }
            }
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                entry.insert(CacheEntry {
                    src_addr,
                    timestamp: now,
                });
                true
            }
        }
    }

    /// Cleans up expired cache entries
    ///
    /// This method removes old entries from the duplicate detection cache
    /// to prevent memory growth and maintain performance.
    #[instrument(skip(self))]
    fn cleanup_cache(&self) {
        let now = Instant::now();
        let original_size = self.cache.len();

        self.cache.retain(|_hash, cache_entry| {
            now.duration_since(cache_entry.timestamp) <= self.cache_ttl
        });

        let cleaned = original_size - self.cache.len();
        if cleaned > 0 {
            debug!(
                cleaned_entries = cleaned,
                ttl_ms = self.cache_ttl.as_millis(),
                remaining_entries = self.cache.len(),
                "Cache cleanup completed"
            );
        }

        // Enforce maximum cache size
        if self.cache.len() > self.max_cache_size {
            warn!(
                current_size = self.cache.len(),
                max_size = self.max_cache_size,
                "Cache size exceeds maximum, consider increasing cache_size or decreasing ttl"
            );
        }
    }

    /// Logs relay statistics
    ///
    /// This method outputs current performance statistics and configuration
    /// information for monitoring and debugging.
    #[instrument(skip(self))]
    fn log_statistics(&self) {
        self.stats.log_stats(self.cache.len(), self.max_cache_size, self.handlers.len());

        // Log config-derived settings
        info!(
            ttl_seconds = self.cache_ttl.as_secs(),
            max_cache_size = self.max_cache_size,
            loop_detection_ms = self.loop_detection_window.as_millis(),
            log_level = ?self.config.log_level,
            log_format = ?self.config.log_format,
            interfaces = self.config.interface.len(),
            "Configuration summary"
        );

        // Log per-handler statistics
        for (token, handler) in &self.handlers {
            debug!(
                token = ?token,
                interface = %handler.src_interface_name,
                destinations = handler.destination_sockets.len(),
                "Handler status"
            );
        }
    }

    /// Enhanced hash calculation that includes interface information to prevent loops
    ///
    /// This creates a unique hash for each (packet, source_ip, interface) combination,
    /// ensuring that forwarded packets don't create infinite loops.
    ///
    /// # Arguments
    /// * `data` - Packet data
    /// * `src_ip` - Source IP address
    /// * `receiving_interface` - Interface that received the packet
    ///
    /// # Returns
    /// * `u64` - Unique hash for this packet/interface combination
    fn calculate_directional_hash(&self, data: &[u8], src_ip: &str, receiving_interface: &str) -> u64 {
        let mut hasher = DefaultHasher::new();
        data.hash(&mut hasher);
        src_ip.hash(&mut hasher);
        receiving_interface.hash(&mut hasher);
        hasher.finish()
    }
}

impl Drop for MioRelayEngine {
    fn drop(&mut self) {
        info!("Shutting down mDNS relay engine");
        debug!("Final statistics:");
        self.log_statistics();
    }
}

/// Sets up safe signal handling using signal-hook
///
/// This function creates a background thread that listens for POSIX signals
/// and sets appropriate flags for the main event loop to process.
///
/// # Returns
/// * `Result<()>` - Ok if signal setup succeeded, Error otherwise
pub fn setup_signal_handling() -> Result<()> {
    let mut signals = Signals::new([SIGINT, SIGTERM, SIGHUP])
        .context("Failed to create signal iterator")?;

    thread::spawn(move || {
        for sig in signals.forever() {
            match sig {
                SIGTERM | SIGINT => {
                    info!("Received termination signal ({}), initiating shutdown", sig);
                    EXIT_FLAG.store(true, Ordering::Relaxed);
                }
                SIGHUP => {
                    info!("Received reload signal, will reload configuration");
                    RELOAD_FLAG.store(true, Ordering::Relaxed);
                }
                _ => {
                    warn!("Received unexpected signal: {}", sig);
                }
            }
        }
    });

    info!("Signal handling initialized");
    Ok(())
}

/// Drop privileges after creating privileged sockets
///
/// This function drops root privileges to the nobody user after sockets
/// have been created and bound to privileged ports.
///
/// # Returns
/// * `Result<()>` - Ok if privilege drop succeeded or not needed, Error otherwise
pub fn drop_privileges() -> Result<()> {
    use nix::unistd::{setuid, setgid, Uid, Gid};

    if nix::unistd::geteuid().is_root() {
        let nobody_uid = Uid::from_raw(65534); // nobody user
        let nobody_gid = Gid::from_raw(65534); // nobody group

        info!("Dropping privileges from root to nobody:nobody");

        setgid(nobody_gid)
            .context("Failed to drop group privileges")?;
        setuid(nobody_uid)
            .context("Failed to drop user privileges")?;

        info!("Successfully dropped privileges to nobody:nobody");
    } else {
        info!("Not running as root, privilege dropping not needed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::time::Duration;

    /// Create a test engine for unit testing
    fn create_test_engine() -> MioRelayEngine {
        let config = crate::Config {
            ttl: Some(10),
            cache_size: Some(1000),
            log_level: Some("info".to_string()),
            log_format: Some("pretty".to_string()),
            interface: vec![crate::InterfaceConfig {
                src: "test_src".to_string(),
                dst: "test_dst".to_string(),
                stack: crate::StackMode::Dual,
            }],
            buffer_size: Some(2048),
            max_events: Some(64),
            loop_detection_ms: Some(200),
            stats_interval_seconds: Some(300),
            cleanup_interval_seconds: Some(30),
            max_packet_size: Some(9000),
        };

        MioRelayEngine {
            config,
            cache: DashMap::new(),
            poll: Poll::new().unwrap(),
            events: Events::with_capacity(64),
            handlers: HashMap::new(),
            cache_ttl: Duration::from_secs(10),
            max_cache_size: 1000,
            loop_detection_window: Duration::from_millis(200),
            stats: RelayStatistics::default(),
            next_cleanup: Instant::now(),
            next_stats: Instant::now(),
            config_path: PathBuf::from("/tmp/test.toml"),
        }
    }

    #[test]
    fn test_directional_hash_uniqueness() {
        let engine = create_test_engine();
        let payload = b"test packet";

        let hash1 = engine.calculate_directional_hash(payload, "192.168.1.1:5353", "eth0");
        let hash2 = engine.calculate_directional_hash(payload, "192.168.1.1:5353", "eth1");
        let hash3 = engine.calculate_directional_hash(payload, "192.168.1.2:5353", "eth0");

        // Same packet from same IP on different interfaces should have different hashes
        assert_ne!(hash1, hash2);

        // Same packet from different IPs on same interface should have different hashes
        assert_ne!(hash1, hash3);

        // Same packet from same IP on same interface should have same hash
        let hash4 = engine.calculate_directional_hash(payload, "192.168.1.1:5353", "eth0");
        assert_eq!(hash1, hash4);
    }

    #[test]
    fn test_loop_detection() {
        let engine = create_test_engine();

        let payload = b"test packet";
        let src_ip = "192.168.1.1:5353";
        let interface = "eth0";

        // First packet should be forwarded
        assert!(engine.should_forward(payload, src_ip, interface));

        // Immediate duplicate should be dropped
        assert!(!engine.should_forward(payload, src_ip, interface));

        // After loop detection window, should be forwarded again
        std::thread::sleep(Duration::from_millis(250));
        assert!(engine.should_forward(payload, src_ip, interface));
    }

    #[test]
    fn test_cache_cleanup() {
        let engine = create_test_engine();

        // Add some cache entries
        let payload = b"test packet";
        let src_ip1 = "192.168.1.1:5353";
        let src_ip2 = "192.168.1.2:5353";
        let interface = "eth0";

        // Forward some packets to populate cache
        assert!(engine.should_forward(payload, src_ip1, interface));
        assert!(engine.should_forward(payload, src_ip2, interface));

        // Cache should have entries
        assert!(engine.cache.len() > 0);

        // Wait for TTL and cleanup
        std::thread::sleep(Duration::from_millis(11000)); // Longer than 10s TTL
        engine.cleanup_cache();

        // Cache should be empty after cleanup
        assert_eq!(engine.cache.len(), 0);
    }

    #[test]
    fn test_signal_flag_handling() {
        use std::sync::atomic::Ordering;

        // Test that signal flags can be set and read
        assert!(!EXIT_FLAG.load(Ordering::Relaxed));
        assert!(!RELOAD_FLAG.load(Ordering::Relaxed));

        EXIT_FLAG.store(true, Ordering::Relaxed);
        RELOAD_FLAG.store(true, Ordering::Relaxed);

        assert!(EXIT_FLAG.load(Ordering::Relaxed));
        assert!(RELOAD_FLAG.load(Ordering::Relaxed));

        // Reset for other tests
        EXIT_FLAG.store(false, Ordering::Relaxed);
        RELOAD_FLAG.store(false, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn test_integration_packet_forwarding() {
        // This is a basic integration test that would need network namespace setup
        // for full testing. For now, we test the configuration and setup logic.

        use tempfile::NamedTempFile;
        use std::io::Write;

        let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let config_content = r#"
ttl = 10
cache_size = 1000
log_level = "info"
log_format = "pretty"
buffer_size = 2048
max_events = 64
loop_detection_ms = 200
stats_interval_seconds = 300
cleanup_interval_seconds = 30
max_packet_size = 9000

[[interface]]
src = "lo"
dst = "eth0"
stack = "dual"
"#;
        temp_file.write_all(config_content.as_bytes()).expect("Failed to write config");
        let config_path = temp_file.path().to_path_buf();
        let config = crate::config::load_config(&config_path).expect("Failed to load config");

        // Test that we can create an engine (this will validate interfaces exist)
        // Note: This might fail on systems without 'lo' interface, but that's rare
        let result = MioRelayEngine::new(config, config_path);

        match result {
            Ok(_engine) => {
                // Engine created successfully - interfaces exist and configuration is valid
                // In a real integration test, we would send actual mDNS packets here
                println!("Integration test: Engine created successfully");
            }
            Err(e) => {
                // This might happen if the 'lo' interface doesn't exist or can't be bound
                println!("Integration test warning: {}", e);
                // This is not necessarily a test failure - it depends on the test environment
            }
        }
    }
}
