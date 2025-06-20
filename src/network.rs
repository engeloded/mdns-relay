//! Network and socket management for the mDNS relay

use std::collections::HashSet;
use std::ffi::CString;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::Ordering;
use anyhow::{Context, Result};
use get_if_addrs::get_if_addrs;
use mio::net::UdpSocket as MioUdpSocket;
use socket2::{Domain, Protocol, Socket, Type};
use tracing::{debug, info, warn, instrument};

use crate::config::{Config, StackMode};
use crate::RelayError;

/// mDNS port number
pub const MDNS_PORT: u16 = 5353;
/// IPv4 mDNS multicast address
pub const IPV4_MDNS_ADDR: &str = "224.0.0.251";
/// IPv6 mDNS multicast address
pub const IPV6_MDNS_ADDR: &str = "ff02::fb";

/// Portable interface name to index conversion using libc
///
/// # Arguments
/// * `interface_name` - The network interface name (e.g., "eth0", "wlan0")
///
/// # Returns
/// * `Some(u32)` - The interface index if found
/// * `None` - If the interface doesn't exist
pub fn if_nametoindex(interface_name: &str) -> Option<u32> {
    let c_name = CString::new(interface_name).ok()?;
    let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if index == 0 {
        None
    } else {
        Some(index)
    }
}

/// Destination socket with its interface name for clear forwarding logic
///
/// This structure encapsulates a forwarding socket bound to a specific
/// network interface along with the interface name for logging and debugging.
#[derive(Debug)]
pub struct DestinationSocket {
    /// Name of the network interface this socket is bound to
    pub interface_name: String,
    /// The actual UDP socket for sending packets
    pub socket: MioUdpSocket,
}

impl DestinationSocket {
    /// Create a new destination socket
    ///
    /// # Arguments
    /// * `interface_name` - Name of the network interface
    /// * `socket` - Configured UDP socket
    pub fn new(interface_name: String, socket: MioUdpSocket) -> Self {
        Self {
            interface_name,
            socket,
        }
    }
}

impl Drop for DestinationSocket {
    fn drop(&mut self) {
        debug!(interface = %self.interface_name, "Cleaning up destination socket");
    }
}

/// Socket handler with pre-allocated buffer and destination sockets
///
/// This structure manages a listening socket for one network interface/protocol
/// combination and handles packet reception and forwarding to configured destinations.
pub struct MioSocketHandler {
    /// Socket for receiving multicast packets
    pub listening_socket: MioUdpSocket,
    /// Pre-allocated buffer for packet reception (avoids allocations)
    pub buffer: Vec<u8>,
    /// Name of the source interface this handler listens on
    pub src_interface_name: String,
    /// Whether this handler processes IPv6 (true) or IPv4 (false)
    pub is_ipv6: bool,
    /// List of destination sockets for forwarding packets
    pub destination_sockets: Vec<DestinationSocket>,
}

impl MioSocketHandler {
    /// Creates a new socket handler
    ///
    /// # Arguments
    /// * `listening_socket` - Configured listening socket
    /// * `src_interface_name` - Name of source interface
    /// * `is_ipv6` - True for IPv6, false for IPv4
    /// * `destination_sockets` - Vector of destination sockets
    /// * `buffer_size` - Size of receive buffer
    pub fn new(
        listening_socket: MioUdpSocket,
        src_interface_name: String,
        is_ipv6: bool,
        destination_sockets: Vec<DestinationSocket>,
        buffer_size: usize,
    ) -> Self {
        Self {
            listening_socket,
            buffer: vec![0u8; buffer_size],
            src_interface_name,
            is_ipv6,
            destination_sockets,
        }
    }

    /// Receives a packet from the listening socket
    ///
    /// This method performs a non-blocking receive operation and returns
    /// the packet data and source address if available.
    ///
    /// # Returns
    /// * `Ok(Some((len, addr)))` - Packet received with length and source address
    /// * `Ok(None)` - No packet available (EAGAIN/EWOULDBLOCK)
    /// * `Err(e)` - Socket error occurred
    #[instrument(skip(self), fields(interface = %self.src_interface_name, ipv6 = self.is_ipv6))]
    pub fn recv_packet(&mut self) -> Result<Option<(usize, SocketAddr)>> {
        match self.listening_socket.recv_from(&mut self.buffer) {
            Ok((len, addr)) => {
                debug!(
                    src_addr = %addr,
                    bytes = len,
                    "Received packet"
                );
                Ok(Some((len, addr)))
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                Ok(None) // No data available
            }
            Err(e) => {
                debug!(error = %e, "Receive error");
                Err(e.into())
            }
        }
    }

    /// Forwards a packet to all destination interfaces
    ///
    /// This method sends the packet to the appropriate multicast address
    /// on all configured destination interfaces for this source interface.
    ///
    /// # Arguments
    /// * `data` - Packet data to forward
    /// * `stats` - Statistics structure to update
    #[instrument(skip(self, data, stats), fields(
        interface = %self.src_interface_name,
        ipv6 = self.is_ipv6,
        packet_size = data.len(),
        destinations = self.destination_sockets.len()
    ))]
    pub fn forward_packet(&mut self, data: &[u8], stats: &crate::engine::RelayStatistics) -> Result<()> {
        // Choose the appropriate multicast address based on IP version
        let multicast_addr = if self.is_ipv6 {
            SocketAddr::new(
                IPV6_MDNS_ADDR.parse::<Ipv6Addr>()
                    .context("Invalid IPv6 multicast address")?.into(),
                MDNS_PORT
            )
        } else {
            SocketAddr::new(
                IPV4_MDNS_ADDR.parse::<Ipv4Addr>()
                    .context("Invalid IPv4 multicast address")?.into(),
                MDNS_PORT
            )
        };

        let mut forwarded_count = 0;
        let mut error_count = 0;

        // Forward to ALL configured destination interfaces for this source
        for dest in &mut self.destination_sockets {
            match dest.socket.send_to(data, multicast_addr) {
                Ok(_) => {
                    forwarded_count += 1;
                    debug!(
                        dst_interface = %dest.interface_name,
                        "Packet forwarded successfully"
                    );
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    warn!(
                        dst_interface = %dest.interface_name,
                        "Send would block - packet dropped"
                    );
                    error_count += 1;
                }
                Err(e) => {
                    warn!(
                        dst_interface = %dest.interface_name,
                        error = %e,
                        "Failed to send packet"
                    );
                    error_count += 1;
                }
            }
        }

        // Update statistics
        if forwarded_count > 0 {
            debug!(
                forwarded_count,
                total_destinations = self.destination_sockets.len(),
                "Packet forwarding completed"
            );
            stats.packets_forwarded.fetch_add(forwarded_count, Ordering::Relaxed);
        }

        if error_count > 0 {
            stats.socket_errors.fetch_add(error_count, Ordering::Relaxed);
        }

        Ok(())
    }

    /// Gets a reference to the packet buffer slice
    ///
    /// # Arguments
    /// * `len` - Length of valid data in buffer
    ///
    /// # Returns
    /// * Slice containing the packet data
    pub fn get_buffer_slice(&self, len: usize) -> &[u8] {
        &self.buffer[..len]
    }
}

impl Drop for MioSocketHandler {
    fn drop(&mut self) {
        debug!(
            interface = %self.src_interface_name,
            ipv6 = self.is_ipv6,
            "Cleaning up socket handler"
        );
    }
}

/// Creates an IPv4 listening socket for mDNS traffic
///
/// This method creates a socket that binds to 0.0.0.0:5353 and joins the
/// IPv4 mDNS multicast group (224.0.0.251) on the specified interface.
///
/// # Arguments
/// * `interface_name` - The network interface to bind to
///
/// # Returns
/// A configured MioUdpSocket ready for mDNS reception
///
/// # Errors
/// Returns error if interface doesn't exist or socket creation fails
#[instrument(skip_all, fields(interface = %interface_name))]
pub fn create_ipv4_listening_socket(interface_name: &str) -> Result<MioUdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .context("Failed to create IPv4 listening socket")?;

    // Configure socket options for multicast reception
    socket.set_reuse_address(true)
        .context("Failed to set SO_REUSEADDR")?;
    #[cfg(unix)]
    {
        socket.set_reuse_port(true)
            .context("Failed to set SO_REUSEPORT")?;
    }
    socket.set_nonblocking(true)
        .context("Failed to set non-blocking")?;

    // CRITICAL: Bind to INADDR_ANY, not multicast address
    let bind_addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), MDNS_PORT);
    socket.bind(&socket2::SockAddr::from(bind_addr))
        .context("Failed to bind IPv4 socket to 0.0.0.0:5353")?;

    // Bind socket to specific interface (works without IP)
    socket.bind_device(Some(interface_name.as_bytes()))
        .with_context(|| format!("Failed to bind socket to interface {}", interface_name))?;

    // Try to join multicast if interface has IP (don't fail if not)
    let interfaces = get_if_addrs().context("Failed to get interface addresses")?;
    match interfaces
        .iter()
        .find(|iface| iface.name == interface_name && iface.ip().is_ipv4())
        .map(|iface| iface.ip())
    {
        Some(std::net::IpAddr::V4(ipv4_addr)) => {
            let mcast_addr = IPV4_MDNS_ADDR.parse::<Ipv4Addr>()
                .context("Invalid IPv4 multicast address")?;

            // Join the mDNS multicast group on this interface
            socket.join_multicast_v4(&mcast_addr, &ipv4_addr)
                .with_context(|| format!("Failed to join IPv4 multicast group on {}", interface_name))?;

            info!(
                interface = %interface_name,
                bind_addr = "0.0.0.0:5353",
                multicast_addr = %IPV4_MDNS_ADDR,
                interface_ip = %ipv4_addr,
                "IPv4 listening socket created and joined multicast"
            );
        }
        _ => {
            warn!(
                interface = %interface_name,
                bind_addr = "0.0.0.0:5353",
                "IPv4 listening socket created but interface has no IPv4 address - multicast join skipped"
            );
        }
    }

    let std_socket: std::net::UdpSocket = socket.into();
    let mio_socket = MioUdpSocket::from_std(std_socket);

    Ok(mio_socket)
}

/// Creates an IPv6 listening socket for mDNS traffic
///
/// This method creates a socket that binds to [::]:5353 and joins the
/// IPv6 mDNS multicast group (ff02::fb) on the specified interface.
///
/// # Arguments
/// * `interface_name` - The network interface to bind to
///
/// # Returns
/// A configured MioUdpSocket ready for mDNS reception
///
/// # Errors
/// Returns error if interface doesn't exist or socket creation fails
#[instrument(skip_all, fields(interface = %interface_name))]
pub fn create_ipv6_listening_socket(interface_name: &str) -> Result<MioUdpSocket> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))
        .context("Failed to create IPv6 listening socket")?;

    // Configure socket options for multicast reception
    socket.set_reuse_address(true)
        .context("Failed to set SO_REUSEADDR")?;
    #[cfg(unix)]
    {
        socket.set_reuse_port(true)
            .context("Failed to set SO_REUSEPORT")?;
    }
    socket.set_only_v6(true)
        .context("Failed to set IPV6_V6ONLY")?;
    socket.set_nonblocking(true)
        .context("Failed to set non-blocking")?;

    // Bind to [::]:5353
    let bind_addr = SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), MDNS_PORT);
    socket.bind(&socket2::SockAddr::from(bind_addr))
        .context("Failed to bind IPv6 socket to [::]:5353")?;

    // Bind socket to specific interface (works without IP)
    socket.bind_device(Some(interface_name.as_bytes()))
        .with_context(|| format!("Failed to bind IPv6 socket to interface {}", interface_name))?;

    let iface_index = if_nametoindex(interface_name)
        .ok_or_else(|| RelayError::InterfaceNotFound(interface_name.to_string()))?;

    let mcast_addr = IPV6_MDNS_ADDR.parse::<Ipv6Addr>()
        .context("Invalid IPv6 multicast address")?;

    // Configure IPv6 multicast settings
    socket.set_multicast_if_v6(iface_index)
        .context("Failed to set IPv6 multicast interface")?;
    socket.join_multicast_v6(&mcast_addr, iface_index)
        .with_context(|| format!("Failed to join IPv6 multicast group on {}", interface_name))?;
    socket.set_multicast_loop_v6(false)
        .context("Failed to set IPv6 multicast loop")?;
    socket.set_multicast_hops_v6(1)
        .context("Failed to set IPv6 multicast hops")?;

    let std_socket: std::net::UdpSocket = socket.into();
    let mio_socket = MioUdpSocket::from_std(std_socket);

    info!(
        interface = %interface_name,
        bind_addr = "[::]:5353",
        multicast_addr = %IPV6_MDNS_ADDR,
        interface_index = iface_index,
        "IPv6 listening socket created"
    );

    Ok(mio_socket)
}

/// Creates an IPv4 forwarding socket
///
/// This method creates a socket bound to the specified interface
/// for sending multicast packets.
///
/// # Arguments
/// * `dst_interface` - The destination interface name
///
/// # Returns
/// A configured MioUdpSocket ready for sending packets
#[instrument(skip_all, fields(interface = %dst_interface))]
pub fn create_ipv4_forwarding_socket(dst_interface: &str) -> Result<MioUdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .context("Failed to create IPv4 forwarding socket")?;

    socket.set_nonblocking(true)
        .context("Failed to set non-blocking")?;

    // Bind to any available port
    let bind_addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0);
    socket.bind(&socket2::SockAddr::from(bind_addr))
        .context("Failed to bind IPv4 forwarding socket")?;

    // Bind socket to specific interface (works without IP)
    socket.bind_device(Some(dst_interface.as_bytes()))
        .with_context(|| format!("Failed to bind forwarding socket to interface {}", dst_interface))?;

    // Try to set multicast interface if IP available (don't fail if not)
    let interfaces = get_if_addrs()
        .context("Failed to get interface addresses")?;

    match interfaces
        .iter()
        .find(|iface| iface.name == dst_interface && iface.ip().is_ipv4())
        .map(|iface| iface.ip())
    {
        Some(std::net::IpAddr::V4(ipv4_addr)) => {
            // Set the outgoing multicast interface
            socket.set_multicast_if_v4(&ipv4_addr)
                .context("Failed to set IPv4 multicast interface")?;

            debug!(
                interface = %dst_interface,
                ip = %ipv4_addr,
                "IPv4 forwarding socket created with multicast interface"
            );
        }
        _ => {
            warn!(
                interface = %dst_interface,
                "IPv4 forwarding socket created but interface has no IPv4 address - multicast sending may not work"
            );
        }
    }

    let std_socket: std::net::UdpSocket = socket.into();
    let mio_socket = MioUdpSocket::from_std(std_socket);

    Ok(mio_socket)
}

/// Creates an IPv6 forwarding socket
///
/// This method creates a socket configured for sending IPv6 multicast packets
/// on the specified interface.
///
/// # Arguments
/// * `dst_interface` - The destination interface name
///
/// # Returns
/// A configured MioUdpSocket ready for sending packets
#[instrument(skip_all, fields(interface = %dst_interface))]
pub fn create_ipv6_forwarding_socket(dst_interface: &str) -> Result<MioUdpSocket> {
    let iface_index = if_nametoindex(dst_interface)
        .ok_or_else(|| RelayError::InterfaceNotFound(dst_interface.to_string()))?;

    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))
        .context("Failed to create IPv6 forwarding socket")?;

    socket.set_nonblocking(true)
        .context("Failed to set non-blocking")?;

    // Bind to any available port for sending
    let bind_addr = SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0);
    socket.bind(&socket2::SockAddr::from(bind_addr))
        .context("Failed to bind IPv6 forwarding socket")?;

    // Bind socket to specific interface (works without IP)
    socket.bind_device(Some(dst_interface.as_bytes()))
        .with_context(|| format!("Failed to bind IPv6 forwarding socket to interface {}", dst_interface))?;

    // Set the outgoing multicast interface
    socket.set_multicast_if_v6(iface_index)
        .context("Failed to set IPv6 multicast interface")?;

    let std_socket: std::net::UdpSocket = socket.into();
    let mio_socket = MioUdpSocket::from_std(std_socket);

    debug!(
        interface = %dst_interface,
        interface_index = iface_index,
        "IPv6 forwarding socket created"
    );
    Ok(mio_socket)
}

/// Validates that all configured interfaces exist
///
/// This method checks that all interfaces referenced in the configuration
/// actually exist on the system. IP addresses are not required.
///
/// # Arguments
/// * `config` - Configuration to validate
///
/// # Returns
/// * `Result<()>` - Ok if all interfaces exist, Error otherwise
#[instrument(skip(config))]
pub fn validate_interfaces(config: &Config) -> Result<()> {
    let interfaces = get_if_addrs()
        .context("Failed to get system interface list")?;

    let interface_names: HashSet<String> = interfaces
        .iter()
        .map(|iface| iface.name.clone())
        .collect();

    let mut missing_interfaces = Vec::new();
    let mut all_configured_interfaces = HashSet::new();

    // Collect all interface names from configuration
    for iface_config in &config.interface {
        all_configured_interfaces.insert(&iface_config.src);
        all_configured_interfaces.insert(&iface_config.dst);
    }

    // Check if all configured interfaces exist
    for iface_name in &all_configured_interfaces {
        if !interface_names.contains(*iface_name) {
            missing_interfaces.push(iface_name.as_str());
        }
    }

    if !missing_interfaces.is_empty() {
        tracing::error!(
            missing_interfaces = ?missing_interfaces,
            available_interfaces = ?interface_names.iter().collect::<Vec<_>>(),
            "Missing network interfaces"
        );
        return Err(anyhow::anyhow!(
            "Configuration references non-existent interfaces: {}. Please check your network configuration.",
            missing_interfaces.join(", ")
        ));
    }

    info!("All configured interfaces exist");
    Ok(())
}

/// Determine the most permissive stack mode from a list of interface configs
///
/// When multiple interface configs share the same source interface,
/// we need to determine what IP stack mode to use for the listening socket.
///
/// # Arguments
/// * `configs` - Slice of interface configurations
///
/// # Returns
/// * `StackMode` - The most permissive stack mode needed
pub fn determine_stack_mode(configs: &[&crate::config::InterfaceConfig]) -> StackMode {
    if configs.len() == 1 {
        configs[0].stack.clone()
    } else {
        // Find the most permissive stack mode
        configs.iter()
            .map(|c| &c.stack)
            .fold(&configs[0].stack, |acc, mode| {
                match (acc, mode) {
                    (StackMode::Dual, _) | (_, StackMode::Dual) => &StackMode::Dual,
                    (StackMode::Ipv6, StackMode::Ipv4) | (StackMode::Ipv4, StackMode::Ipv6) => &StackMode::Dual,
                    _ => mode
                }
            }).clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Config, InterfaceConfig, StackMode};

    #[test]
    fn test_interface_validation() {
        let config = Config {
            ttl: Some(10),
            cache_size: Some(1000),
            log_level: Some("info".to_string()),
            log_format: Some("pretty".to_string()),
            interface: vec![InterfaceConfig {
                src: "lo".to_string(),    // loopback should exist on most systems
                dst: "lo".to_string(),
                stack: StackMode::Dual,
            }],
            buffer_size: Some(2048),
            max_events: Some(64),
            loop_detection_ms: Some(200),
            stats_interval_seconds: Some(300),
            cleanup_interval_seconds: Some(30),
            max_packet_size: Some(9000),
        };

        // Loopback interface should exist
        assert!(validate_interfaces(&config).is_ok());

        let bad_config = Config {
            ttl: Some(10),
            cache_size: Some(1000),
            log_level: Some("info".to_string()),
            log_format: Some("pretty".to_string()),
            interface: vec![InterfaceConfig {
                src: "nonexistent_interface_12345".to_string(),
                dst: "another_nonexistent_interface_67890".to_string(),
                stack: StackMode::Dual,
            }],
            buffer_size: Some(2048),
            max_events: Some(64),
            loop_detection_ms: Some(200),
            stats_interval_seconds: Some(300),
            cleanup_interval_seconds: Some(30),
            max_packet_size: Some(9000),
        };

        // Non-existent interfaces should fail validation
        assert!(validate_interfaces(&bad_config).is_err());
    }

    #[test]
    fn test_determine_stack_mode() {
        use crate::{InterfaceConfig, StackMode};

        // Single config - should return same stack mode
        let config1 = InterfaceConfig {
            src: "eth0".to_string(),
            dst: "eth1".to_string(),
            stack: StackMode::Ipv4,
        };
        let configs = vec![&config1];
        assert!(matches!(determine_stack_mode(&configs), StackMode::Ipv4));

        // Mixed IPv4 and IPv6 - should return Dual
        let config1 = InterfaceConfig {
            src: "eth0".to_string(),
            dst: "eth1".to_string(),
            stack: StackMode::Ipv4,
        };
        let config2 = InterfaceConfig {
            src: "eth0".to_string(),
            dst: "eth2".to_string(),
            stack: StackMode::Ipv6,
        };
        let configs = vec![&config1, &config2];
        assert!(matches!(determine_stack_mode(&configs), StackMode::Dual));

        // Contains Dual - should return Dual
        let config1 = InterfaceConfig {
            src: "eth0".to_string(),
            dst: "eth1".to_string(),
            stack: StackMode::Ipv4,
        };
        let config2 = InterfaceConfig {
            src: "eth0".to_string(),
            dst: "eth2".to_string(),
            stack: StackMode::Dual,
        };
        let configs = vec![&config1, &config2];
        assert!(matches!(determine_stack_mode(&configs), StackMode::Dual));
    }
}
