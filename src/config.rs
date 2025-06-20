//! Configuration management for the mDNS relay

use std::path::PathBuf;
use std::fs;
use anyhow::{Context, Result};
use serde::Deserialize;
use tracing::{info, instrument};

/// Default configuration constants
pub const DEFAULT_BUFFER_SIZE: usize = 2048;
pub const DEFAULT_MAX_EVENTS: usize = 64;
pub const DEFAULT_LOOP_DETECTION_MS: u64 = 200;
pub const DEFAULT_CACHE_TTL_SECONDS: u64 = 10;
pub const DEFAULT_CACHE_SIZE: usize = 1000;
pub const DEFAULT_STATS_INTERVAL_SECONDS: u64 = 300; // 5 minutes
pub const DEFAULT_CLEANUP_INTERVAL_SECONDS: u64 = 30;
pub const DEFAULT_MAX_PACKET_SIZE: usize = 9000; // Support jumbo frames
pub const DEFAULT_CONFIG_PATH: &str = "/etc/mdns-relay.toml";

/// Network stack configuration for interfaces
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum StackMode {
    /// IPv4 only
    Ipv4,
    /// IPv6 only
    Ipv6,
    /// Both IPv4 and IPv6 (default)
    Dual,
}

/// Default stack mode when not specified
pub fn default_stack() -> StackMode {
    StackMode::Dual
}

/// Configuration for an interface pair (source -> destination)
#[derive(Debug, Deserialize)]
pub struct InterfaceConfig {
    /// Source interface name (where packets are received)
    pub src: String,
    /// Destination interface name (where packets are forwarded)
    pub dst: String,
    /// Network stack mode for this interface pair
    #[serde(default = "default_stack")]
    pub stack: StackMode,
}

/// Main configuration structure loaded from TOML file
///
/// This structure defines all configurable parameters for the mDNS relay,
/// with sensible defaults for production use.
#[derive(Debug, Deserialize)]
pub struct Config {
    /// Cache entry TTL in seconds (default: 10)
    /// Controls how long to remember packets to prevent loops
    pub ttl: Option<u64>,

    /// Maximum cache size in entries (default: 1000)
    /// Limits memory usage for the duplicate detection cache
    pub cache_size: Option<usize>,

    /// Log level: error, warn, info, debug, trace (default: info)
    /// Controls verbosity of log output
    pub log_level: Option<String>,

    /// Log format: pretty or json (default: pretty)
    /// pretty = human-readable, json = structured for log aggregation
    pub log_format: Option<String>,

    /// Interface forwarding configuration
    /// Each entry defines a source -> destination forwarding rule
    pub interface: Vec<InterfaceConfig>,

    /// Packet buffer size in bytes (default: 2048)
    /// Should be large enough for typical mDNS packets
    pub buffer_size: Option<usize>,

    /// Maximum number of events per poll (default: 64)
    /// Higher values can improve throughput but increase latency
    pub max_events: Option<usize>,

    /// Loop detection window in milliseconds (default: 200)
    /// How long to remember packets for duplicate detection
    pub loop_detection_ms: Option<u64>,

    /// Statistics reporting interval in seconds (default: 300)
    /// How often to log performance statistics
    pub stats_interval_seconds: Option<u64>,

    /// Cache cleanup interval in seconds (default: 30)
    /// How often to clean expired entries from the cache
    pub cleanup_interval_seconds: Option<u64>,

    /// Maximum packet size to process (default: 9000)
    /// Supports jumbo frames for high-performance networks
    pub max_packet_size: Option<usize>,
}

impl Config {
    /// Validates the configuration for correctness and consistency
    ///
    /// This method performs comprehensive validation of all configuration
    /// parameters to catch errors early before starting the relay engine.
    #[instrument(skip(self))]
    pub fn validate(&self) -> Result<()> {
        // Validate that at least one interface pair is configured
        if self.interface.is_empty() {
            return Err(anyhow::anyhow!("No interface pairs configured"));
        }

        // Validate each interface pair
        for (i, iface) in self.interface.iter().enumerate() {
            if iface.src.is_empty() || iface.dst.is_empty() {
                return Err(anyhow::anyhow!("Interface pair {} has empty src or dst", i + 1));
            }
            if iface.src == iface.dst {
                return Err(anyhow::anyhow!("Interface pair {} has same src and dst: {}", i + 1, iface.src));
            }
        }

        // Validate buffer size
        if let Some(buffer_size) = self.buffer_size {
            if !(64..=65536).contains(&buffer_size) {
                return Err(anyhow::anyhow!("Buffer size must be between 64 and 65536 bytes"));
            }
        }

        // Validate cache size
        if let Some(cache_size) = self.cache_size {
            if cache_size == 0 {
                return Err(anyhow::anyhow!("Cache size must be greater than 0"));
            }
        }

        // Validate TTL
        if let Some(ttl) = self.ttl {
            if ttl == 0 {
                return Err(anyhow::anyhow!("TTL must be greater than 0"));
            }
        }

        // Validate log format
        if let Some(ref log_format) = self.log_format {
            if !matches!(log_format.as_str(), "pretty" | "json") {
                return Err(anyhow::anyhow!("Log format must be 'pretty' or 'json', got: {}", log_format));
            }
        }

        // Validate log level
        if let Some(ref log_level) = self.log_level {
            match log_level.to_lowercase().as_str() {
                "error" | "warn" | "info" | "debug" | "trace" => {},
                _ => return Err(anyhow::anyhow!("Log level must be one of: error, warn, info, debug, trace, got: {}", log_level)),
            }
        }

        // Validate intervals
        if let Some(stats_interval) = self.stats_interval_seconds {
            if stats_interval == 0 {
                return Err(anyhow::anyhow!("Stats interval must be greater than 0"));
            }
        }

        if let Some(cleanup_interval) = self.cleanup_interval_seconds {
            if cleanup_interval == 0 {
                return Err(anyhow::anyhow!("Cleanup interval must be greater than 0"));
            }
        }

        // Validate packet size
        if let Some(max_packet_size) = self.max_packet_size {
            if !(64..=65536).contains(&max_packet_size) {
                return Err(anyhow::anyhow!("Max packet size must be between 64 and 65536 bytes"));
            }
        }

        info!("Configuration validation passed");
        Ok(())
    }

    /// Apply defaults for missing configuration values
    pub fn apply_defaults(&mut self) {
        if self.buffer_size.is_none() {
            self.buffer_size = Some(DEFAULT_BUFFER_SIZE);
        }
        if self.max_events.is_none() {
            self.max_events = Some(DEFAULT_MAX_EVENTS);
        }
        if self.loop_detection_ms.is_none() {
            self.loop_detection_ms = Some(DEFAULT_LOOP_DETECTION_MS);
        }
        if self.ttl.is_none() {
            self.ttl = Some(DEFAULT_CACHE_TTL_SECONDS);
        }
        if self.cache_size.is_none() {
            self.cache_size = Some(DEFAULT_CACHE_SIZE);
        }
        if self.stats_interval_seconds.is_none() {
            self.stats_interval_seconds = Some(DEFAULT_STATS_INTERVAL_SECONDS);
        }
        if self.cleanup_interval_seconds.is_none() {
            self.cleanup_interval_seconds = Some(DEFAULT_CLEANUP_INTERVAL_SECONDS);
        }
        if self.max_packet_size.is_none() {
            self.max_packet_size = Some(DEFAULT_MAX_PACKET_SIZE);
        }
        if self.log_level.is_none() {
            self.log_level = Some("info".to_string());
        }
        if self.log_format.is_none() {
            self.log_format = Some("pretty".to_string());
        }
    }
}

/// Loads and validates configuration from TOML file
///
/// This function reads the configuration file, applies defaults for missing values,
/// and validates the configuration for correctness.
///
/// # Arguments
/// * `config_path` - Path to the TOML configuration file
///
/// # Returns
/// * `Result<Config>` - Parsed and validated configuration or error
#[instrument(skip_all, fields(config_path = %config_path.display()))]
pub fn load_config(config_path: &PathBuf) -> Result<Config> {
    let config_str = fs::read_to_string(config_path)
        .with_context(|| format!("Failed to read config file: {}", config_path.display()))?;

    let mut config: Config = toml::from_str(&config_str)
        .with_context(|| format!("Failed to parse config file: {}", config_path.display()))?;

    // Apply defaults for missing configuration values
    config.apply_defaults();

    // Validate configuration
    config.validate()?;

    info!(
        interfaces = config.interface.len(),
        buffer_size = config.buffer_size,
        cache_size = config.cache_size,
        ttl_seconds = config.ttl,
        log_level = config.log_level.as_deref().unwrap_or("info"),
        log_format = config.log_format.as_deref().unwrap_or("pretty"),
        "Configuration loaded successfully"
    );

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;

    /// Create a valid test configuration file
    fn create_test_config() -> Result<NamedTempFile, std::io::Error> {
        let mut temp_file = NamedTempFile::new()?;

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

        temp_file.write_all(config_content.as_bytes())?;
        Ok(temp_file)
    }

    #[test]
    fn test_config_validation() {
        let mut config = Config {
            ttl: Some(10),
            cache_size: Some(1000),
            log_level: Some("info".to_string()),
            log_format: Some("pretty".to_string()),
            interface: vec![],
            buffer_size: Some(2048),
            max_events: Some(64),
            loop_detection_ms: Some(200),
            stats_interval_seconds: Some(300),
            cleanup_interval_seconds: Some(30),
            max_packet_size: Some(9000),
        };

        // Empty interface list should fail
        assert!(config.validate().is_err());

        // Valid config should pass
        config.interface.push(InterfaceConfig {
            src: "eth0".to_string(),
            dst: "eth1".to_string(),
            stack: StackMode::Dual,
        });
        assert!(config.validate().is_ok());

        // Same src and dst should fail
        config.interface.push(InterfaceConfig {
            src: "eth0".to_string(),
            dst: "eth0".to_string(),
            stack: StackMode::Dual,
        });
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_file_loading() {
        let temp_file = create_test_config().expect("Failed to create test config");
        let config_path = temp_file.path().to_path_buf();

        let config = load_config(&config_path).expect("Failed to load config");

        assert_eq!(config.ttl, Some(10));
        assert_eq!(config.cache_size, Some(1000));
        assert_eq!(config.log_level, Some("info".to_string()));
        assert_eq!(config.interface.len(), 1);
        assert_eq!(config.interface[0].src, "lo");
        assert_eq!(config.interface[0].dst, "eth0");
    }
}
