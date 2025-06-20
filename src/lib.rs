//! mDNS Relay - A lightweight, high-performance mDNS relay for IPv4/IPv6 across network segments
//!
//! This crate provides a high-performance mDNS relay daemon that forwards mDNS multicast packets
//! between network interfaces, enabling service discovery across isolated subnets. It's ideal for
//! Matter, HomeKit, and similar protocols that rely on mDNS for device discovery.
//!
//! # Features
//!
//! - IPv4 and IPv6 support with configurable stack modes
//! - High-performance event-driven architecture using mio
//! - Loop detection with configurable time windows
//! - Memory-efficient duplicate packet filtering
//! - Comprehensive configuration validation
//! - Signal-based configuration reloading
//! - Structured logging with JSON and pretty-print formats
//! - Privilege dropping for security
//! - Health check capabilities
//!
//! # Example
//!
//! ```no_run
//! use mdns_relay::health_check;
//!
//! // Check the health status of the relay
//! match health_check() {
//!     Ok(status) => println!("Relay status: {}", status),
//!     Err(e) => eprintln!("Health check failed: {}", e),
//! }
//! ```

use std::sync::atomic::Ordering;

// Include all modules
pub mod errors;
pub mod config;
pub mod engine;
pub mod network;

// Re-export commonly used types
pub use errors::RelayError;
pub use config::{Config, InterfaceConfig, StackMode, load_config};
pub use engine::{MioRelayEngine, RelayStatistics};

/// Health check function that can be called to verify relay status
///
/// # Returns
/// * `Ok(String)` - Status string ("OK" or "Shutting down")
/// * `Err(anyhow::Error)` - Error if health check fails
pub fn health_check() -> anyhow::Result<String> {
    let shutting_down = engine::EXIT_FLAG.load(Ordering::Relaxed);
    if shutting_down {
        return Ok("Shutting down".to_string());
    }

    Ok("OK".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn test_health_check() {
        // Test health check with normal state
        let health = health_check().expect("Health check failed");
        assert_eq!(health, "OK");

        // Test health check with shutdown state
        engine::EXIT_FLAG.store(true, Ordering::Relaxed);
        let health = health_check().expect("Health check failed");
        assert_eq!(health, "Shutting down");

        // Reset for other tests
        engine::EXIT_FLAG.store(false, Ordering::Relaxed);
    }
}
