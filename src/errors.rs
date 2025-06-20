//! Error types for the mDNS relay

use thiserror::Error;

/// Custom error types for the mDNS relay
#[derive(Error, Debug)]
pub enum RelayError {
    #[error("Network interface not found: {0}")]
    InterfaceNotFound(String),

    #[error("Failed to create socket: {0}")]
    SocketCreation(#[from] std::io::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Runtime error: {0}")]
    Runtime(String),
}

impl RelayError {
    /// Create a new configuration error
    pub fn config<S: Into<String>>(msg: S) -> Self {
        Self::Config(msg.into())
    }

    /// Create a new runtime error
    pub fn runtime<S: Into<String>>(msg: S) -> Self {
        Self::Runtime(msg.into())
    }

    /// Create a new interface not found error
    pub fn interface_not_found<S: Into<String>>(interface: S) -> Self {
        Self::InterfaceNotFound(interface.into())
    }
}
