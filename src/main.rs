//! Main entry point for the mDNS relay daemon

use std::path::PathBuf;
use anyhow::{Context, Result};
use clap::{Arg, ArgAction, Command};
use tracing::{info, error, Level};
use tracing_subscriber::{
    fmt,
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter
};

use mdns_relay::{
    config::{load_config, DEFAULT_CONFIG_PATH},
    engine::{MioRelayEngine, setup_signal_handling, drop_privileges},
    Config,
};

/// Version information
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Convert string log level to tracing Level enum
fn parse_log_level(level_str: &str) -> Level {
    match level_str.to_lowercase().as_str() {
        "error" => Level::ERROR,
        "warn" => Level::WARN,
        "info" => Level::INFO,
        "debug" => Level::DEBUG,
        "trace" => Level::TRACE,
        _ => Level::INFO,
    }
}

/// Convert Level enum back to string for display
fn level_to_string(level: Level) -> &'static str {
    match level {
        Level::ERROR => "error",
        Level::WARN => "warn",
        Level::INFO => "info",
        Level::DEBUG => "debug",
        Level::TRACE => "trace",
    }
}

/// Sets up tracing with the specified level and format from config
///
/// This function initializes the tracing subscriber with either JSON or pretty-printed
/// output format based on the configuration. The logger is configured to output to stdout only.
///
/// # Arguments
/// * `config` - Configuration containing log_level and log_format
///
/// # Returns
/// * `Result<()>` - Ok if logging setup succeeded, Error otherwise
fn setup_logging(config: &Config) -> Result<()> {
    let level = parse_log_level(config.log_level.as_deref().unwrap_or("info"));
    let json_format = config.log_format.as_deref() == Some("json");
    let filter = EnvFilter::new(format!("mdns_relay={}", level_to_string(level)));

    if json_format {
        // Structured JSON logging to stdout - ideal for log aggregation systems
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer()
                .json()
                .with_current_span(true)
                .with_span_list(false)  // Reduces noise in JSON output
                .with_target(true)
                .with_thread_ids(true)
                .with_timer(fmt::time::UtcTime::rfc_3339())
                .with_writer(std::io::stdout))
            .init();
    } else {
        // Human-readable format to stdout with microsecond precision
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer()
                .compact()  // More concise than full format
                .with_target(true)
                .with_thread_ids(false)  // Less noise for human reading
                .with_timer(fmt::time::UtcTime::rfc_3339())
                .with_writer(std::io::stdout))
            .init();
    }

    info!(
        level = %level_to_string(level),
        format = if json_format { "json" } else { "pretty" },
        "Logging initialized"
    );
    Ok(())
}

/// Builds the CLI interface using clap
///
/// # Returns
/// * `Command` - Configured clap Command for argument parsing
fn build_cli() -> Command {
    Command::new("mdns-relay")
        .version(VERSION)
        .author("Engel Oded")
        .about("A lightweight, high-performance mDNS relay for IPv4/IPv6 across network segments")
        .long_about("Forwards mDNS multicast packets between network interfaces, enabling service discovery across isolated subnets. Ideal for Matter, HomeKit, and similar protocols.")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Configuration file path")
                .default_value(DEFAULT_CONFIG_PATH)
                .value_parser(clap::value_parser!(PathBuf))
        )
        .arg(
            Arg::new("version")
                .short('v')
                .long("version")
                .help("Print version information")
                .action(ArgAction::Version)
        )
}

/// Main function - entry point for the mDNS relay daemon
///
/// This function handles command line parsing, configuration loading,
/// logging setup, and starts the main relay engine.
///
/// # Returns
/// * `Result<()>` - Ok if program executed successfully, Error otherwise
fn main() -> Result<()> {
    let matches = build_cli().get_matches();
    let config_path = matches.get_one::<PathBuf>("config").unwrap().clone();

    // Load configuration first to get logging settings
    let config = load_config(&config_path)
        .with_context(|| "Failed to load configuration")?;

    // Setup logging based on configuration
    setup_logging(&config)?;

    info!(
        version = VERSION,
        config_path = %config_path.display(),
        "Starting mDNS relay daemon"
    );

    info!(
        interface_pairs = config.interface.len(),
        "Loaded configuration"
    );

    // Print configuration for verification
    for (i, iface) in config.interface.iter().enumerate() {
        info!(
            index = i + 1,
            src = %iface.src,
            dst = %iface.dst,
            stack = ?iface.stack,
            "Interface configuration"
        );
    }

    // Set up signal handling
    setup_signal_handling()
        .context("Failed to set up signal handling")?;

    // Create and run the relay engine
    let mut relay = MioRelayEngine::new(config, config_path.clone())
        .context("Failed to initialize relay engine")?;

    info!("mDNS relay engine initialized successfully");

    // Drop privileges after creating privileged sockets
    drop_privileges()
        .context("Failed to drop privileges")?;

    if let Err(e) = relay.run() {
        error!(error = %e, "Relay engine error");
        return Err(e);
    }

    info!("mDNS relay daemon shutdown complete");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::Level;

    #[test]
    fn test_log_level_parsing() {
        assert_eq!(parse_log_level("error"), Level::ERROR);
        assert_eq!(parse_log_level("ERROR"), Level::ERROR);
        assert_eq!(parse_log_level("warn"), Level::WARN);
        assert_eq!(parse_log_level("info"), Level::INFO);
        assert_eq!(parse_log_level("debug"), Level::DEBUG);
        assert_eq!(parse_log_level("trace"), Level::TRACE);
        assert_eq!(parse_log_level("invalid"), Level::INFO); // Default to INFO
    }

    #[test]
    fn test_privilege_dropping() {
        // Test privilege dropping when not root (should not fail)
        let result = drop_privileges();
        assert!(result.is_ok());

        // Note: Testing actual privilege dropping from root would require
        // running tests as root, which is not recommended for safety
    }
}
