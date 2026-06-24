//! EdgePacer - lightweight edge agent for the LogPacer platform.
//!
//! Handles runtime introspection, metadata reporting, log file tailing,
//! and secure forwarding to LogRelay via the logpacer_wire protocol.

mod runtime;

use clap::Parser;
use edgepacer::config::{AppConfig, Cli};

/// On Linux, use jemalloc with a background purge thread so freed memory is
/// returned to the OS promptly, keeping RSS close to the real working set
/// rather than glibc's high-water per-arena retention. macOS dev builds keep
/// the system allocator.
#[cfg(target_os = "linux")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// Tune jemalloc's page decay so freed pages are returned to the OS quickly.
/// Read by jemalloc at startup via the `_rjem_malloc_conf` symbol
/// (tikv-jemalloc's prefixed config name).
#[cfg(target_os = "linux")]
#[allow(non_upper_case_globals)]
#[unsafe(export_name = "_rjem_malloc_conf")]
pub static malloc_conf: &[u8] = b"background_thread:true,dirty_decay_ms:1000,muzzy_decay_ms:0\0";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let app_config = AppConfig::try_from(cli)?;

    runtime::run(app_config).await
}
