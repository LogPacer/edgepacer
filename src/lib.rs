//! EdgePacer library surface for binaries and integration tests.
//!
//! Runtime-only helper modules stay crate-private unless a binary or
//! integration test needs to cross the library boundary.

pub mod agent;
pub mod auth_session;
pub mod batch_tracker;
mod bootstrap;
pub mod buffer;
pub mod checkpoint;
pub mod common;
pub mod config;
pub mod container_reader;
pub mod counters;
mod cri;
pub mod delivery;
pub mod discovery;
mod docker_stream;
pub mod ebpf;
pub mod entry_assembler;
pub mod error_collector;
pub mod host_metrics;
#[cfg(target_os = "macos")]
pub mod host_metrics_darwin;
#[cfg(target_os = "linux")]
pub mod host_metrics_linux;
#[cfg(target_os = "windows")]
pub mod host_metrics_windows;
pub mod identity;
pub mod importer;
mod journal;
mod journald_stream;
pub mod legacy_migration;
pub mod manager;
pub mod metrics_pipeline;
pub mod metrics_shipper;
pub mod orchestrator;
pub mod overflow;
pub mod pipeline;
pub mod rate_limiter;
pub mod retry;
pub mod sampler;
pub mod self_telemetry;
pub mod sender;
pub mod shipper;
pub(crate) mod sqlite_sequence_buffer;
pub mod stats;
pub mod streaming_actor;
pub mod streaming_checkpoint;
pub mod streaming_pipeline;
mod streaming_runner;
pub mod tailer;
pub mod token_store;
pub mod trace_buffer;
pub mod trace_proxy;
pub mod trace_proxy_manager;
pub mod trace_wire;
pub mod tracker;
pub mod upload_token_store;
mod windows_event_log;
