//! EdgePacer Manager — supervisor binary for the agent.
//!
//! Handles bootstrap token persistence, process lifecycle (start/stop/restart),
//! auto-updates with rollback, and health monitoring.

pub mod auth;
pub mod process;
pub mod updater;
