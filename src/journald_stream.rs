//! Journald log streaming — sdjournal primary, journalctl fallback.
//!
//! Streams logs from a systemd unit and enqueues them to the streaming
//! pipeline actor for guaranteed delivery.
//!
//! Resume semantics: cursor-based exact replay. Journald cursors point to
//! a specific log entry, so resume is gap-free (unlike Docker's timestamp-based
//! at-least-once).

use tokio::sync::watch;

use crate::config::MultilineConfig;
use crate::journal;
use crate::streaming_actor::StreamHandle;

/// Stream logs from a systemd unit into the streaming pipeline actor.
pub async fn stream_journald_logs(
    handle: &StreamHandle,
    unit: &str,
    source_id: &str,
    resume_cursor: Option<&str>,
    multiline: Option<&MultilineConfig>,
    shutdown: &mut watch::Receiver<bool>,
) {
    journal::stream_unit_logs(handle, unit, source_id, resume_cursor, multiline, shutdown).await;
}
