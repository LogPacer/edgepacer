//! Streaming source reader — reconnect loop feeding the pipeline actor.
//!
//! The drain side lives in `streaming_actor`: one task per source owns the
//! pipeline, and this reader reaches it only through a [`StreamHandle`].

use std::time::Duration;

use tokio::sync::watch;
use tracing::{info, warn};

use crate::config::{StreamAccessMethod, StreamingSourceConfig};
use crate::docker_stream;
use crate::journald_stream;
use crate::streaming_actor::StreamHandle;

const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Run a streaming reader with exponential backoff reconnect.
pub async fn run_streaming_reader(
    handle: StreamHandle,
    config: StreamingSourceConfig,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut backoff = Duration::from_secs(1);

    loop {
        if *shutdown.borrow() {
            return;
        }

        let checkpoint = match handle.checkpoint().await {
            Ok(checkpoint) => checkpoint,
            Err(_) => {
                warn!(
                    log_source_id = %config.log_source_id,
                    "streaming pipeline actor gone, stopping reader"
                );
                return;
            }
        };

        info!(log_source_id = %config.log_source_id, "starting streaming reader");

        match &config.access_method {
            StreamAccessMethod::DockerApi { container_id } => {
                let since = checkpoint.as_ref().and_then(|cp| cp.docker_since());
                docker_stream::stream_container_logs(
                    &handle,
                    container_id,
                    &config.log_source_id,
                    since,
                    &mut shutdown,
                )
                .await;
            }
            StreamAccessMethod::Journald { unit } => {
                let cursor = checkpoint.as_ref().and_then(|cp| cp.journald_cursor());
                journald_stream::stream_journald_logs(
                    &handle,
                    unit,
                    &config.log_source_id,
                    cursor,
                    &mut shutdown,
                )
                .await;
            }
        }

        if *shutdown.borrow() {
            return;
        }

        warn!(
            log_source_id = %config.log_source_id,
            backoff_secs = backoff.as_secs(),
            "streaming reader disconnected, reconnecting"
        );

        tokio::select! {
            _ = tokio::time::sleep(backoff) => {}
            _ = shutdown.changed() => return,
        }

        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}
