//! Streaming checkpoint — resume tokens for non-replayable sources.
//!
//! Unlike file sources (which can replay from a byte offset in the source file),
//! streaming sources (Docker API, journald, Windows Event Log) cannot replay
//! from an arbitrary position. Their resume tokens are best-effort:
//!
//! - **Docker**: timestamp of the last seen log line. On reconnect, uses Docker API
//!   `since` parameter. Duplicates around the resume point are accepted (at-least-once).
//! - **Journald**: cursor string. Exact replay (no duplicates).
//! - **Windows Event Log**: record ID. Exact replay.
//!
//! These are intentionally different semantic branches sharing a storage location,
//! NOT interchangeable fields.

use std::time::SystemTime;

use serde::{Deserialize, Serialize};

/// Resume token for a streaming source.
///
/// The `source_type` discriminant ensures Docker timestamp and journald cursor
/// are treated as different semantic branches, not interchangeable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamingCheckpoint {
    /// Log source ID from Rails (the identity key).
    pub source_id: String,
    /// Which streaming backend produced this checkpoint.
    pub source_type: StreamingSourceType,
    /// When this checkpoint was last persisted.
    pub updated_at: SystemTime,
}

/// Streaming source type — determines which resume field is meaningful.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "resume_token")]
pub enum StreamingSourceType {
    /// Docker container logs. Resume token is a timestamp (RFC3339Nano).
    /// At-least-once: duplicates around the resume point are accepted.
    Docker {
        /// Last seen log timestamp as RFC3339Nano string.
        /// Passed to Docker API as `since` parameter on reconnect.
        last_timestamp: String,
        /// Container ID being streamed.
        container_id: String,
    },
    /// Journald logs. Resume token is a cursor string.
    /// Exact replay: journald cursors point to a specific log entry.
    Journald {
        /// Journald cursor string for exact resume.
        cursor: String,
    },
    /// Windows Event Log. Resume token is the last delivered record ID.
    /// Exact replay: `wevtutil` can query records after this ID.
    WindowsEventLog {
        /// Event Log channel, e.g. "Application" or "System".
        channel: String,
        /// Last seen EventRecordID.
        record_id: u64,
    },
}

impl StreamingCheckpoint {
    /// Create a Docker streaming checkpoint.
    pub fn docker(source_id: &str, container_id: &str, last_timestamp: &str) -> Self {
        Self {
            source_id: source_id.to_string(),
            source_type: StreamingSourceType::Docker {
                last_timestamp: last_timestamp.to_string(),
                container_id: container_id.to_string(),
            },
            updated_at: SystemTime::now(),
        }
    }

    /// Create a journald streaming checkpoint.
    pub fn journald(source_id: &str, cursor: &str) -> Self {
        Self {
            source_id: source_id.to_string(),
            source_type: StreamingSourceType::Journald {
                cursor: cursor.to_string(),
            },
            updated_at: SystemTime::now(),
        }
    }

    /// Create a Windows Event Log streaming checkpoint.
    pub fn windows_event_log(source_id: &str, channel: &str, record_id: u64) -> Self {
        Self {
            source_id: source_id.to_string(),
            source_type: StreamingSourceType::WindowsEventLog {
                channel: channel.to_string(),
                record_id,
            },
            updated_at: SystemTime::now(),
        }
    }

    /// Extract the Docker `since` parameter for API reconnect, if this is a Docker checkpoint.
    pub fn docker_since(&self) -> Option<&str> {
        match &self.source_type {
            StreamingSourceType::Docker { last_timestamp, .. } => Some(last_timestamp.as_str()),
            _ => None,
        }
    }

    /// Extract the journald cursor for exact resume, if this is a journald checkpoint.
    pub fn journald_cursor(&self) -> Option<&str> {
        match &self.source_type {
            StreamingSourceType::Journald { cursor } => Some(cursor.as_str()),
            _ => None,
        }
    }

    /// Extract the last Windows Event Log record ID, if this checkpoint belongs
    /// to the requested channel.
    pub fn windows_event_record_id(&self, channel: &str) -> Option<u64> {
        match &self.source_type {
            StreamingSourceType::WindowsEventLog {
                channel: checkpoint_channel,
                record_id,
            } if checkpoint_channel.eq_ignore_ascii_case(channel) => Some(*record_id),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_checkpoint_roundtrip() {
        let cp = StreamingCheckpoint::docker("src-123", "abc123", "2026-04-05T10:30:00.123456789Z");

        assert_eq!(cp.source_id, "src-123");
        assert_eq!(cp.docker_since(), Some("2026-04-05T10:30:00.123456789Z"));

        // Serialize and deserialize
        let json = serde_json::to_string(&cp).unwrap();
        let restored: StreamingCheckpoint = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.source_id, "src-123");
        assert_eq!(
            restored.docker_since(),
            Some("2026-04-05T10:30:00.123456789Z")
        );
    }

    #[test]
    fn docker_since_returns_none_for_journald() {
        let cp = StreamingCheckpoint {
            source_id: "src-456".into(),
            source_type: StreamingSourceType::Journald {
                cursor: "s=abc123".into(),
            },
            updated_at: SystemTime::now(),
        };
        assert!(cp.docker_since().is_none());
    }

    #[test]
    fn windows_event_checkpoint_roundtrip() {
        let cp = StreamingCheckpoint::windows_event_log("src-win", "Application", 42);

        assert_eq!(cp.windows_event_record_id("application"), Some(42));
        assert_eq!(cp.windows_event_record_id("System"), None);

        let json = serde_json::to_string(&cp).unwrap();
        let restored: StreamingCheckpoint = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.windows_event_record_id("Application"), Some(42));
    }

    #[test]
    fn source_types_are_distinct() {
        let docker = StreamingSourceType::Docker {
            last_timestamp: "2026-01-01T00:00:00Z".into(),
            container_id: "abc".into(),
        };
        let journald = StreamingSourceType::Journald {
            cursor: "s=abc".into(),
        };
        let windows_event = StreamingSourceType::WindowsEventLog {
            channel: "Application".into(),
            record_id: 1,
        };
        assert_ne!(docker, journald);
        assert_ne!(journald, windows_event);
    }
}
