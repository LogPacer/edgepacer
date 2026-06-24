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
    fn source_types_are_distinct() {
        let docker = StreamingSourceType::Docker {
            last_timestamp: "2026-01-01T00:00:00Z".into(),
            container_id: "abc".into(),
        };
        let journald = StreamingSourceType::Journald {
            cursor: "s=abc".into(),
        };
        assert_ne!(docker, journald);
    }
}
