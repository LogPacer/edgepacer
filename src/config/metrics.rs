use super::UnifiedConfig;
use super::fields::{
    ArchiveId, ConfigFieldError, ConfigParseReport, FieldContext, MetricSourceId, RepoId,
    WireEndpoint, positive_u64_field_or, required_config_key_result, required_config_string_result,
};

/// A metrics stream extracted from unified config - enough to drive metrics shipping.
#[derive(Debug, Clone)]
pub struct MetricsStreamConfig {
    pub metric_source_id: String,
    pub subbox_endpoint: String,
    pub archive_id: String,
    pub repo_id: String,
    pub collection_interval_secs: u64,
    pub send_interval_secs: u64,
}

/// Extract all metrics streams from unified config.
///
/// The metrics section is a map keyed by `metric_source_id`, not an array.
/// Entries missing required fields (subbox_endpoint, archive_id, repo_id) are skipped.
pub fn all_metrics_streams(config: &UnifiedConfig) -> Vec<MetricsStreamConfig> {
    all_metrics_streams_with_diagnostics(config).into_values()
}

pub(crate) fn all_metrics_streams_with_diagnostics(
    config: &UnifiedConfig,
) -> ConfigParseReport<MetricsStreamConfig> {
    let Some(metrics) = config.section("metrics").and_then(|v| v.as_object()) else {
        return ConfigParseReport::default();
    };

    let mut report = ConfigParseReport::default();

    for (key, value) in metrics {
        match metrics_stream_from_entry(key, value) {
            Ok(stream) => report.values.push(stream),
            Err(error) => report.record_error(error),
        }
    }

    report
}

fn metrics_stream_from_entry(
    key: &str,
    value: &serde_json::Value,
) -> Result<MetricsStreamConfig, ConfigFieldError> {
    let ctx = FieldContext::entry("metrics", key);
    let metric_source_id = required_config_key_result::<MetricSourceId>(key, ctx)?;
    let subbox_endpoint =
        required_config_string_result::<WireEndpoint>(value, "subbox_endpoint", ctx)?;
    let archive_id = required_config_string_result::<ArchiveId>(value, "archive_id", ctx)?;
    let repo_id = required_config_string_result::<RepoId>(value, "repo_id", ctx)?;
    let collection_interval_secs = positive_u64_field_or(value, "collection_interval_secs", 1);
    let send_interval_secs = positive_u64_field_or(value, "send_interval_secs", 10);

    Ok(MetricsStreamConfig {
        metric_source_id: metric_source_id.0,
        subbox_endpoint: subbox_endpoint.0,
        archive_id: archive_id.0,
        repo_id: repo_id.0,
        collection_interval_secs,
        send_interval_secs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn unified(raw: serde_json::Value) -> UnifiedConfig {
        UnifiedConfig::new(raw, "etag-1".into())
    }

    #[test]
    fn extracts_metrics_streams_from_unified_config() {
        let unified = unified(json!({
            "metrics": {
                "metrics-42": {
                    "subbox_endpoint": "https://subbox.example.com/wire",
                    "archive_id": "arc_123",
                    "repo_id": "repo_456",
                    "collection_interval_secs": 1,
                    "send_interval_secs": 10
                }
            }
        }));

        let streams = all_metrics_streams(&unified);

        assert_eq!(streams.len(), 1);
        assert_eq!(streams[0].metric_source_id, "metrics-42");
        assert_eq!(
            streams[0].subbox_endpoint,
            "https://subbox.example.com/wire"
        );
        assert_eq!(streams[0].archive_id, "arc_123");
        assert_eq!(streams[0].repo_id, "repo_456");
        assert_eq!(streams[0].collection_interval_secs, 1);
        assert_eq!(streams[0].send_interval_secs, 10);
    }

    #[test]
    fn metrics_streams_defaults_intervals_when_missing() {
        let unified = unified(json!({
            "metrics": {
                "metrics-99": {
                    "subbox_endpoint": "https://subbox.example.com/wire",
                    "archive_id": "arc_1",
                    "repo_id": "repo_1"
                }
            }
        }));

        let streams = all_metrics_streams(&unified);

        assert_eq!(streams.len(), 1);
        assert_eq!(streams[0].collection_interval_secs, 1);
        assert_eq!(streams[0].send_interval_secs, 10);
        assert_eq!(
            streams[0].subbox_endpoint,
            "https://subbox.example.com/wire"
        );
    }

    #[test]
    fn metrics_streams_defaults_zero_intervals() {
        let unified = unified(json!({
            "metrics": {
                "metrics-zero": {
                    "subbox_endpoint": "https://subbox.example.com/wire",
                    "archive_id": "arc_1",
                    "repo_id": "repo_1",
                    "collection_interval_secs": 0,
                    "send_interval_secs": 0
                }
            }
        }));

        let streams = all_metrics_streams(&unified);

        assert_eq!(streams.len(), 1);
        assert_eq!(streams[0].collection_interval_secs, 1);
        assert_eq!(streams[0].send_interval_secs, 10);
    }

    #[test]
    fn metrics_streams_skips_entries_missing_required_fields() {
        let unified = unified(json!({
            "metrics": {
                "valid": {
                    "subbox_endpoint": "https://subbox.example.com/wire",
                    "archive_id": "arc_1",
                    "repo_id": "repo_1"
                },
                "missing-endpoint": {
                    "archive_id": "arc_2",
                    "repo_id": "repo_2"
                },
                "missing-archive": {
                    "subbox_endpoint": "https://subbox.example.com/wire",
                    "repo_id": "repo_3"
                }
            }
        }));

        let report = all_metrics_streams_with_diagnostics(&unified);
        let streams = &report.values;

        assert_eq!(streams.len(), 1);
        assert_eq!(streams[0].metric_source_id, "valid");
        assert!(report.errors.iter().any(|error| {
            matches!(
                error,
                ConfigFieldError::InvalidField {
                    section: "metrics",
                    entry_id: Some(entry_id),
                    field: "subbox_endpoint",
                    expected: "non-empty string",
                    ..
                } if entry_id == "missing-endpoint"
            )
        }));
        assert!(report.errors.iter().any(|error| {
            matches!(
                error,
                ConfigFieldError::InvalidField {
                    section: "metrics",
                    entry_id: Some(entry_id),
                    field: "archive_id",
                    expected: "non-empty string",
                    ..
                } if entry_id == "missing-archive"
            )
        }));
    }

    #[test]
    fn metrics_streams_returns_empty_when_no_metrics_section() {
        let unified = unified(json!({}));

        assert!(all_metrics_streams(&unified).is_empty());
    }
}
