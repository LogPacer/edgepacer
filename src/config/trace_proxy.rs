use std::collections::BTreeSet;
use std::net::SocketAddr;

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::UnifiedConfig;
use super::fields::{
    ArchiveId, ConfigFieldError, ConfigParseReport, FieldContext, RepoId, TraceProxyId,
    WireEndpoint, required_config_key_result, required_config_string_result,
    required_string_field_result,
};

/// A trace proxy extracted from unified config - enough to drive proxy lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceProxyStreamConfig {
    /// Unique identifier from Rails for this proxy instance.
    pub log_source_id: String,
    pub listen_address: SocketAddr,
    /// Optional OTLP/gRPC listener (`:4317`). Absent in config leaves gRPC off.
    pub grpc_listen_address: Option<SocketAddr>,
    pub subbox_endpoint: String,
    pub archive_id: String,
    pub repo_id: String,
    pub require_service_name: bool,
    pub allowed_service_names: BTreeSet<String>,
    /// SHA256 hash of the config fields that trigger proxy restart when changed.
    /// Includes listener, destination, and trace acceptance policy.
    pub config_hash: String,
}

impl TraceProxyStreamConfig {
    /// Compute hash of fields that matter for proxy restart.
    pub fn compute_hash(
        listen_address: &str,
        grpc_listen_address: Option<&str>,
        subbox_endpoint: &str,
        archive_id: &str,
        repo_id: &str,
        require_service_name: bool,
        allowed_service_names: &BTreeSet<String>,
    ) -> String {
        let mut input = String::new();
        append_hash_field(&mut input, listen_address);
        // Empty stands for "no gRPC listener" — distinct from any real address,
        // so adding, removing, or changing the gRPC port restarts the proxy.
        append_hash_field(&mut input, grpc_listen_address.unwrap_or(""));
        append_hash_field(&mut input, subbox_endpoint);
        append_hash_field(&mut input, archive_id);
        append_hash_field(&mut input, repo_id);
        append_hash_field(
            &mut input,
            if require_service_name {
                "true"
            } else {
                "false"
            },
        );
        append_hash_field(&mut input, &allowed_service_names.len().to_string());
        for service_name in allowed_service_names {
            append_hash_field(&mut input, service_name);
        }

        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        hex::encode(hasher.finalize())
    }
}

fn append_hash_field(input: &mut String, value: &str) {
    input.push_str(&value.len().to_string());
    input.push(':');
    input.push_str(value);
    input.push(';');
}

/// Extract all trace proxies from unified config.
///
/// Each proxy is keyed by `log_source_id` from Rails.
pub fn all_trace_proxies(config: &UnifiedConfig) -> Vec<TraceProxyStreamConfig> {
    all_trace_proxies_with_diagnostics(config).into_values()
}

pub(crate) fn all_trace_proxies_with_diagnostics(
    config: &UnifiedConfig,
) -> ConfigParseReport<TraceProxyStreamConfig> {
    let Some(proxies) = config.section("traces").and_then(|value| value.as_object()) else {
        return ConfigParseReport::default();
    };

    let mut report = ConfigParseReport::default();

    for (log_source_id, proxy) in proxies {
        match trace_proxy_from_entry(log_source_id, proxy) {
            Ok(proxy) => report.values.push(proxy),
            Err(error) => report.record_error(error),
        }
    }

    report
}

fn trace_proxy_from_entry(
    log_source_id: &str,
    proxy: &serde_json::Value,
) -> Result<TraceProxyStreamConfig, ConfigFieldError> {
    let ctx = FieldContext::entry("traces", log_source_id);
    let trace_proxy_id = required_config_key_result::<TraceProxyId>(log_source_id, ctx)?;
    let listen_address = required_string_field_result(proxy, "listen_address", ctx)?;
    let parsed_listen_address = parse_listen_address(&listen_address, ctx)?;
    let grpc_listen_address = optional_listen_address_field(proxy, "grpc_listen_address", ctx)?;
    let subbox_endpoint =
        required_config_string_result::<WireEndpoint>(proxy, "subbox_endpoint", ctx)?;
    let archive_id = required_config_string_result::<ArchiveId>(proxy, "archive_id", ctx)?;
    let repo_id = required_config_string_result::<RepoId>(proxy, "repo_id", ctx)?;
    let allowed_service_names = allowed_service_names_field(proxy, ctx)?;
    let require_service_name = optional_bool_field(proxy, "require_service_name", false, ctx)?
        || !allowed_service_names.is_empty();

    let config_hash = TraceProxyStreamConfig::compute_hash(
        &listen_address,
        grpc_listen_address.map(|addr| addr.to_string()).as_deref(),
        subbox_endpoint.0.as_str(),
        archive_id.0.as_str(),
        repo_id.0.as_str(),
        require_service_name,
        &allowed_service_names,
    );

    Ok(TraceProxyStreamConfig {
        log_source_id: trace_proxy_id.0,
        listen_address: parsed_listen_address,
        grpc_listen_address,
        subbox_endpoint: subbox_endpoint.0,
        archive_id: archive_id.0,
        repo_id: repo_id.0,
        require_service_name,
        allowed_service_names,
        config_hash,
    })
}

fn parse_listen_address(raw: &str, ctx: FieldContext<'_>) -> Result<SocketAddr, ConfigFieldError> {
    match raw.parse() {
        Ok(address) => Ok(address),
        Err(_) => Err(ConfigFieldError::invalid_field_value(
            ctx,
            "listen_address",
            "socket address",
            raw,
        )),
    }
}

/// Parse an optional socket-address field. Absent leaves the listener off; a
/// present-but-unparseable value is an error so a typo'd gRPC port is rejected
/// rather than silently dropping the listener.
fn optional_listen_address_field(
    proxy: &Value,
    field: &'static str,
    ctx: FieldContext<'_>,
) -> Result<Option<SocketAddr>, ConfigFieldError> {
    let Some(raw) = proxy.get(field) else {
        return Ok(None);
    };

    let Some(raw) = raw.as_str() else {
        return Err(ConfigFieldError::invalid_field(ctx, field, "socket address"));
    };

    match raw.parse() {
        Ok(address) => Ok(Some(address)),
        Err(_) => Err(ConfigFieldError::invalid_field_value(
            ctx,
            field,
            "socket address",
            raw,
        )),
    }
}

fn allowed_service_names_field(
    proxy: &Value,
    ctx: FieldContext<'_>,
) -> Result<BTreeSet<String>, ConfigFieldError> {
    let Some(raw_names) = proxy.get("allowed_service_names") else {
        return Ok(BTreeSet::new());
    };

    let Some(names) = raw_names.as_array() else {
        return Err(ConfigFieldError::invalid_field(
            ctx,
            "allowed_service_names",
            "array of non-empty strings",
        ));
    };

    let mut allowed = BTreeSet::new();
    for name in names {
        let Some(name) = name.as_str().filter(|raw| !raw.is_empty()) else {
            return Err(ConfigFieldError::invalid_field(
                ctx,
                "allowed_service_names",
                "array of non-empty strings",
            ));
        };
        allowed.insert(name.to_string());
    }

    Ok(allowed)
}

fn optional_bool_field(
    value: &Value,
    field: &'static str,
    fallback: bool,
    ctx: FieldContext<'_>,
) -> Result<bool, ConfigFieldError> {
    match value.get(field) {
        None => Ok(fallback),
        Some(Value::Bool(raw)) => Ok(*raw),
        Some(_) => Err(ConfigFieldError::invalid_field(ctx, field, "boolean")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn unified(raw: serde_json::Value) -> UnifiedConfig {
        UnifiedConfig::new(raw, "etag-1".into())
    }

    #[test]
    fn extracts_trace_proxy_configs_from_unified_config() {
        let unified = unified(json!({
            "traces": {
                "traces-proxy-agent-123": {
                    "listen_address": "127.0.0.1:4318",
                    "subbox_endpoint": "https://subbox.example",
                    "archive_id": "arc_123",
                    "repo_id": "repo_456",
                    "allowed_service_names": ["checkout", "billing"]
                }
            }
        }));

        let proxies = all_trace_proxies(&unified);

        assert_eq!(proxies.len(), 1);
        assert_eq!(proxies[0].log_source_id, "traces-proxy-agent-123");
        assert_eq!(
            proxies[0].listen_address,
            "127.0.0.1:4318".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(proxies[0].subbox_endpoint, "https://subbox.example");
        assert_eq!(proxies[0].archive_id, "arc_123");
        assert_eq!(proxies[0].repo_id, "repo_456");
        assert!(proxies[0].require_service_name);
        assert_eq!(
            proxies[0].allowed_service_names,
            BTreeSet::from(["billing".to_string(), "checkout".to_string()])
        );
    }

    #[test]
    fn skips_invalid_trace_proxy_entries() {
        let unified = unified(json!({
            "traces": {
                "valid-proxy": {
                        "listen_address": "127.0.0.1:4318",
                        "subbox_endpoint": "https://subbox.example",
                        "archive_id": "arc_valid",
                        "repo_id": "repo_valid"
                    },
                "missing-repo": {
                        "listen_address": "127.0.0.1:4319",
                        "subbox_endpoint": "https://subbox.example",
                        "archive_id": "arc_missing_repo"
                    },
                "bad-address": {
                        "listen_address": "not-an-address",
                        "subbox_endpoint": "https://subbox.example",
                        "archive_id": "arc_bad",
                        "repo_id": "repo_bad"
                    },
                "bad-allowed-service-name": {
                        "listen_address": "127.0.0.1:4320",
                        "subbox_endpoint": "https://subbox.example",
                        "archive_id": "arc_bad_allowed",
                        "repo_id": "repo_bad_allowed",
                        "allowed_service_names": ["checkout", ""]
                    },
                "bad-require-service-name": {
                        "listen_address": "127.0.0.1:4321",
                        "subbox_endpoint": "https://subbox.example",
                        "archive_id": "arc_bad_require",
                        "repo_id": "repo_bad_require",
                        "require_service_name": "true"
                    }
            }
        }));

        let report = all_trace_proxies_with_diagnostics(&unified);
        let proxies = &report.values;

        assert_eq!(proxies.len(), 1);
        assert_eq!(proxies[0].log_source_id, "valid-proxy");
        assert!(report.errors.iter().any(|error| {
            matches!(
                error,
                ConfigFieldError::InvalidField {
                    section: "traces",
                    entry_id: Some(entry_id),
                    field: "repo_id",
                    expected: "non-empty string",
                    ..
                } if entry_id == "missing-repo"
            )
        }));
        assert!(report.errors.iter().any(|error| {
            matches!(
                error,
                ConfigFieldError::InvalidField {
                    section: "traces",
                    entry_id: Some(entry_id),
                    field: "listen_address",
                    expected: "socket address",
                    actual: Some(actual),
                    ..
                } if entry_id == "bad-address" && actual == "not-an-address"
            )
        }));
        assert!(report.errors.iter().any(|error| {
            matches!(
                error,
                ConfigFieldError::InvalidField {
                    section: "traces",
                    entry_id: Some(entry_id),
                    field: "allowed_service_names",
                    expected: "array of non-empty strings",
                    ..
                } if entry_id == "bad-allowed-service-name"
            )
        }));
        assert!(report.errors.iter().any(|error| {
            matches!(
                error,
                ConfigFieldError::InvalidField {
                    section: "traces",
                    entry_id: Some(entry_id),
                    field: "require_service_name",
                    expected: "boolean",
                    ..
                } if entry_id == "bad-require-service-name"
            )
        }));
    }

    #[test]
    fn trace_proxy_config_hash_changes_when_restart_fields_change() {
        let base = TraceProxyStreamConfig::compute_hash(
            "127.0.0.1:4318",
            None,
            "https://subbox.example",
            "arc_123",
            "repo_456",
            false,
            &BTreeSet::new(),
        );
        let changed_address = TraceProxyStreamConfig::compute_hash(
            "127.0.0.1:4319",
            None,
            "https://subbox.example",
            "arc_123",
            "repo_456",
            false,
            &BTreeSet::new(),
        );
        let changed_endpoint = TraceProxyStreamConfig::compute_hash(
            "127.0.0.1:4318",
            None,
            "https://subbox-alt.example",
            "arc_123",
            "repo_456",
            false,
            &BTreeSet::new(),
        );
        let changed_archive = TraceProxyStreamConfig::compute_hash(
            "127.0.0.1:4318",
            None,
            "https://subbox.example",
            "arc_999",
            "repo_456",
            false,
            &BTreeSet::new(),
        );
        let changed_repo = TraceProxyStreamConfig::compute_hash(
            "127.0.0.1:4318",
            None,
            "https://subbox.example",
            "arc_123",
            "repo_999",
            false,
            &BTreeSet::new(),
        );
        let changed_policy = TraceProxyStreamConfig::compute_hash(
            "127.0.0.1:4318",
            None,
            "https://subbox.example",
            "arc_123",
            "repo_456",
            true,
            &BTreeSet::from(["checkout".to_string()]),
        );
        let added_grpc = TraceProxyStreamConfig::compute_hash(
            "127.0.0.1:4318",
            Some("127.0.0.1:4317"),
            "https://subbox.example",
            "arc_123",
            "repo_456",
            false,
            &BTreeSet::new(),
        );

        assert_ne!(base, changed_address);
        assert_ne!(base, changed_endpoint);
        assert_ne!(base, changed_archive);
        assert_ne!(base, changed_repo);
        assert_ne!(base, changed_policy);
        assert_ne!(base, added_grpc);

        let comma_literal = TraceProxyStreamConfig::compute_hash(
            "127.0.0.1:4318",
            None,
            "https://subbox.example",
            "arc_123",
            "repo_456",
            true,
            &BTreeSet::from(["a,b".to_string()]),
        );
        let split_names = TraceProxyStreamConfig::compute_hash(
            "127.0.0.1:4318",
            None,
            "https://subbox.example",
            "arc_123",
            "repo_456",
            true,
            &BTreeSet::from(["a".to_string(), "b".to_string()]),
        );
        assert_ne!(comma_literal, split_names);
    }

    #[test]
    fn extracts_grpc_listen_address_when_present() {
        let unified = unified(json!({
            "traces": {
                "traces-proxy-agent-123": {
                    "listen_address": "127.0.0.1:4318",
                    "grpc_listen_address": "127.0.0.1:4317",
                    "subbox_endpoint": "https://subbox.example",
                    "archive_id": "arc_123",
                    "repo_id": "repo_456"
                }
            }
        }));

        let proxies = all_trace_proxies(&unified);

        assert_eq!(proxies.len(), 1);
        assert_eq!(
            proxies[0].grpc_listen_address,
            Some("127.0.0.1:4317".parse::<SocketAddr>().unwrap())
        );
    }

    #[test]
    fn grpc_listen_address_defaults_to_none() {
        let unified = unified(json!({
            "traces": {
                "traces-proxy-agent-123": {
                    "listen_address": "127.0.0.1:4318",
                    "subbox_endpoint": "https://subbox.example",
                    "archive_id": "arc_123",
                    "repo_id": "repo_456"
                }
            }
        }));

        let proxies = all_trace_proxies(&unified);

        assert_eq!(proxies.len(), 1);
        assert_eq!(proxies[0].grpc_listen_address, None);
    }

    #[test]
    fn skips_proxy_with_invalid_grpc_listen_address() {
        let unified = unified(json!({
            "traces": {
                "bad-grpc-address": {
                    "listen_address": "127.0.0.1:4318",
                    "grpc_listen_address": "not-an-address",
                    "subbox_endpoint": "https://subbox.example",
                    "archive_id": "arc_bad_grpc",
                    "repo_id": "repo_bad_grpc"
                }
            }
        }));

        let report = all_trace_proxies_with_diagnostics(&unified);

        assert!(report.values.is_empty());
        assert!(report.errors.iter().any(|error| {
            matches!(
                error,
                ConfigFieldError::InvalidField {
                    section: "traces",
                    entry_id: Some(entry_id),
                    field: "grpc_listen_address",
                    expected: "socket address",
                    actual: Some(actual),
                    ..
                } if entry_id == "bad-grpc-address" && actual == "not-an-address"
            )
        }));
    }
}
