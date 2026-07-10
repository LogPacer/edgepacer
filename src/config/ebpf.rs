use super::fields::{
    ArchiveId, FieldContext, LogSourceId, Port, RepoId, ServiceName, WireEndpoint, port_list_field,
    required_config_key, required_config_string, required_string_field, string_array_field,
};
use super::{UnifiedConfig, compute_checksum};

/// A single eBPF capture target from the unified config `ebpf.targets` map.
///
/// Mirrors Rails' `EbpfTarget`. `open_ports` arrives
/// as a comma-separated string (e.g. `"8080,8443"`) and is parsed to a port list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfTargetConfig {
    pub log_source_id: String,
    pub service_name: String,
    pub systemd_unit: Option<String>,
    pub open_ports: Vec<u16>,
    pub archive_id: String,
    pub repo_id: String,
    pub protocols: Vec<String>,
    pub subbox_endpoint: String,
}

/// The `ebpf` section of unified config (Rails `EbpfDirective`).
///
/// Ships off by default and double-gated server-side (a present-but-disabled
/// section has `enabled: false`, empty targets, `receiver_port: 4318`).
/// `network_flows` is an independent sub-toggle from per-target instrumentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfSectionConfig {
    pub enabled: bool,
    pub receiver_port: u16,
    pub network_flows_enabled: bool,
    pub network_cidrs: Vec<String>,
    pub targets: Vec<EbpfTargetConfig>,
    /// SHA256 over the whole `ebpf` subtree - drives reconcile/restart.
    pub config_hash: String,
}

/// Default OTLP/HTTP receiver port the server always sends for eBPF.
const EBPF_DEFAULT_RECEIVER_PORT: u16 = 4318;

/// Extract the `ebpf` section from unified config. Returns `None` when absent
/// (older servers / local mode); a present-but-disabled section returns
/// `Some` with `enabled: false` so reconcile can tear down running programs.
pub fn ebpf_section(config: &UnifiedConfig) -> Option<EbpfSectionConfig> {
    let section = config.section("ebpf")?;
    let ctx = FieldContext::section("ebpf");

    let enabled = section
        .get("enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let receiver_port = section
        .get("receiver_port")
        .and_then(|v| v.as_u64())
        .and_then(|p| Port::from_u64(p, "receiver_port", ctx).map(Port::get))
        .unwrap_or(EBPF_DEFAULT_RECEIVER_PORT);

    let network_flows = section.get("network_flows");
    let network_flows_enabled = network_flows
        .and_then(|n| n.get("enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let network_cidrs = network_flows
        .map(|network_flows| string_array_field(network_flows, "cidrs"))
        .unwrap_or_default();

    Some(EbpfSectionConfig {
        enabled,
        receiver_port,
        network_flows_enabled,
        network_cidrs,
        targets: parse_ebpf_targets(section.get("targets")),
        config_hash: compute_checksum(section),
    })
}

/// Parse the `ebpf.targets` object (keyed by `log_source_id`) into a list.
/// A target with no `service_name` is skipped - it cannot be routed.
fn parse_ebpf_targets(targets: Option<&serde_json::Value>) -> Vec<EbpfTargetConfig> {
    let Some(map) = targets.and_then(|v| v.as_object()) else {
        return Vec::new();
    };

    map.iter()
        .filter_map(|(log_source_key, target)| {
            let ctx = FieldContext::entry("ebpf.targets", log_source_key);
            let log_source_id = required_config_key::<LogSourceId>(log_source_key, ctx)?;
            let service_name = required_config_string::<ServiceName>(target, "service_name", ctx)?;
            let archive_id = required_config_string::<ArchiveId>(target, "archive_id", ctx)?;
            let repo_id = required_config_string::<RepoId>(target, "repo_id", ctx)?;
            let subbox_endpoint =
                required_config_string::<WireEndpoint>(target, "subbox_endpoint", ctx)?;
            let systemd_unit = match target.get("systemd_unit") {
                Some(_) => Some(required_string_field(target, "systemd_unit", ctx)?),
                None => None,
            };

            Some(EbpfTargetConfig {
                log_source_id: log_source_id.0,
                service_name: service_name.0,
                systemd_unit,
                open_ports: parse_port_list(target.get("open_ports"), ctx),
                archive_id: archive_id.0,
                repo_id: repo_id.0,
                protocols: string_array_field(target, "protocols"),
                subbox_endpoint: subbox_endpoint.0,
            })
        })
        .collect()
}

/// Parse `open_ports`, which Rails sends as `"8080,8443"` (also tolerate a JSON array).
fn parse_port_list(value: Option<&serde_json::Value>, ctx: FieldContext<'_>) -> Vec<u16> {
    port_list_field(value, "open_ports", ctx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn unified(raw: serde_json::Value) -> UnifiedConfig {
        UnifiedConfig::new(raw, "etag".to_string())
    }

    #[test]
    fn absent_section_returns_none() {
        let cfg = unified(json!({}));
        assert!(ebpf_section(&cfg).is_none());
    }

    #[test]
    fn disabled_default_section_parses() {
        let cfg = unified(json!({
            "ebpf": {
                "enabled": false,
                "receiver_port": 4318,
                "network_flows": { "enabled": false, "cidrs": [] },
                "targets": {}
            }
        }));
        let section = ebpf_section(&cfg).expect("section present");
        assert!(!section.enabled);
        assert_eq!(section.receiver_port, 4318);
        assert!(!section.network_flows_enabled);
        assert!(section.targets.is_empty());
    }

    #[test]
    fn enabled_section_with_targets_and_flows() {
        let cfg = unified(json!({
            "ebpf": {
                "enabled": true,
                "receiver_port": 4318,
                "network_flows": { "enabled": true, "cidrs": ["10.0.0.0/8", "192.168.0.0/16"] },
                "targets": {
                    "loggable_42": {
                        "service_name": "api-gateway",
                        "open_ports": "8080,8443",
                        "archive_id": "arc_1",
                        "repo_id": "repo_1",
                        "protocols": ["http", "grpc"],
                        "subbox_endpoint": "https://subbox.example/wire"
                    }
                }
            }
        }));
        let section = ebpf_section(&cfg).expect("section present");
        assert!(section.enabled);
        assert!(section.network_flows_enabled);
        assert_eq!(section.network_cidrs, vec!["10.0.0.0/8", "192.168.0.0/16"]);
        assert_eq!(section.targets.len(), 1);
        let target = &section.targets[0];
        assert_eq!(target.log_source_id, "loggable_42");
        assert_eq!(target.service_name, "api-gateway");
        assert_eq!(target.open_ports, vec![8080, 8443]);
        assert_eq!(target.protocols, vec!["http", "grpc"]);
        assert_eq!(target.subbox_endpoint, "https://subbox.example/wire");
    }

    #[test]
    fn config_hash_changes_when_section_changes() {
        let disabled = ebpf_section(&unified(json!({ "ebpf": { "enabled": false } })))
            .unwrap()
            .config_hash;
        let enabled = ebpf_section(&unified(json!({ "ebpf": { "enabled": true } })))
            .unwrap()
            .config_hash;
        assert_ne!(disabled, enabled);
    }

    #[test]
    fn target_without_service_name_is_skipped() {
        let cfg = unified(json!({
            "ebpf": { "enabled": true, "targets": { "x": { "archive_id": "a" } } }
        }));
        assert!(ebpf_section(&cfg).unwrap().targets.is_empty());
    }

    #[test]
    fn invalid_ports_are_rejected_without_truncation() {
        let cfg = unified(json!({
            "ebpf": {
                "enabled": true,
                "receiver_port": 70000,
                "targets": {
                    "loggable_42": {
                        "service_name": "api-gateway",
                        "open_ports": [8080, 70000],
                        "archive_id": "arc_1",
                        "repo_id": "repo_1",
                        "protocols": ["http"],
                        "subbox_endpoint": "https://subbox.example/wire"
                    }
                }
            }
        }));

        let section = ebpf_section(&cfg).expect("section present");

        assert_eq!(section.receiver_port, EBPF_DEFAULT_RECEIVER_PORT);
        assert_eq!(section.targets[0].open_ports, vec![8080]);
    }

    #[test]
    fn target_without_required_routing_fields_is_skipped() {
        let cfg = unified(json!({
            "ebpf": {
                "enabled": true,
                "targets": {
                    "missing-routing": {
                        "service_name": "api-gateway",
                        "open_ports": "8080"
                    }
                }
            }
        }));

        assert!(ebpf_section(&cfg).unwrap().targets.is_empty());
    }

    #[test]
    fn target_preserves_optional_exact_systemd_unit_identity() {
        let cfg = unified(json!({
            "ebpf": {
                "enabled": true,
                "targets": {
                    "loggable_42": {
                        "service_name": "nginx",
                        "systemd_unit": "nginx.service",
                        "open_ports": "80,443",
                        "archive_id": "arc_1",
                        "repo_id": "repo_1",
                        "protocols": ["http"],
                        "subbox_endpoint": "https://subbox.example/wire"
                    }
                }
            }
        }));

        let target = &ebpf_section(&cfg).unwrap().targets[0];
        assert_eq!(target.systemd_unit.as_deref(), Some("nginx.service"));
    }

    #[test]
    fn malformed_present_systemd_unit_cannot_downgrade_to_container_identity() {
        let cfg = unified(json!({
            "ebpf": {
                "enabled": true,
                "targets": {
                    "loggable_42": {
                        "service_name": "nginx",
                        "systemd_unit": false,
                        "open_ports": "80",
                        "archive_id": "arc_1",
                        "repo_id": "repo_1",
                        "protocols": ["http"],
                        "subbox_endpoint": "https://subbox.example/wire"
                    }
                }
            }
        }));

        assert!(ebpf_section(&cfg).unwrap().targets.is_empty());
    }
}
