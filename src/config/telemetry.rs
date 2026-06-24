use super::fields::{
    ArchiveId, FieldContext, RepoId, WireEndpoint, optional_string_field, required_config_string,
};
use super::{UnifiedConfig, compute_checksum};

/// Customer identity embedded in self-telemetry log bodies.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TelemetryContext {
    pub tenant_id: String,
    pub tenant_name: String,
    pub customer_archive_id: String,
}

/// Self-telemetry routing + context from unified config `telemetry` section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelemetryConfig {
    pub enabled: bool,
    pub subbox_endpoint: String,
    pub archive_id: String,
    pub repo_id: String,
    pub min_level: String,
    pub context: TelemetryContext,
    /// Checksum of the telemetry section - restart pipeline when this changes.
    pub config_hash: String,
}

/// Extract self-telemetry config when enabled with required routing fields.
pub fn telemetry_config(config: &UnifiedConfig) -> Option<TelemetryConfig> {
    let section = config.section("telemetry")?;
    let ctx = FieldContext::section("telemetry");
    let enabled = section.get("enabled")?.as_bool()?;
    if !enabled {
        return None;
    }

    let subbox_endpoint = required_config_string::<WireEndpoint>(section, "subbox_endpoint", ctx)?;
    let archive_id = required_config_string::<ArchiveId>(section, "archive_id", ctx)?;
    let repo_id = required_config_string::<RepoId>(section, "repo_id", ctx)?;
    let min_level = optional_string_field(section, "min_level").unwrap_or_else(|| "info".into());

    let context_fields = section.get("context").and_then(|value| value.as_object());
    let context = TelemetryContext {
        tenant_id: context_value(context_fields, "tenant_id"),
        tenant_name: context_value(context_fields, "tenant_name"),
        customer_archive_id: context_value(context_fields, "customer_archive_id"),
    };

    let config_hash = compute_checksum(section);

    Some(TelemetryConfig {
        enabled,
        subbox_endpoint: subbox_endpoint.0,
        archive_id: archive_id.0,
        repo_id: repo_id.0,
        min_level,
        context,
        config_hash,
    })
}

fn context_value(
    context_fields: Option<&serde_json::Map<String, serde_json::Value>>,
    key: &str,
) -> String {
    context_fields
        .and_then(|fields| fields.get(key))
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn unified(raw: serde_json::Value) -> UnifiedConfig {
        UnifiedConfig::new(raw, "etag".into())
    }

    #[test]
    fn extracts_telemetry_config_when_enabled() {
        let unified = unified(json!({
            "telemetry": {
                "enabled": true,
                "subbox_endpoint": "https://staff-relay.example/wire",
                "archive_id": "staff-arc",
                "repo_id": "edgepacer-ops",
                "min_level": "warn",
                "context": {
                    "tenant_id": "t-1",
                    "tenant_name": "Acme",
                    "customer_archive_id": "cust-arc"
                }
            }
        }));

        let tele = telemetry_config(&unified).expect("telemetry config");
        assert!(tele.enabled);
        assert_eq!(tele.subbox_endpoint, "https://staff-relay.example/wire");
        assert_eq!(tele.min_level, "warn");
        assert_eq!(tele.context.tenant_id, "t-1");
        assert!(!tele.config_hash.is_empty());
    }

    #[test]
    fn telemetry_config_none_without_subbox_endpoint() {
        let unified = unified(json!({
            "telemetry": {
                "enabled": true,
                "archive_id": "staff-arc",
                "repo_id": "edgepacer-ops"
            }
        }));

        assert!(telemetry_config(&unified).is_none());
    }

    #[test]
    fn telemetry_config_none_when_disabled() {
        let unified = unified(json!({ "telemetry": { "enabled": false } }));

        assert!(telemetry_config(&unified).is_none());
    }
}
