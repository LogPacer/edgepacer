use serde_json::Value;
use thiserror::Error;
use tracing::warn;

#[derive(Debug, Clone, Copy)]
pub struct FieldContext<'a> {
    pub section: &'static str,
    pub entry_id: Option<&'a str>,
}

impl<'a> FieldContext<'a> {
    pub const fn section(section: &'static str) -> Self {
        Self {
            section,
            entry_id: None,
        }
    }

    pub const fn entry(section: &'static str, entry_id: &'a str) -> Self {
        Self {
            section,
            entry_id: Some(entry_id),
        }
    }
}

pub type ConfigFieldResult<T> = Result<T, ConfigFieldError>;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConfigFieldError {
    #[error(
        "invalid unified config field: section={section}, entry_id={entry_id:?}, field={field}, expected={expected}, actual={actual:?}"
    )]
    InvalidField {
        section: &'static str,
        entry_id: Option<String>,
        field: &'static str,
        expected: &'static str,
        actual: Option<String>,
    },
}

impl ConfigFieldError {
    pub fn invalid_field(
        ctx: FieldContext<'_>,
        field: &'static str,
        expected: &'static str,
    ) -> Self {
        Self::invalid_field_with_actual(ctx, field, expected, None)
    }

    pub fn invalid_field_value(
        ctx: FieldContext<'_>,
        field: &'static str,
        expected: &'static str,
        actual: impl Into<String>,
    ) -> Self {
        Self::invalid_field_with_actual(ctx, field, expected, Some(actual.into()))
    }

    fn invalid_field_with_actual(
        ctx: FieldContext<'_>,
        field: &'static str,
        expected: &'static str,
        actual: Option<String>,
    ) -> Self {
        Self::InvalidField {
            section: ctx.section,
            entry_id: ctx.entry_id.map(str::to_owned),
            field,
            expected,
            actual,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigParseReport<T> {
    pub values: Vec<T>,
    pub errors: Vec<ConfigFieldError>,
}

impl<T> Default for ConfigParseReport<T> {
    fn default() -> Self {
        Self {
            values: Vec::new(),
            errors: Vec::new(),
        }
    }
}

impl<T> ConfigParseReport<T> {
    pub fn into_values(self) -> Vec<T> {
        self.values
    }

    pub fn record_error(&mut self, error: ConfigFieldError) {
        warn_config_field_error(&error);
        self.errors.push(error);
    }
}

macro_rules! config_string_type {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $name(pub String);

        impl From<String> for $name {
            fn from(value: String) -> Self {
                Self(value)
            }
        }

        impl ConfigString for $name {}
    };
}

pub trait ConfigString: From<String> {}

config_string_type!(ArchiveId);
config_string_type!(LogSourceId);
config_string_type!(MetricSourceId);
config_string_type!(RepoId);
config_string_type!(ServiceName);
config_string_type!(TraceProxyId);
config_string_type!(WireEndpoint);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Port(u16);

impl Port {
    pub fn try_from_u64(
        raw: u64,
        field: &'static str,
        ctx: FieldContext<'_>,
    ) -> ConfigFieldResult<Self> {
        match u16::try_from(raw) {
            Ok(port) => Ok(Self(port)),
            Err(_) => Err(ConfigFieldError::invalid_field_value(
                ctx,
                field,
                "u16 port",
                raw.to_string(),
            )),
        }
    }

    pub fn from_u64(raw: u64, field: &'static str, ctx: FieldContext<'_>) -> Option<Self> {
        match Self::try_from_u64(raw, field, ctx) {
            Ok(port) => Some(port),
            Err(error) => {
                warn_config_field_error(&error);
                None
            }
        }
    }

    pub fn get(self) -> u16 {
        self.0
    }
}

pub fn required_string_field(
    value: &Value,
    field: &'static str,
    ctx: FieldContext<'_>,
) -> Option<String> {
    match required_string_field_result(value, field, ctx) {
        Ok(value) => Some(value),
        Err(error) => {
            warn_config_field_error(&error);
            None
        }
    }
}

pub fn required_string_field_result(
    value: &Value,
    field: &'static str,
    ctx: FieldContext<'_>,
) -> ConfigFieldResult<String> {
    let Some(raw) = value.get(field).and_then(Value::as_str) else {
        return Err(ConfigFieldError::invalid_field(
            ctx,
            field,
            "non-empty string",
        ));
    };

    if raw.is_empty() {
        return Err(ConfigFieldError::invalid_field_value(
            ctx,
            field,
            "non-empty string",
            raw,
        ));
    }

    Ok(raw.to_string())
}

pub fn required_config_string<T: ConfigString>(
    value: &Value,
    field: &'static str,
    ctx: FieldContext<'_>,
) -> Option<T> {
    match required_config_string_result(value, field, ctx) {
        Ok(value) => Some(value),
        Err(error) => {
            warn_config_field_error(&error);
            None
        }
    }
}

pub fn required_config_string_result<T: ConfigString>(
    value: &Value,
    field: &'static str,
    ctx: FieldContext<'_>,
) -> ConfigFieldResult<T> {
    required_string_field_result(value, field, ctx).map(T::from)
}

pub fn required_config_key<T: ConfigString>(key: &str, ctx: FieldContext<'_>) -> Option<T> {
    match required_config_key_result(key, ctx) {
        Ok(value) => Some(value),
        Err(error) => {
            warn_config_field_error(&error);
            None
        }
    }
}

pub fn required_config_key_result<T: ConfigString>(
    key: &str,
    ctx: FieldContext<'_>,
) -> ConfigFieldResult<T> {
    required_key_result(key, ctx).map(T::from)
}

pub fn optional_string_field(value: &Value, field: &str) -> Option<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|raw| !raw.is_empty())
        .map(String::from)
}

pub fn bool_field_or(value: &Value, field: &str, fallback: bool) -> bool {
    value
        .get(field)
        .and_then(Value::as_bool)
        .unwrap_or(fallback)
}

pub fn u64_field(value: &Value, field: &str) -> Option<u64> {
    value.get(field).and_then(Value::as_u64)
}

pub fn positive_u64_field_or(value: &Value, field: &str, fallback: u64) -> u64 {
    u64_field(value, field)
        .filter(|&raw| raw > 0)
        .unwrap_or(fallback)
}

pub fn u32_field_or(
    value: &Value,
    field: &'static str,
    fallback: u32,
    ctx: FieldContext<'_>,
) -> u32 {
    let Some(raw) = u64_field(value, field) else {
        return fallback;
    };

    match u32::try_from(raw) {
        Ok(value) => value,
        Err(_) => {
            warn_invalid(ctx, field, "u32");
            fallback
        }
    }
}

pub fn string_array_field(value: &Value, field: &str) -> Vec<String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

pub fn port_list_field(
    value: Option<&Value>,
    field: &'static str,
    ctx: FieldContext<'_>,
) -> Vec<u16> {
    match value {
        Some(Value::String(raw)) => raw
            .split(',')
            .filter_map(|part| {
                let trimmed = part.trim();
                if trimmed.is_empty() {
                    return None;
                }
                match trimmed.parse::<u16>() {
                    Ok(port) => Some(port),
                    Err(_) => {
                        warn_invalid(ctx, field, "comma-separated u16 ports");
                        None
                    }
                }
            })
            .collect(),
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|item| {
                let Some(raw) = item.as_u64() else {
                    warn_invalid(ctx, field, "array of u16 ports");
                    return None;
                };
                Port::from_u64(raw, field, ctx).map(Port::get)
            })
            .collect(),
        Some(_) => {
            warn_invalid(ctx, field, "port string or array");
            Vec::new()
        }
        None => Vec::new(),
    }
}

fn required_key_result(key: &str, ctx: FieldContext<'_>) -> ConfigFieldResult<String> {
    if key.is_empty() {
        Err(ConfigFieldError::invalid_field_value(
            ctx,
            "map_key",
            "non-empty string",
            key,
        ))
    } else {
        Ok(key.to_string())
    }
}

fn warn_invalid(ctx: FieldContext<'_>, field: &'static str, expected: &'static str) {
    warn_config_field_error(&ConfigFieldError::invalid_field(ctx, field, expected));
}

pub fn warn_config_field_error(error: &ConfigFieldError) {
    let ConfigFieldError::InvalidField {
        section,
        entry_id,
        field,
        expected,
        actual,
    } = error;

    warn!(
        section = *section,
        entry_id = ?entry_id.as_deref(),
        field = *field,
        expected = *expected,
        actual = ?actual.as_deref(),
        "invalid unified config field, skipping entry"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn required_string_field_result_reports_missing_field() {
        let error = required_string_field_result(
            &json!({}),
            "subbox_endpoint",
            FieldContext::entry("metrics", "metric-1"),
        )
        .expect_err("missing field");

        assert_eq!(
            error,
            ConfigFieldError::InvalidField {
                section: "metrics",
                entry_id: Some("metric-1".to_string()),
                field: "subbox_endpoint",
                expected: "non-empty string",
                actual: None,
            }
        );
    }

    #[test]
    fn required_config_key_result_reports_empty_key() {
        let error =
            required_config_key_result::<MetricSourceId>("", FieldContext::entry("metrics", ""))
                .expect_err("empty key");

        assert_eq!(
            error,
            ConfigFieldError::InvalidField {
                section: "metrics",
                entry_id: Some(String::new()),
                field: "map_key",
                expected: "non-empty string",
                actual: Some(String::new()),
            }
        );
    }

    #[test]
    fn port_try_from_u64_reports_overflow() {
        let error = Port::try_from_u64(
            u64::from(u16::MAX) + 1,
            "receiver_port",
            FieldContext::section("ebpf"),
        )
        .expect_err("oversized port");

        assert_eq!(
            error,
            ConfigFieldError::InvalidField {
                section: "ebpf",
                entry_id: None,
                field: "receiver_port",
                expected: "u16 port",
                actual: Some("65536".to_string()),
            }
        );
    }
}
