use super::{SharedConfig, UnifiedConfig};
use std::time::Duration;

impl UnifiedConfig {
    pub fn config_poll_secs(&self) -> Option<u64> {
        self.positive_config_secs("poll_secs")
    }

    pub fn stats_interval_secs(&self) -> Option<u64> {
        self.positive_config_secs("stats_interval_secs")
    }

    pub fn send_stats(&self) -> Option<bool> {
        self.section("config")?.get("send_stats")?.as_bool()
    }

    fn positive_config_secs(&self, field: &str) -> Option<u64> {
        self.section("config")?
            .get(field)?
            .as_u64()
            .filter(|&secs| secs > 0)
    }
}

pub async fn effective_poll_interval(shared: &SharedConfig, fallback: Duration) -> Duration {
    shared
        .read()
        .await
        .as_ref()
        .and_then(UnifiedConfig::config_poll_secs)
        .map_or(fallback, Duration::from_secs)
}

pub async fn effective_stats_interval(shared: &SharedConfig, fallback: Duration) -> Duration {
    shared
        .read()
        .await
        .as_ref()
        .and_then(UnifiedConfig::stats_interval_secs)
        .map_or(fallback, Duration::from_secs)
}

pub async fn stats_reporting_enabled(shared: &SharedConfig) -> bool {
    shared
        .read()
        .await
        .as_ref()
        .and_then(UnifiedConfig::send_stats)
        .unwrap_or(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn unified(raw: serde_json::Value) -> UnifiedConfig {
        UnifiedConfig::new(raw, "etag".into())
    }

    #[test]
    fn reads_cadence_from_config_section() {
        let cfg = unified(json!({
            "config": {
                "poll_secs": 45,
                "stats_interval_secs": 30,
                "send_stats": false
            }
        }));

        assert_eq!(cfg.config_poll_secs(), Some(45));
        assert_eq!(cfg.stats_interval_secs(), Some(30));
        assert_eq!(cfg.send_stats(), Some(false));
    }

    #[test]
    fn absent_config_values_are_none() {
        let without_config = unified(json!({}));
        assert_eq!(without_config.config_poll_secs(), None);
        assert_eq!(without_config.stats_interval_secs(), None);
        assert_eq!(without_config.send_stats(), None);

        let empty_config = unified(json!({ "config": {} }));
        assert_eq!(empty_config.config_poll_secs(), None);
        assert_eq!(empty_config.stats_interval_secs(), None);
        assert_eq!(empty_config.send_stats(), None);
    }

    #[test]
    fn zero_or_non_numeric_cadence_is_absent() {
        let zero = unified(json!({
            "config": {
                "poll_secs": 0,
                "stats_interval_secs": 0
            }
        }));
        assert_eq!(zero.config_poll_secs(), None);
        assert_eq!(zero.stats_interval_secs(), None);

        let non_numeric = unified(json!({
            "config": {
                "poll_secs": "60",
                "stats_interval_secs": "30",
                "send_stats": "true"
            }
        }));
        assert_eq!(non_numeric.config_poll_secs(), None);
        assert_eq!(non_numeric.stats_interval_secs(), None);
        assert_eq!(non_numeric.send_stats(), None);
    }

    #[test]
    fn send_stats_reads_boolean_values() {
        assert_eq!(
            unified(json!({ "config": { "send_stats": true } })).send_stats(),
            Some(true)
        );
        assert_eq!(
            unified(json!({ "config": { "send_stats": false } })).send_stats(),
            Some(false)
        );
    }

    #[tokio::test]
    async fn effective_helpers_use_config_values() {
        let shared = super::super::shared_config();
        *shared.write().await = Some(unified(json!({
            "config": {
                "poll_secs": 5,
                "stats_interval_secs": 7,
                "send_stats": false
            }
        })));

        assert_eq!(
            effective_poll_interval(&shared, Duration::from_secs(60)).await,
            Duration::from_secs(5)
        );
        assert_eq!(
            effective_stats_interval(&shared, Duration::from_secs(30)).await,
            Duration::from_secs(7)
        );
        assert!(!stats_reporting_enabled(&shared).await);
    }

    #[tokio::test]
    async fn effective_helpers_fall_back_when_absent() {
        let shared = super::super::shared_config();

        assert_eq!(
            effective_poll_interval(&shared, Duration::from_secs(60)).await,
            Duration::from_secs(60)
        );
        assert_eq!(
            effective_stats_interval(&shared, Duration::from_secs(30)).await,
            Duration::from_secs(30)
        );
        assert!(stats_reporting_enabled(&shared).await);
    }
}
