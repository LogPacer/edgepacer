use super::UnifiedConfig;
use super::fields::u64_field;

impl UnifiedConfig {
    /// Per-buffer redb page-cache cap (MiB) from the optional `buffer` section,
    /// e.g. `{"buffer": {"cache_mb": 4}}`. `None` means "not configured" - the
    /// agent then falls back to the `EDGEPACER_BUFFER_CACHE_MB` env var / default.
    /// Hot-reloadable: changing it restarts pipelines so buffers reopen with the
    /// new cap (redb fixes the cache size at open time).
    pub fn buffer_cache_mb(&self) -> Option<u64> {
        u64_field(self.section("buffer")?, "cache_mb")
    }

    /// Per-batch ship byte cap (MiB) from the `buffer` section, e.g.
    /// `{"buffer": {"ship_batch_max_mb": 4}}`. Bounds the encoded payload so it
    /// stays under the receiver's request-size limit. `None` falls back to the
    /// `EDGEPACER_SHIP_BATCH_MAX_MB` env var / default. Hot-reloadable.
    pub fn ship_batch_max_mb(&self) -> Option<u64> {
        u64_field(self.section("buffer")?, "ship_batch_max_mb")
    }
}

/// Buffer/delivery tuning resolved from dynamic config, each knob falling back
/// to its env var then a compile-time default. Carried by the orchestrator and
/// applied when reopening pipelines; a change triggers a pipeline restart so
/// the new values take effect (redb fixes its cache at open time).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufferTuning {
    /// redb page-cache cap per buffer, in bytes.
    pub cache_size_bytes: usize,
    /// Maximum raw bytes shipped per batch.
    pub ship_batch_max_bytes: usize,
}

impl BufferTuning {
    /// Resolve from the optional active config. Precedence per knob:
    /// config override > env var > compile-time default.
    pub fn resolve(unified: Option<&UnifiedConfig>) -> Self {
        Self {
            cache_size_bytes: crate::buffer::cache_bytes_for(
                unified.and_then(UnifiedConfig::buffer_cache_mb),
            ),
            ship_batch_max_bytes: crate::pipeline::ship_batch_max_bytes_for(
                unified.and_then(UnifiedConfig::ship_batch_max_mb),
            ),
        }
    }
}

impl Default for BufferTuning {
    fn default() -> Self {
        Self::resolve(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn unified(raw: serde_json::Value) -> UnifiedConfig {
        UnifiedConfig::new(raw, "etag".into())
    }

    #[test]
    fn buffer_cache_mb_reads_buffer_section() {
        let unified = unified(json!({ "buffer": { "cache_mb": 4 } }));

        assert_eq!(unified.buffer_cache_mb(), Some(4));
    }

    #[test]
    fn buffer_tuning_resolves_config_overrides() {
        let unified = unified(json!({ "buffer": { "cache_mb": 2, "ship_batch_max_mb": 3 } }));

        let tuning = BufferTuning::resolve(Some(&unified));

        assert_eq!(tuning.cache_size_bytes, 2 * 1024 * 1024);
        assert_eq!(tuning.ship_batch_max_bytes, 3 * 1024 * 1024);
        assert_eq!(unified.ship_batch_max_mb(), Some(3));
    }

    #[test]
    fn buffer_cache_mb_absent_is_none() {
        let config = unified(json!({}));
        assert_eq!(config.buffer_cache_mb(), None);

        let bad = unified(json!({ "buffer": { "cache_mb": "lots" } }));
        assert_eq!(bad.buffer_cache_mb(), None);
    }
}
