use std::collections::HashSet;

use sha2::{Digest, Sha256};

use super::fields::{
    ArchiveId, FieldContext, LogSourceId, RepoId, WireEndpoint, bool_field_or,
    optional_string_field, required_config_key, required_config_string, required_string_field,
    u32_field_or,
};
use super::services::{CheckpointAdoption, all_service_descriptions, resolve_service_descriptions};
use super::{StreamAccessMethod, StreamingSourceConfig, UnifiedConfig};
use crate::discovery::cache::{
    AccessMethod, CollectMatch, MatchStatus, MatchVia, ResolvedAccess, infer_loggable_type,
};

/// A log stream extracted from unified config - enough to drive a delivery pipeline.
#[derive(Debug, Clone)]
pub struct LogStreamConfig {
    /// Unique identifier from Rails (the source identity key).
    pub log_source_id: String,
    pub path: String,
    pub endpoint: String,
    pub archive_id: String,
    pub repo_id: String,
    /// Stamp the agent's `resource_identifier` into shipped metadata. Default
    /// false; logpacer opts a source in via `stamp_resource_identifier` in the collect map.
    pub stamp_resource_identifier: bool,
    /// File-backed source encoding/framing. Plain application files are raw;
    /// container runtime files need their wrapper stripped before shipping.
    pub source_format: FileSourceFormat,
    /// Optional multiline-aggregation configuration. When present, the
    /// pipeline runs raw tailed lines through an EntryAssembler that
    /// stitches continuations into single events.
    pub multiline: Option<MultilineConfig>,
    /// SHA256 hash of the config fields that trigger pipeline restart when changed.
    /// Includes: path, endpoint, archive_id, repo_id, multiline, source format,
    /// and stamp_resource_identifier.
    pub config_hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileSourceFormat {
    Plain,
    DockerJson,
    KubernetesCri,
}

impl FileSourceFormat {
    pub fn hash_part(self) -> &'static str {
        match self {
            FileSourceFormat::Plain => "file",
            FileSourceFormat::DockerJson => "docker-json",
            FileSourceFormat::KubernetesCri => "k8s-cri",
        }
    }
}

/// Per-source multiline aggregation settings, mirroring Go's
/// `config.MultilineConfig`. `start_pattern` matches the first line of an
/// event; non-matching lines are continuations. `max_lines` caps the
/// buffer; `timeout_secs` is the idle-flush interval (Vector-style -
/// resets on every line).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultilineConfig {
    pub start_pattern: String,
    pub max_lines: u32,
    pub timeout_secs: u32,
}

/// A collect directive from unified config `collect` map (Rails collection intent).
#[derive(Debug, Clone)]
pub struct CollectStreamConfig {
    pub log_source_id: String,
    pub locator: String,
    pub matching_strategy: String,
    pub container_identifier: String,
    pub subbox_endpoint: String,
    pub archive_id: String,
    pub repo_id: String,
    /// Stamp the agent's `resource_identifier` into shipped metadata. Default
    /// false; logpacer opts a source in via `stamp_resource_identifier` in the collect map.
    pub stamp_resource_identifier: bool,
    pub multiline: Option<MultilineConfig>,
    pub config_hash: String,
}

/// Resolved file + streaming sources after discovery cache lookup, plus a
/// per-directive diagnostic the caller uses for transition-only logging.
#[derive(Debug, Clone, Default)]
pub struct ResolvedCollectStreams {
    pub file_streams: Vec<LogStreamConfig>,
    pub streaming_sources: Vec<StreamingSourceConfig>,
    pub diagnostics: Vec<CollectDiagnostic>,
    /// Legacy→synthesized state-dir adoption candidates from this pass, one per
    /// selector-synthesized source (see [`CheckpointAdoption`]).
    pub checkpoint_adoptions: Vec<CheckpointAdoption>,
}

/// How one collect directive resolved this pass. Carries the coarse status so
/// the orchestrator logs only on transitions (a fresh miss, a recovery) rather
/// than warning every reconcile, plus a compact human detail — never raw argv
/// or full evidence dumps.
#[derive(Debug, Clone)]
pub struct CollectDiagnostic {
    pub log_source_id: String,
    pub status: MatchStatus,
    pub detail: String,
}

impl LogStreamConfig {
    /// Compute hash of fields that matter for pipeline restart.
    /// If any of these change, the pipeline must be torn down and recreated.
    pub fn compute_hash(
        path: &str,
        endpoint: &str,
        archive_id: &str,
        repo_id: &str,
        multiline: Option<&MultilineConfig>,
        source_format: FileSourceFormat,
        stamp_resource_identifier: bool,
    ) -> String {
        let multiline_part = multiline_hash_part(multiline);
        let stamp_part = if stamp_resource_identifier {
            "stamp"
        } else {
            "nostamp"
        };
        let input = format!(
            "{path}|{endpoint}|{archive_id}|{repo_id}|{multiline_part}|{}|{stamp_part}",
            source_format.hash_part()
        );
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        hex::encode(hasher.finalize())
    }
}

impl CollectStreamConfig {
    pub fn compute_hash(
        locator: &str,
        matching_strategy: &str,
        subbox_endpoint: &str,
        archive_id: &str,
        repo_id: &str,
        multiline: Option<&MultilineConfig>,
        stamp_resource_identifier: bool,
    ) -> String {
        let multiline_part = multiline_hash_part(multiline);
        let stamp_part = if stamp_resource_identifier {
            "stamp"
        } else {
            "nostamp"
        };
        let input = format!(
            "{locator}|{matching_strategy}|{subbox_endpoint}|{archive_id}|{repo_id}|{multiline_part}|{stamp_part}"
        );
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        hex::encode(hasher.finalize())
    }

    pub fn ship_endpoint(&self) -> &str {
        &self.subbox_endpoint
    }
}

/// Parse unified config `collect` map entries.
pub fn all_collect_streams(config: &UnifiedConfig) -> Vec<CollectStreamConfig> {
    let Some(collect) = config
        .raw
        .get("collect")
        .and_then(|value| value.as_object())
    else {
        return Vec::new();
    };

    collect
        .iter()
        .filter_map(|(log_source_key, entry)| {
            let ctx = FieldContext::entry("collect", log_source_key);
            let log_source_id = required_config_key::<LogSourceId>(log_source_key, ctx)?;
            let locator = required_string_field(entry, "locator", ctx)?;
            let subbox_endpoint =
                required_config_string::<WireEndpoint>(entry, "subbox_endpoint", ctx)?;
            let archive_id = required_config_string::<ArchiveId>(entry, "archive_id", ctx)?;
            let repo_id = required_config_string::<RepoId>(entry, "repo_id", ctx)?;
            let matching_strategy = optional_string_field(entry, "matching_strategy")
                .or_else(|| optional_string_field(entry, "access_method"))
                .unwrap_or_default();
            let container_identifier =
                optional_string_field(entry, "container_identifier").unwrap_or_default();
            let stamp_resource_identifier =
                bool_field_or(entry, "stamp_resource_identifier", false);

            let multiline = parse_multiline_config(entry.get("multiline"), ctx);
            let config_hash = CollectStreamConfig::compute_hash(
                &locator,
                &matching_strategy,
                subbox_endpoint.0.as_str(),
                archive_id.0.as_str(),
                repo_id.0.as_str(),
                multiline.as_ref(),
                stamp_resource_identifier,
            );

            Some(CollectStreamConfig {
                log_source_id: log_source_id.0,
                locator,
                matching_strategy,
                container_identifier,
                subbox_endpoint: subbox_endpoint.0,
                archive_id: archive_id.0,
                repo_id: repo_id.0,
                stamp_resource_identifier,
                multiline,
                config_hash,
            })
        })
        .collect()
}

/// Resolve collect directives via discovery cache (EdgePacer Knows Best).
///
/// Resolution never logs: each directive yields a [`CollectDiagnostic`] so the
/// caller can log only on status transitions instead of on every reconcile.
pub fn resolve_collect_streams(
    streams: &[CollectStreamConfig],
    cache: &crate::discovery::cache::DiscoveryCache,
) -> ResolvedCollectStreams {
    let mut resolved = ResolvedCollectStreams::default();
    resolve_collect_streams_into(&mut resolved, streams, cache, &HashSet::new());
    resolved
}

/// Claims-aware legacy resolution: a directive that resolves to a container
/// already claimed by a service description (matched on the access locator —
/// the concrete thing a pipeline would tail) yields no source. One pipeline
/// per container, even while Rails dual-emits a legacy stream alongside its
/// selector-backed description.
fn resolve_collect_streams_into(
    resolved: &mut ResolvedCollectStreams,
    streams: &[CollectStreamConfig],
    cache: &crate::discovery::cache::DiscoveryCache,
    claimed_locators: &HashSet<String>,
) {
    for stream in streams {
        let identifier = if !stream.container_identifier.is_empty() {
            stream.container_identifier.as_str()
        } else {
            stream.locator.as_str()
        };

        if identifier.is_empty() {
            resolved
                .diagnostics
                .push(not_found(stream, "missing locator".into()));
            continue;
        }

        if is_windows_event_log_method(&stream.matching_strategy) {
            resolved.streaming_sources.push(streaming_source(
                stream,
                StreamAccessMethod::WindowsEventLog {
                    channel: identifier.to_string(),
                },
            ));
            resolved
                .diagnostics
                .push(matched(stream, MatchVia::WindowsEventLog));
            continue;
        }

        if stream.matching_strategy == "file_path" {
            // A file's stable identity is the path it sits at — an exact-path
            // check, not the argv of whatever process writes it.
            if std::path::Path::new(identifier).is_file() {
                resolved.file_streams.push(log_stream_from_collect(
                    stream,
                    identifier,
                    FileSourceFormat::Plain,
                ));
                resolved
                    .diagnostics
                    .push(matched(stream, MatchVia::FilePath));
            } else {
                resolved
                    .diagnostics
                    .push(not_found(stream, format!("no file at {identifier}")));
            }
            continue;
        }

        let loggable_type = infer_loggable_type(&stream.matching_strategy);
        match cache.resolve(identifier, loggable_type) {
            CollectMatch::Matched(access) if claimed_locators.contains(&access.access_locator) => {
                resolved.diagnostics.push(CollectDiagnostic {
                    log_source_id: stream.log_source_id.clone(),
                    status: MatchStatus::Matched,
                    detail: "container claimed by a service description".into(),
                });
            }
            CollectMatch::Matched(access) => push_resolved_source(resolved, stream, access),
            CollectMatch::Ambiguous { candidates } => {
                resolved.diagnostics.push(CollectDiagnostic {
                    log_source_id: stream.log_source_id.clone(),
                    status: MatchStatus::Ambiguous,
                    detail: format!(
                        "{candidates} discovered sources matched {} ambiguously",
                        stream.matching_strategy
                    ),
                });
            }
            CollectMatch::NotFound => resolved.diagnostics.push(not_found(
                stream,
                format!(
                    "no discovered loggable for {}={identifier}",
                    stream.matching_strategy
                ),
            )),
        }
    }
}

/// Route one resolved access to the right pipeline lane and record a matched
/// diagnostic. Split out so `resolve_collect_streams` stays flat.
fn push_resolved_source(
    resolved: &mut ResolvedCollectStreams,
    stream: &CollectStreamConfig,
    access: ResolvedAccess,
) {
    let ResolvedAccess {
        access_method,
        matched_via,
        access_locator,
        ..
    } = access;

    route_source(resolved, stream, access_method, access_locator);
    resolved.diagnostics.push(matched(stream, matched_via));
}

/// Route one stream to the pipeline lane its access method demands. Shared by
/// legacy directive resolution and selector-synthesized sources, so both ride
/// the exact same lanes.
pub(super) fn route_source(
    resolved: &mut ResolvedCollectStreams,
    stream: &CollectStreamConfig,
    access_method: AccessMethod,
    access_locator: String,
) {
    match access_method {
        AccessMethod::File => resolved.file_streams.push(log_stream_from_collect(
            stream,
            &access_locator,
            FileSourceFormat::Plain,
        )),
        AccessMethod::DockerJsonFile => resolved.file_streams.push(log_stream_from_collect(
            stream,
            &access_locator,
            FileSourceFormat::DockerJson,
        )),
        AccessMethod::Kubernetes => resolved.file_streams.push(log_stream_from_collect(
            stream,
            &access_locator,
            FileSourceFormat::KubernetesCri,
        )),
        AccessMethod::DockerApi => resolved.streaming_sources.push(streaming_source(
            stream,
            StreamAccessMethod::DockerApi {
                container_id: access_locator,
            },
        )),
        AccessMethod::Journald => resolved.streaming_sources.push(streaming_source(
            stream,
            StreamAccessMethod::Journald {
                unit: access_locator,
            },
        )),
        AccessMethod::WindowsEventLog => resolved.streaming_sources.push(streaming_source(
            stream,
            StreamAccessMethod::WindowsEventLog {
                channel: access_locator,
            },
        )),
    }
}

fn streaming_source(
    stream: &CollectStreamConfig,
    access_method: StreamAccessMethod,
) -> StreamingSourceConfig {
    StreamingSourceConfig {
        log_source_id: stream.log_source_id.clone(),
        access_method,
        endpoint: stream.ship_endpoint().to_string(),
        archive_id: stream.archive_id.clone(),
        repo_id: stream.repo_id.clone(),
        stamp_resource_identifier: stream.stamp_resource_identifier,
        multiline: stream.multiline.clone(),
        config_hash: stream.config_hash.clone(),
    }
}

fn is_windows_event_log_method(method: &str) -> bool {
    matches!(
        method,
        "windows_event" | "windows_event_log" | "event_log" | "eventlog"
    )
}

fn matched(stream: &CollectStreamConfig, via: MatchVia) -> CollectDiagnostic {
    CollectDiagnostic {
        log_source_id: stream.log_source_id.clone(),
        status: MatchStatus::Matched,
        detail: format!("via {} ({})", via.as_str(), via.confidence().as_str()),
    }
}

fn not_found(stream: &CollectStreamConfig, detail: String) -> CollectDiagnostic {
    CollectDiagnostic {
        log_source_id: stream.log_source_id.clone(),
        status: MatchStatus::NotFound,
        detail,
    }
}

/// Resolve active collection from unified config: service descriptions first
/// (they claim containers in array order), then the legacy `collect` map with
/// claimed containers excluded.
pub fn resolved_collect_from_config(
    config: &UnifiedConfig,
    cache: &crate::discovery::cache::DiscoveryCache,
) -> ResolvedCollectStreams {
    let mut resolved = ResolvedCollectStreams::default();
    let descriptions = all_service_descriptions(config);
    let claimed_locators = resolve_service_descriptions(&descriptions, cache, &mut resolved);
    let collect = all_collect_streams(config);
    resolve_collect_streams_into(&mut resolved, &collect, cache, &claimed_locators);
    resolved
}

fn log_stream_from_collect(
    stream: &CollectStreamConfig,
    path: &str,
    source_format: FileSourceFormat,
) -> LogStreamConfig {
    let config_hash = LogStreamConfig::compute_hash(
        path,
        stream.ship_endpoint(),
        &stream.archive_id,
        &stream.repo_id,
        stream.multiline.as_ref(),
        source_format,
        stream.stamp_resource_identifier,
    );
    LogStreamConfig {
        log_source_id: stream.log_source_id.clone(),
        path: path.to_string(),
        endpoint: stream.ship_endpoint().to_string(),
        archive_id: stream.archive_id.clone(),
        repo_id: stream.repo_id.clone(),
        stamp_resource_identifier: stream.stamp_resource_identifier,
        source_format,
        multiline: stream.multiline.clone(),
        config_hash,
    }
}

pub(super) fn parse_multiline_config(
    value: Option<&serde_json::Value>,
    ctx: FieldContext<'_>,
) -> Option<MultilineConfig> {
    let multiline = value?;
    let start_pattern = required_string_field(multiline, "start_pattern", ctx)?;
    let max_lines = u32_field_or(multiline, "max_lines", 0, ctx);
    let timeout_secs = multiline
        .get("timeout_seconds")
        .and_then(|value| value.as_u64())
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or_else(|| u32_field_or(multiline, "timeout_secs", 0, ctx));
    Some(MultilineConfig {
        start_pattern,
        max_lines,
        timeout_secs,
    })
}

/// Serialize the multiline settings into a stable fragment for config-hash
/// computation. `-` denotes "no multiline", so toggling it changes the hash.
fn multiline_hash_part(multiline: Option<&MultilineConfig>) -> String {
    match multiline {
        Some(multiline) => format!(
            "{}|{}|{}",
            multiline.start_pattern, multiline.max_lines, multiline.timeout_secs
        ),
        None => String::from("-"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::{Census, Container, DiscoveryCache};
    use serde_json::json;
    use std::collections::HashMap;

    fn unified(raw: serde_json::Value) -> UnifiedConfig {
        UnifiedConfig::new(raw, "etag-1".into())
    }

    fn docker_container(id: &str, name: &str, log_path: &str) -> Container {
        Container {
            id: id.into(),
            name: name.into(),
            service_name: String::new(),
            service_name_explicit: false,
            image: "nginx:latest".into(),
            state: "running".into(),
            labels: HashMap::new(),
            env: Vec::new(),
            runtime: "docker".into(),
            log_path: log_path.into(),
            log_format: "plain_text".into(),
            pod_uid: String::new(),
            pod_name: String::new(),
            namespace: String::new(),
            node_name: String::new(),
            deployment: String::new(),
            workload_kind: String::new(),
            container_id: id.into(),
            container_name: String::new(),
            runtime_process: None,
        }
    }

    #[test]
    fn collect_streams_require_subbox_endpoint_for_wire_shipping() {
        let unified = unified(json!({
            "collect": {
                "src-wire": {
                    "locator": "/var/log/app.log",
                    "matching_strategy": "file_path",
                    "subbox_endpoint": "https://1.subbox.example.com/wire",
                    "archive_id": "arc",
                    "repo_id": "repo"
                },
                "missing-subbox": {
                    "locator": "/var/log/old.log",
                    "matching_strategy": "file_path",
                    "archive_id": "arc",
                    "repo_id": "repo"
                }
            }
        }));

        let streams = all_collect_streams(&unified);

        assert_eq!(streams.len(), 1);
        assert_eq!(streams[0].log_source_id, "src-wire");
        assert_eq!(
            streams[0].ship_endpoint(),
            "https://1.subbox.example.com/wire"
        );
        assert_eq!(
            streams[0].subbox_endpoint,
            "https://1.subbox.example.com/wire"
        );

        let same_stream_different_endpoint = CollectStreamConfig::compute_hash(
            "/var/log/app.log",
            "file_path",
            "https://2.subbox.example.com/wire",
            "arc",
            "repo",
            None,
            false,
        );
        assert_ne!(streams[0].config_hash, same_stream_different_endpoint);
    }

    #[test]
    fn parses_collect_map_entries() {
        let unified = unified(json!({
            "collect": {
                "collectable-42": {
                    "locator": "/var/log/app.log",
                    "matching_strategy": "file_path",
                    "subbox_endpoint": "https://subbox.example.com/wire",
                    "archive_id": "arc_1",
                    "repo_id": "repo_1"
                }
            }
        }));

        let streams = all_collect_streams(&unified);

        assert_eq!(streams.len(), 1);
        assert_eq!(streams[0].log_source_id, "collectable-42");
        assert_eq!(streams[0].locator, "/var/log/app.log");
        assert_eq!(streams[0].matching_strategy, "file_path");
    }

    #[test]
    fn resolved_collect_from_config_uses_discovery_cache() {
        let unified = unified(json!({
            "collect": {
                "collect-file": {
                    "locator": "file-app",
                    "matching_strategy": "container_name",
                    "subbox_endpoint": "https://collect.example.com/wire",
                    "archive_id": "arc_file",
                    "repo_id": "repo_file"
                },
                "collect-stream": {
                    "locator": "stream-app",
                    "matching_strategy": "container_name",
                    "subbox_endpoint": "https://collect.example.com/wire",
                    "archive_id": "arc_stream",
                    "repo_id": "repo_stream",
                    "multiline": {
                        "start_pattern": "^\\d{4}-\\d{2}-\\d{2}",
                        "max_lines": 500,
                        "timeout_seconds": 5
                    }
                }
            }
        }));
        let mut census = Census::default();
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("file-app.log");
        std::fs::write(&log_path, "line\n").unwrap();
        census.containers.push(docker_container(
            "file-abc123def456",
            "file-app",
            log_path.to_str().unwrap(),
        ));
        census
            .containers
            .push(docker_container("stream-abc123def456", "stream-app", ""));
        let mut cache = DiscoveryCache::new();
        cache.update_all(&census);

        let resolved = resolved_collect_from_config(&unified, &cache);

        assert_eq!(resolved.file_streams.len(), 1);
        let file = &resolved.file_streams[0];
        assert_eq!(file.log_source_id, "collect-file");
        assert_eq!(file.path, log_path.to_str().unwrap());
        assert_eq!(file.endpoint, "https://collect.example.com/wire");
        assert_eq!(file.archive_id, "arc_file");
        assert_eq!(file.repo_id, "repo_file");
        assert_eq!(file.source_format, FileSourceFormat::DockerJson);

        assert_eq!(resolved.streaming_sources.len(), 1);
        let stream = &resolved.streaming_sources[0];
        assert_eq!(stream.log_source_id, "collect-stream");
        assert_eq!(
            stream.access_method,
            StreamAccessMethod::DockerApi {
                container_id: "stream-abc123def456".into()
            }
        );
        assert_eq!(stream.endpoint, "https://collect.example.com/wire");
        assert_eq!(stream.archive_id, "arc_stream");
        assert_eq!(stream.repo_id, "repo_stream");
        assert_eq!(
            stream.multiline.as_ref().map(|config| {
                (
                    config.start_pattern.as_str(),
                    config.max_lines,
                    config.timeout_secs,
                )
            }),
            Some((r"^\d{4}-\d{2}-\d{2}", 500, 5))
        );
    }

    #[test]
    fn windows_event_log_collect_source_resolves_directly() {
        let unified = unified(json!({
            "collect": {
                "windows-application": {
                    "locator": "Application",
                    "access_method": "windows_event_log",
                    "subbox_endpoint": "https://collect.example.com/wire",
                    "archive_id": "arc_win",
                    "repo_id": "repo_win"
                }
            }
        }));
        let cache = DiscoveryCache::new();

        let resolved = resolved_collect_from_config(&unified, &cache);

        assert!(resolved.file_streams.is_empty());
        assert_eq!(resolved.streaming_sources.len(), 1);
        let stream = &resolved.streaming_sources[0];
        assert_eq!(stream.log_source_id, "windows-application");
        assert_eq!(
            stream.access_method,
            StreamAccessMethod::WindowsEventLog {
                channel: "Application".into()
            }
        );
        assert_eq!(stream.endpoint, "https://collect.example.com/wire");
        assert_eq!(stream.archive_id, "arc_win");
        assert_eq!(stream.repo_id, "repo_win");

        assert_eq!(resolved.diagnostics.len(), 1);
        assert_eq!(resolved.diagnostics[0].status, MatchStatus::Matched);
        assert!(resolved.diagnostics[0].detail.contains("windows_event_log"));
    }

    #[test]
    fn stamp_resource_identifier_defaults_false_and_opts_in() {
        let unified = unified(json!({
            "collect": {
                "default-src": {
                    "locator": "/var/log/a.log",
                    "matching_strategy": "file_path",
                    "subbox_endpoint": "https://s/wire",
                    "archive_id": "arc",
                    "repo_id": "repo"
                },
                "stamped-src": {
                    "locator": "/var/log/b.log",
                    "matching_strategy": "file_path",
                    "subbox_endpoint": "https://s/wire",
                    "archive_id": "arc",
                    "repo_id": "repo",
                    "stamp_resource_identifier": true
                }
            }
        }));

        let streams = all_collect_streams(&unified);
        let by_id = |id: &str| streams.iter().find(|s| s.log_source_id == id).unwrap();

        assert!(
            !by_id("default-src").stamp_resource_identifier,
            "an absent flag defaults to false"
        );
        assert!(
            by_id("stamped-src").stamp_resource_identifier,
            "an explicit true opts the source in"
        );

        // The flag is folded into the restart hash, so flipping it restarts the
        // pipeline (the shipper is rebuilt with/without stamping).
        let stamped = CollectStreamConfig::compute_hash(
            "/var/log/a.log",
            "file_path",
            "https://s/wire",
            "arc",
            "repo",
            None,
            true,
        );
        assert_ne!(by_id("default-src").config_hash, stamped);
    }

    #[test]
    fn collect_streams_skip_empty_required_fields() {
        let unified = unified(json!({
            "collect": {
                "valid": {
                    "locator": "/var/log/app.log",
                    "matching_strategy": "file_path",
                    "subbox_endpoint": "https://s/wire",
                    "archive_id": "arc",
                    "repo_id": "repo"
                },
                "empty-endpoint": {
                    "locator": "/var/log/app.log",
                    "matching_strategy": "file_path",
                    "subbox_endpoint": "",
                    "archive_id": "arc",
                    "repo_id": "repo"
                },
                "empty-locator": {
                    "locator": "",
                    "matching_strategy": "file_path",
                    "subbox_endpoint": "https://s/wire",
                    "archive_id": "arc",
                    "repo_id": "repo"
                }
            }
        }));

        let streams = all_collect_streams(&unified);

        assert_eq!(streams.len(), 1);
        assert_eq!(streams[0].log_source_id, "valid");
    }

    #[test]
    fn resolve_emits_diagnostics_for_present_and_missing_files() {
        let dir = tempfile::tempdir().unwrap();
        let present = dir.path().join("present.log");
        std::fs::write(&present, "x\n").unwrap();

        let unified = unified(json!({
            "collect": {
                "has-file": {
                    "locator": present.to_str().unwrap(),
                    "matching_strategy": "file_path",
                    "subbox_endpoint": "https://s/wire",
                    "archive_id": "arc",
                    "repo_id": "repo"
                },
                "no-file": {
                    "locator": "/definitely/missing.log",
                    "matching_strategy": "file_path",
                    "subbox_endpoint": "https://s/wire",
                    "archive_id": "arc",
                    "repo_id": "repo"
                }
            }
        }));
        let cache = DiscoveryCache::new();
        let resolved = resolved_collect_from_config(&unified, &cache);

        // Present file resolves to a stream; the missing one becomes a NotFound
        // diagnostic (not an inline warn) so the caller can dedup it.
        assert_eq!(resolved.file_streams.len(), 1);
        assert_eq!(
            resolved.file_streams[0].source_format,
            FileSourceFormat::Plain
        );
        let by_id = |id: &str| {
            resolved
                .diagnostics
                .iter()
                .find(|d| d.log_source_id == id)
                .unwrap()
        };
        assert_eq!(by_id("has-file").status, MatchStatus::Matched);
        assert_eq!(by_id("no-file").status, MatchStatus::NotFound);
        assert!(by_id("no-file").detail.contains("no file at"));
    }

    #[test]
    fn resolve_refuses_ambiguous_weak_container_match() {
        // Two containers share a 12-char id prefix; a weak id match must surface
        // as Ambiguous and produce no stream rather than guessing.
        let unified = unified(json!({
            "collect": {
                "amb": {
                    "locator": "aaaa11112222zz",
                    "matching_strategy": "container_id",
                    "subbox_endpoint": "https://s/wire",
                    "archive_id": "arc",
                    "repo_id": "repo"
                }
            }
        }));
        let mut census = Census::default();
        census
            .containers
            .push(docker_container("aaaa11112222aa", "svc-a", ""));
        census
            .containers
            .push(docker_container("aaaa11112222bb", "svc-b", ""));
        let mut cache = DiscoveryCache::new();
        cache.update_all(&census);

        let resolved = resolved_collect_from_config(&unified, &cache);

        assert!(resolved.file_streams.is_empty());
        assert!(resolved.streaming_sources.is_empty());
        assert_eq!(resolved.diagnostics.len(), 1);
        assert_eq!(resolved.diagnostics[0].status, MatchStatus::Ambiguous);
    }
}
