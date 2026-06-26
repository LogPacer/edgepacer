/// How to collect logs from a non-file streaming source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamAccessMethod {
    DockerApi { container_id: String },
    Journald { unit: String },
    WindowsEventLog { channel: String },
}

/// A streaming log source extracted from unified config.
#[derive(Debug, Clone)]
pub struct StreamingSourceConfig {
    pub log_source_id: String,
    pub access_method: StreamAccessMethod,
    pub endpoint: String,
    pub archive_id: String,
    pub repo_id: String,
    /// Stamp the agent's `resource_identifier` into shipped metadata. Default
    /// false; logpacer opts a source in per `stamp_resource_identifier` in the collect map.
    pub stamp_resource_identifier: bool,
    pub config_hash: String,
}
