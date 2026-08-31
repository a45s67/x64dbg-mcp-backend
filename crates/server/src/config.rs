use std::{
    env, fs,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    time::Duration,
};

use serde::Deserialize;
use thiserror::Error;

const DEFAULT_BIND: &str = "127.0.0.1";
const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;
const HARD_MAX_BODY_BYTES: usize = 4 * 1024 * 1024;
const DEFAULT_MAX_INFLIGHT: usize = 8;
const HARD_MAX_INFLIGHT: usize = 32;
const DEFAULT_MAX_OUTPUT_BYTES: usize = 1024 * 1024;
const HARD_MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const DEFAULT_REQUEST_TIMEOUT_MS: usize = 10_000;
const HARD_REQUEST_TIMEOUT_MS: usize = 30_000;
const DEFAULT_MUTATION_TIMEOUT_MS: usize = 30_000;
const HARD_MUTATION_TIMEOUT_MS: usize = 120_000;
const DEFAULT_SHUTDOWN_TIMEOUT_MS: usize = 10_000;
const HARD_SHUTDOWN_TIMEOUT_MS: usize = 30_000;
const DEFAULT_MAX_HEADER_COUNT: usize = 64;
const HARD_MAX_HEADER_COUNT: usize = 128;
const DEFAULT_MAX_HEADER_BYTES: usize = 32 * 1024;
const HARD_MAX_HEADER_BYTES: usize = 64 * 1024;
const DEFAULT_MAX_REQUESTS_PER_SECOND: usize = 100;
const HARD_MAX_REQUESTS_PER_SECOND: usize = 1_000;

#[derive(Debug)]
pub struct Config {
    bind: IpAddr,
    port: u16,
    bearer_token: Vec<u8>,
    pub max_body_bytes: usize,
    pub max_inflight: usize,
    pub max_output_bytes: usize,
    pub max_header_count: usize,
    pub max_header_bytes: usize,
    pub max_requests_per_second: usize,
    request_timeout: Duration,
    mutation_timeout: Duration,
    shutdown_timeout: Duration,
    allowed_origins: Vec<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("X64DBG_MCP_BIND is not a valid IP address")]
    InvalidBind,
    #[error("X64DBG_MCP_BIND must be a loopback address")]
    NonLoopbackBind,
    #[error("X64DBG_MCP_PORT is required and must be between 1 and 65535")]
    InvalidPort,
    #[error("X64DBG_MCP_TOKEN is required and must contain at least 32 bytes")]
    InvalidToken,
    #[error("{0} must be an integer no greater than {1}")]
    InvalidLimit(&'static str, usize),
    #[error(
        "X64DBG_MCP_ALLOWED_ORIGINS must contain at most 16 comma-separated ASCII origins of at most 256 bytes"
    )]
    InvalidOrigins,
    #[error("sidecar TOML configuration could not be read or parsed")]
    InvalidFile,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct FileConfig {
    bind: Option<String>,
    port: Option<u16>,
    bearer_token: Option<String>,
    max_body_bytes: Option<usize>,
    max_inflight: Option<usize>,
    max_output_bytes: Option<usize>,
    request_timeout_ms: Option<usize>,
    mutation_timeout_ms: Option<usize>,
    shutdown_timeout_ms: Option<usize>,
    max_header_count: Option<usize>,
    max_header_bytes: Option<usize>,
    max_requests_per_second: Option<usize>,
    allowed_origins: Option<Vec<String>>,
}

impl Config {
    /// Loads and validates the sidecar configuration from environment variables.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when a required value is missing, malformed, outside
    /// its hard bound, or requests a non-loopback bind address.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_sources(FileConfig::default())
    }

    /// Loads the optional TOML file beside the executable, then overlays
    /// environment variables.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] for an unreadable/invalid explicitly configured
    /// file or any invalid effective setting.
    pub fn load() -> Result<Self, ConfigError> {
        Self::load_from(None)
    }

    /// Loads from an explicitly selected file or the normal environment/beside-
    /// executable location.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when the selected file or effective settings are
    /// invalid.
    pub fn load_from(command_path: Option<PathBuf>) -> Result<Self, ConfigError> {
        let explicit = command_path.or_else(|| env::var_os("X64DBG_MCP_CONFIG").map(PathBuf::from));
        let path = explicit.clone().unwrap_or_else(|| {
            env::current_exe()
                .ok()
                .and_then(|path| {
                    path.parent()
                        .map(|parent| parent.join("x64dbg-mcp-server.toml"))
                })
                .unwrap_or_else(|| PathBuf::from("x64dbg-mcp-server.toml"))
        });
        let file = match fs::read_to_string(&path) {
            Ok(contents) => toml::from_str(&contents).map_err(|_| ConfigError::InvalidFile)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && explicit.is_none() => {
                FileConfig::default()
            }
            Err(_) => return Err(ConfigError::InvalidFile),
        };
        Self::from_sources(file)
    }

    fn from_sources(file: FileConfig) -> Result<Self, ConfigError> {
        let bind = env::var("X64DBG_MCP_BIND")
            .ok()
            .or(file.bind)
            .unwrap_or_else(|| DEFAULT_BIND.to_owned())
            .parse::<IpAddr>()
            .map_err(|_| ConfigError::InvalidBind)?;
        if !bind.is_loopback() {
            return Err(ConfigError::NonLoopbackBind);
        }

        let port = env::var("X64DBG_MCP_PORT")
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
            .or(file.port)
            .filter(|value| *value != 0)
            .ok_or(ConfigError::InvalidPort)?;

        let bearer_token = env::var("X64DBG_MCP_TOKEN")
            .ok()
            .or(file.bearer_token)
            .filter(|value| value.len() >= 32)
            .ok_or(ConfigError::InvalidToken)?
            .into_bytes();

        let max_body_bytes = parse_limit(
            "X64DBG_MCP_MAX_BODY_BYTES",
            file.max_body_bytes.unwrap_or(DEFAULT_MAX_BODY_BYTES),
            HARD_MAX_BODY_BYTES,
        )?;
        let max_inflight = parse_limit(
            "X64DBG_MCP_MAX_INFLIGHT",
            file.max_inflight.unwrap_or(DEFAULT_MAX_INFLIGHT),
            HARD_MAX_INFLIGHT,
        )?;
        let request_timeout_ms = parse_limit(
            "X64DBG_MCP_REQUEST_TIMEOUT_MS",
            file.request_timeout_ms
                .unwrap_or(DEFAULT_REQUEST_TIMEOUT_MS),
            HARD_REQUEST_TIMEOUT_MS,
        )?;
        let mutation_timeout_ms = parse_limit(
            "X64DBG_MCP_MUTATION_TIMEOUT_MS",
            file.mutation_timeout_ms
                .unwrap_or(DEFAULT_MUTATION_TIMEOUT_MS),
            HARD_MUTATION_TIMEOUT_MS,
        )?;
        let shutdown_timeout_ms = parse_limit(
            "X64DBG_MCP_SHUTDOWN_TIMEOUT_MS",
            file.shutdown_timeout_ms
                .unwrap_or(DEFAULT_SHUTDOWN_TIMEOUT_MS),
            HARD_SHUTDOWN_TIMEOUT_MS,
        )?;
        let max_output_bytes = parse_limit(
            "X64DBG_MCP_MAX_OUTPUT_BYTES",
            file.max_output_bytes.unwrap_or(DEFAULT_MAX_OUTPUT_BYTES),
            HARD_MAX_OUTPUT_BYTES,
        )?;
        let allowed_origins = parse_origins(file.allowed_origins.unwrap_or_default())?;
        let max_header_count = parse_limit(
            "X64DBG_MCP_MAX_HEADER_COUNT",
            file.max_header_count.unwrap_or(DEFAULT_MAX_HEADER_COUNT),
            HARD_MAX_HEADER_COUNT,
        )?;
        let max_header_bytes = parse_limit(
            "X64DBG_MCP_MAX_HEADER_BYTES",
            file.max_header_bytes.unwrap_or(DEFAULT_MAX_HEADER_BYTES),
            HARD_MAX_HEADER_BYTES,
        )?;
        let max_requests_per_second = parse_limit(
            "X64DBG_MCP_MAX_REQUESTS_PER_SECOND",
            file.max_requests_per_second
                .unwrap_or(DEFAULT_MAX_REQUESTS_PER_SECOND),
            HARD_MAX_REQUESTS_PER_SECOND,
        )?;

        Ok(Self {
            bind,
            port,
            bearer_token,
            max_body_bytes,
            max_inflight,
            max_output_bytes,
            max_header_count,
            max_header_bytes,
            max_requests_per_second,
            request_timeout: Duration::from_millis(request_timeout_ms as u64),
            mutation_timeout: Duration::from_millis(mutation_timeout_ms as u64),
            shutdown_timeout: Duration::from_millis(shutdown_timeout_ms as u64),
            allowed_origins,
        })
    }

    #[must_use]
    pub const fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.bind, self.port)
    }

    #[must_use]
    pub fn bearer_token(&self) -> &[u8] {
        &self.bearer_token
    }

    #[must_use]
    pub const fn request_timeout(&self) -> Duration {
        self.request_timeout
    }

    #[must_use]
    pub const fn mutation_timeout(&self) -> Duration {
        self.mutation_timeout
    }

    #[must_use]
    pub const fn shutdown_timeout(&self) -> Duration {
        self.shutdown_timeout
    }

    #[must_use]
    pub fn origin_allowed(&self, origin: &str) -> bool {
        self.allowed_origins.iter().any(|allowed| allowed == origin)
    }

    #[cfg(test)]
    #[must_use]
    pub fn for_test(token: &str) -> Self {
        Self {
            bind: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            port: 3000,
            bearer_token: token.as_bytes().to_vec(),
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            max_inflight: DEFAULT_MAX_INFLIGHT,
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            max_header_count: DEFAULT_MAX_HEADER_COUNT,
            max_header_bytes: DEFAULT_MAX_HEADER_BYTES,
            max_requests_per_second: DEFAULT_MAX_REQUESTS_PER_SECOND,
            request_timeout: Duration::from_millis(DEFAULT_REQUEST_TIMEOUT_MS as u64),
            mutation_timeout: Duration::from_millis(DEFAULT_MUTATION_TIMEOUT_MS as u64),
            shutdown_timeout: Duration::from_millis(DEFAULT_SHUTDOWN_TIMEOUT_MS as u64),
            allowed_origins: Vec::new(),
        }
    }
}

fn parse_origins(default: Vec<String>) -> Result<Vec<String>, ConfigError> {
    let origins = env::var("X64DBG_MCP_ALLOWED_ORIGINS").map_or(default, |value| {
        value
            .split(',')
            .map(str::trim)
            .map(str::to_owned)
            .collect::<Vec<_>>()
    });
    if origins.len() > 16
        || origins
            .iter()
            .any(|origin| origin.is_empty() || origin.len() > 256 || !origin.is_ascii())
    {
        return Err(ConfigError::InvalidOrigins);
    }
    Ok(origins)
}

fn parse_limit(name: &'static str, default: usize, hard_max: usize) -> Result<usize, ConfigError> {
    let value = match env::var(name) {
        Ok(value) => value
            .parse::<usize>()
            .map_err(|_| ConfigError::InvalidLimit(name, hard_max))?,
        Err(_) => default,
    };
    (value > 0 && value <= hard_max)
        .then_some(value)
        .ok_or(ConfigError::InvalidLimit(name, hard_max))
}

#[cfg(test)]
mod tests {
    use super::FileConfig;

    #[test]
    fn minimal_installed_toml_uses_optional_server_defaults() {
        let parsed: FileConfig = toml::from_str(
            r#"
                bind = "127.0.0.1"
                port = 43164
                bearer_token = "0123456789abcdef0123456789abcdef"
            "#,
        )
        .unwrap();
        assert_eq!(parsed.port, Some(43164));
        assert!(parsed.max_inflight.is_none());
        assert!(parsed.request_timeout_ms.is_none());
        assert!(parsed.allowed_origins.is_none());
    }

    #[test]
    fn toml_schema_accepts_documented_fields_and_rejects_unknown_ones() {
        let parsed: FileConfig = toml::from_str(
            r#"
                bind = "127.0.0.1"
                port = 43129
                bearer_token = "0123456789abcdef0123456789abcdef"
                max_body_bytes = 1048576
                max_inflight = 8
                max_output_bytes = 1048576
                request_timeout_ms = 10000
                mutation_timeout_ms = 30000
                shutdown_timeout_ms = 10000
                max_header_count = 64
                max_header_bytes = 32768
                max_requests_per_second = 100
                allowed_origins = ["https://gateway.example"]
            "#,
        )
        .unwrap();
        assert_eq!(parsed.port, Some(43129));
        assert!(toml::from_str::<FileConfig>("unknown = true").is_err());
    }
}
