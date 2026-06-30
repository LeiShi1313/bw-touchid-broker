use anyhow::{Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub server: ServerConfig,
    pub bitwarden: BitwardenConfig,
    pub keychain: KeychainConfig,
    pub approval: ApprovalConfig,
    pub audit: AuditConfig,
    pub signing: SigningConfig,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub public_url: String,
    pub tls_cert: String,
    pub tls_key: String,
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BitwardenConfig {
    pub bw_path: String,
    pub server_url: String,
    pub email: String,
    pub appdata_dir: String,
    #[serde(default)]
    pub sync_before_read: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KeychainConfig {
    pub service: String,
    pub account: String,
    pub helper_path: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ApprovalConfig {
    #[serde(default = "default_true")]
    pub confirm_dialog: bool,
    #[serde(default = "default_dialog_timeout")]
    pub dialog_timeout_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuditConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub path: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SigningConfig {
    #[serde(default = "default_max_skew")]
    pub max_skew_seconds: i64,
    #[serde(default = "default_nonce_ttl")]
    pub nonce_ttl_seconds: i64,
    pub clients: Vec<ClientConfig>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClientConfig {
    pub id: String,
    pub secret: String,
    #[serde(default)]
    pub approval: ClientApprovalMode,
    #[serde(default)]
    pub allowed_secrets: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientApprovalMode {
    #[default]
    Prompt,
    Trusted,
}

impl ClientApprovalMode {
    pub fn is_trusted(&self) -> bool {
        matches!(self, Self::Trusted)
    }
}

fn default_true() -> bool {
    true
}

fn default_dialog_timeout() -> u64 {
    120
}

fn default_max_skew() -> i64 {
    300
}

fn default_nonce_ttl() -> i64 {
    600
}

fn default_max_body_bytes() -> usize {
    65_536
}

pub fn default_home() -> PathBuf {
    env::var_os("BW_BROKER_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let home = env::var_os("HOME").expect("HOME is required");
            PathBuf::from(home).join(".bw-broker")
        })
}

pub fn expand_path(value: &str, home: &Path) -> PathBuf {
    if let Some(rest) = value.strip_prefix("$BW_BROKER_HOME/") {
        return home.join(rest);
    }
    if value == "$BW_BROKER_HOME" {
        return home.to_path_buf();
    }
    if let Some(rest) = value.strip_prefix("~/") {
        if let Some(user_home) = env::var_os("HOME") {
            return PathBuf::from(user_home).join(rest);
        }
    }
    PathBuf::from(value)
}

pub fn config_path(home: &Path) -> PathBuf {
    home.join("config.json")
}

pub fn catalog_path(home: &Path) -> PathBuf {
    home.join("catalog.json")
}

pub fn nonce_path(home: &Path) -> PathBuf {
    home.join("nonces.json")
}

pub fn default_config(
    _home: &Path,
    email: String,
    server_url: String,
    client_id: String,
    host: String,
    port: u16,
    public_url: Option<String>,
) -> Config {
    let client_secret = generate_client_secret();
    let account = if email.is_empty() {
        "ai-agent@example.com".to_string()
    } else {
        email.clone()
    };
    let public_url = public_url.unwrap_or_else(|| format!("https://{host}:{port}"));
    Config {
        server: ServerConfig {
            host,
            port,
            public_url,
            tls_cert: "$BW_BROKER_HOME/tls/server.crt".to_string(),
            tls_key: "$BW_BROKER_HOME/tls/server.key".to_string(),
            max_body_bytes: default_max_body_bytes(),
        },
        bitwarden: BitwardenConfig {
            bw_path: "bw".to_string(),
            server_url,
            email,
            appdata_dir: "$BW_BROKER_HOME/bw-cli".to_string(),
            sync_before_read: false,
        },
        keychain: KeychainConfig {
            service: "bw-touchid-broker.master-password".to_string(),
            account,
            helper_path: "$BW_BROKER_HOME/bin/bw-broker-keychain".to_string(),
        },
        approval: ApprovalConfig {
            confirm_dialog: true,
            dialog_timeout_seconds: default_dialog_timeout(),
        },
        audit: AuditConfig {
            enabled: true,
            path: "$BW_BROKER_HOME/audit.log".to_string(),
        },
        signing: SigningConfig {
            max_skew_seconds: default_max_skew(),
            nonce_ttl_seconds: default_nonce_ttl(),
            clients: vec![ClientConfig {
                id: client_id,
                secret: client_secret,
                approval: ClientApprovalMode::Prompt,
                allowed_secrets: vec!["*".to_string()],
            }],
        },
    }
}

pub fn generate_client_secret() -> String {
    let mut secret_bytes = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut secret_bytes);
    URL_SAFE_NO_PAD.encode(secret_bytes)
}

pub fn load_config(home: &Path) -> Result<Config> {
    let path = config_path(home);
    let text = fs::read_to_string(&path).with_context(|| {
        format!(
            "missing config {}; run `bw-broker init` first",
            path.display()
        )
    })?;
    serde_json::from_str(&text).with_context(|| format!("failed to parse {}", path.display()))
}

pub fn save_config(home: &Path, config: &Config) -> Result<()> {
    write_private_json(&config_path(home), config)
}

pub fn write_private_json<T: Serialize + ?Sized>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    let text = serde_json::to_string_pretty(value)?;
    fs::write(&tmp, format!("{text}\n"))?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    fs::rename(&tmp, path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

pub fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

pub fn find_client<'a>(config: &'a Config, client_id: &str) -> Option<&'a ClientConfig> {
    config
        .signing
        .clients
        .iter()
        .find(|client| client.id == client_id)
}
