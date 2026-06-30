use bw_touchid_broker::catalog::{save_catalog, Catalog, CatalogEntry};
use bw_touchid_broker::certs::ensure_self_signed_cert;
use bw_touchid_broker::cli::run_from;
use bw_touchid_broker::config::{
    save_config, ApprovalConfig, AuditConfig, BitwardenConfig, ClientApprovalMode, ClientConfig,
    Config, KeychainConfig, ServerConfig, SigningConfig,
};
use bw_touchid_broker::server::serve_config;
use bw_touchid_broker::signing::signed_headers_json;
use reqwest::StatusCode;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tempfile::TempDir;

#[tokio::test]
async fn signed_secret_request_unlocks_and_fetches_one_item() {
    let fixture = Fixture::new();
    let port = free_port();
    let config = fixture.config(port, false);
    let catalog = Catalog {
        version: 1,
        secrets: BTreeMap::from([(
            "github_token".to_string(),
            CatalogEntry {
                item_id: "item-1".to_string(),
                kind: "login".to_string(),
                description: "GitHub token".to_string(),
                return_fields: vec!["username".to_string(), "password".to_string()],
                approval_required: false,
                ttl_seconds: 60,
                allowed_clients: vec!["remote-agent".to_string()],
                metadata: json!({}),
            },
        )]),
    };
    save_config(fixture.home(), &config).unwrap();
    save_catalog(fixture.home(), &catalog).unwrap();

    let server_home = fixture.home().to_path_buf();
    let server_config = config.clone();
    let handle = tokio::spawn(async move {
        let _ = serve_config(server_home, server_config).await;
    });
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    wait_for_health(&client, port).await;

    let body = serde_json::to_vec(&json!({
        "secret_id": "github_token",
        "purpose": "unit test clone",
        "run_id": "test-run",
        "fields": ["username", "password"]
    }))
    .unwrap();
    let signed = signed_headers_json(
        "remote-agent",
        "client-secret",
        "POST",
        "/v1/secret-requests",
        &body,
        "nonce-1",
    )
    .unwrap();
    let mut request = client
        .post(format!("https://127.0.0.1:{port}/v1/secret-requests"))
        .header("content-type", "application/json")
        .body(body);
    for (key, value) in signed.as_object().unwrap() {
        request = request.header(key, value.as_str().unwrap());
    }
    let response = request.send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let payload: Value = response.json().await.unwrap();
    assert_eq!(
        payload,
        json!({
            "secret_id": "github_token",
            "fields": {"username": "bot", "password": "token-value"},
            "ttl_seconds": 60
        })
    );

    handle.abort();
    let calls = fs::read_to_string(fixture.call_log()).unwrap();
    assert!(calls.contains("--nointeraction status|"));
    assert!(calls.contains(
        "--nointeraction --raw unlock --passwordenv BW_BROKER_MASTER_PASSWORD|agent-master"
    ));
    assert!(calls.contains("--nointeraction --session session-123 get item item-1|"));
    assert!(fs::read_to_string(fixture.home().join("audit.log"))
        .unwrap()
        .contains("\"event\":\"secret_released\""));
}

#[tokio::test]
async fn trusted_client_skips_per_request_approval() {
    let fixture = Fixture::new();
    let port = free_port();
    let mut config = fixture.config(port, false);
    config.approval.confirm_dialog = true;
    config.signing.clients[0].approval = ClientApprovalMode::Trusted;
    let catalog = Catalog {
        version: 1,
        secrets: BTreeMap::from([(
            "github_token".to_string(),
            CatalogEntry {
                item_id: "item-1".to_string(),
                kind: "login".to_string(),
                description: "GitHub token".to_string(),
                return_fields: vec!["password".to_string()],
                approval_required: true,
                ttl_seconds: 60,
                allowed_clients: vec!["remote-agent".to_string()],
                metadata: json!({}),
            },
        )]),
    };
    save_config(fixture.home(), &config).unwrap();
    save_catalog(fixture.home(), &catalog).unwrap();

    let server_home = fixture.home().to_path_buf();
    let server_config = config.clone();
    let handle = tokio::spawn(async move {
        let _ = serve_config(server_home, server_config).await;
    });
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    wait_for_health(&client, port).await;

    let body = serde_json::to_vec(&json!({
        "secret_id": "github_token",
        "purpose": "trusted client unit test",
        "run_id": "test-run",
        "fields": ["password"]
    }))
    .unwrap();
    let signed = signed_headers_json(
        "remote-agent",
        "client-secret",
        "POST",
        "/v1/secret-requests",
        &body,
        "nonce-trusted",
    )
    .unwrap();
    let mut request = client
        .post(format!("https://127.0.0.1:{port}/v1/secret-requests"))
        .header("content-type", "application/json")
        .body(body);
    for (key, value) in signed.as_object().unwrap() {
        request = request.header(key, value.as_str().unwrap());
    }
    let response = request.send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let payload: Value = response.json().await.unwrap();
    assert_eq!(payload["fields"], json!({"password": "token-value"}));

    handle.abort();
}

#[tokio::test]
async fn build_catalog_uses_stored_master_password_and_lists_items() {
    let fixture = Fixture::new();
    let config = fixture.config(27443, true);
    save_config(fixture.home(), &config).unwrap();

    run_from([
        "bw-broker",
        "--home",
        fixture.home().to_str().unwrap(),
        "build-catalog",
        "--allowed-client",
        "remote-agent",
        "--collection-id",
        "collection-1",
        "--organization-id",
        "org-1",
    ])
    .await
    .unwrap();

    let catalog: Value =
        serde_json::from_str(&fs::read_to_string(fixture.home().join("catalog.json")).unwrap())
            .unwrap();
    let entry = &catalog["secrets"]["github_readonly_token"];
    assert_eq!(entry["item_id"], "item-1");
    assert_eq!(entry["allowed_clients"], json!(["remote-agent"]));
    assert_eq!(
        entry["return_fields"],
        json!(["username", "password", "uris", "custom.scope"])
    );
    assert_eq!(entry["metadata"]["organization_id"], "org-1");
    assert_eq!(entry["metadata"]["collection_ids"], json!(["collection-1"]));
    let calls = fs::read_to_string(fixture.call_log()).unwrap();
    assert!(calls.contains("--nointeraction --session session-123 list items --collectionid collection-1 --organizationid org-1|"));
}

#[tokio::test]
async fn build_catalog_skips_server_config_when_profile_is_already_logged_in() {
    let fixture = Fixture::new();
    let mut config = fixture.config(27443, true);
    config.bitwarden.server_url = "https://vaultwarden.example.com".to_string();
    config.bitwarden.bw_path = fixture
        .home()
        .join("logged-in-server-bw")
        .to_string_lossy()
        .to_string();
    write_executable(
        &fixture.home().join("logged-in-server-bw"),
        &fake_logged_in_server_bw_script(fixture.call_log()),
    );
    save_config(fixture.home(), &config).unwrap();

    run_from([
        "bw-broker",
        "--home",
        fixture.home().to_str().unwrap(),
        "build-catalog",
        "--sync",
    ])
    .await
    .unwrap();

    let calls = fs::read_to_string(fixture.call_log()).unwrap();
    assert!(!calls.contains("config server"));
    assert!(calls.contains(
        "--nointeraction --raw unlock --passwordenv BW_BROKER_MASTER_PASSWORD|agent-master"
    ));
    assert!(calls.contains("--nointeraction --session session-123 sync|"));
    assert!(calls.contains("--nointeraction --session session-123 list items|"));
}

#[tokio::test]
async fn login_command_passes_two_factor_options() {
    let fixture = Fixture::new();
    let mut config = fixture.config(27443, true);
    config.bitwarden.bw_path = fixture
        .home()
        .join("two-factor-bw")
        .to_string_lossy()
        .to_string();
    write_executable(
        &fixture.home().join("two-factor-bw"),
        &fake_two_factor_login_bw_script(fixture.call_log()),
    );
    save_config(fixture.home(), &config).unwrap();

    run_from([
        "bw-broker",
        "--home",
        fixture.home().to_str().unwrap(),
        "login",
        "--method",
        "0",
        "--code",
        "123456",
    ])
    .await
    .unwrap();

    let calls = fs::read_to_string(fixture.call_log()).unwrap();
    assert!(calls.contains("--nointeraction status|"));
    assert!(calls.contains("--nointeraction --raw login ai-agent@example.com --passwordenv BW_BROKER_MASTER_PASSWORD --method 0 --code 123456|agent-master"));
    assert!(calls.contains("--nointeraction --session session-2fa lock|"));
}

#[tokio::test]
async fn login_command_requires_method_and_code_pair() {
    let fixture = Fixture::new();
    let config = fixture.config(27443, true);
    save_config(fixture.home(), &config).unwrap();

    let err = run_from([
        "bw-broker",
        "--home",
        fixture.home().to_str().unwrap(),
        "login",
        "--method",
        "0",
    ])
    .await
    .unwrap_err()
    .to_string();

    assert!(err.contains("--method requires --code"));
    assert!(!fixture.call_log().exists());
}

#[tokio::test]
async fn add_client_command_generates_secret_and_trust_policy() {
    let fixture = Fixture::new();
    let config = fixture.config(27443, true);
    save_config(fixture.home(), &config).unwrap();

    run_from([
        "bw-broker",
        "--home",
        fixture.home().to_str().unwrap(),
        "add-client",
        "--client-id",
        "ci-agent",
        "--allowed-secret",
        "github_token",
        "--trusted",
    ])
    .await
    .unwrap();

    let updated: Config =
        serde_json::from_str(&fs::read_to_string(fixture.home().join("config.json")).unwrap())
            .unwrap();
    let client = updated
        .signing
        .clients
        .iter()
        .find(|client| client.id == "ci-agent")
        .unwrap();
    assert_eq!(client.approval, ClientApprovalMode::Trusted);
    assert_eq!(client.allowed_secrets, vec!["github_token".to_string()]);
    assert!(client.secret.len() >= 32);
}

struct Fixture {
    temp: TempDir,
    fake_bw: PathBuf,
    fake_keychain: PathBuf,
    call_log: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = TempDir::new().unwrap();
        let fake_bw = temp.path().join("fake-bw");
        let fake_keychain = temp.path().join("fake-keychain");
        let call_log = temp.path().join("bw-calls.log");
        write_executable(&fake_bw, &fake_bw_script(&call_log));
        write_executable(&fake_keychain, fake_keychain_script());
        Self {
            temp,
            fake_bw,
            fake_keychain,
            call_log,
        }
    }

    fn home(&self) -> &Path {
        self.temp.path()
    }

    fn call_log(&self) -> &Path {
        &self.call_log
    }

    fn config(&self, port: u16, catalog_mode: bool) -> Config {
        let cert = self.home().join("server.crt");
        let key = self.home().join("server.key");
        ensure_self_signed_cert(&cert, &key).unwrap();
        Config {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port,
                public_url: format!("https://127.0.0.1:{port}"),
                tls_cert: cert.to_string_lossy().to_string(),
                tls_key: key.to_string_lossy().to_string(),
                max_body_bytes: 65_536,
            },
            bitwarden: BitwardenConfig {
                bw_path: self.fake_bw.to_string_lossy().to_string(),
                server_url: "".to_string(),
                email: "ai-agent@example.com".to_string(),
                appdata_dir: self.home().join("bw-cli").to_string_lossy().to_string(),
                sync_before_read: false,
            },
            keychain: KeychainConfig {
                service: "test".to_string(),
                account: "ai-agent@example.com".to_string(),
                helper_path: self.fake_keychain.to_string_lossy().to_string(),
            },
            approval: ApprovalConfig {
                confirm_dialog: false,
                dialog_timeout_seconds: 1,
            },
            audit: AuditConfig {
                enabled: !catalog_mode,
                path: self.home().join("audit.log").to_string_lossy().to_string(),
            },
            signing: SigningConfig {
                max_skew_seconds: 300,
                nonce_ttl_seconds: 600,
                clients: vec![ClientConfig {
                    id: "remote-agent".to_string(),
                    secret: "client-secret".to_string(),
                    approval: ClientApprovalMode::Prompt,
                    allowed_secrets: vec!["*".to_string()],
                }],
            },
        }
    }
}

fn write_executable(path: &Path, content: &str) {
    fs::write(path, content).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn fake_bw_script(call_log: &Path) -> String {
    format!(
        r#"#!/bin/sh
printf '%s|%s
' "$*" "$BW_BROKER_MASTER_PASSWORD" >> {call_log}
case "$*" in
  "--nointeraction status")
    printf '%s\n' '{{"status":"locked"}}'
    ;;
  "--nointeraction --raw unlock --passwordenv BW_BROKER_MASTER_PASSWORD")
    if [ "$BW_BROKER_MASTER_PASSWORD" != "agent-master" ]; then
      echo "bad master" >&2
      exit 2
    fi
    printf '%s\n' 'session-123'
    ;;
  "--nointeraction --session session-123 get item item-1")
    printf '%s\n' '{{"id":"item-1","name":"GitHub Token","type":1,"login":{{"username":"bot","password":"token-value","uris":[{{"uri":"https://github.com"}}]}}}}'
    ;;
  "--nointeraction --session session-123 list items --collectionid collection-1 --organizationid org-1")
    printf '%s\n' '[{{"id":"item-1","name":"GitHub Readonly Token","type":1,"organizationId":"org-1","collectionIds":["collection-1"],"login":{{"username":"bot","password":"token-value","uris":[{{"uri":"https://github.com"}}]}},"fields":[{{"name":"scope","value":"read"}}]}}]'
    ;;
  "--nointeraction --session session-123 lock")
    exit 0
    ;;
  *)
    echo "unexpected args: $*" >&2
    exit 2
    ;;
esac
"#,
        call_log = shell_quote(call_log)
    )
}

fn fake_two_factor_login_bw_script(call_log: &Path) -> String {
    format!(
        r#"#!/bin/sh
printf '%s|%s
' "$*" "$BW_BROKER_MASTER_PASSWORD" >> {call_log}
case "$*" in
  "--nointeraction status")
    printf '%s\n' '{{"status":"unauthenticated"}}'
    ;;
  "--nointeraction --raw login ai-agent@example.com --passwordenv BW_BROKER_MASTER_PASSWORD --method 0 --code 123456")
    if [ "$BW_BROKER_MASTER_PASSWORD" != "agent-master" ]; then
      echo "bad master" >&2
      exit 2
    fi
    printf '%s\n' 'session-2fa'
    ;;
  "--nointeraction --session session-2fa lock")
    exit 0
    ;;
  *)
    echo "unexpected args: $*" >&2
    exit 2
    ;;
esac
"#,
        call_log = shell_quote(call_log)
    )
}

fn fake_logged_in_server_bw_script(call_log: &Path) -> String {
    format!(
        r#"#!/bin/sh
printf '%s|%s
' "$*" "$BW_BROKER_MASTER_PASSWORD" >> {call_log}
case "$*" in
  "--nointeraction status")
    printf '%s\n' '{{"serverUrl":"https://vaultwarden.example.com","status":"locked"}}'
    ;;
  "--nointeraction --raw unlock --passwordenv BW_BROKER_MASTER_PASSWORD")
    if [ "$BW_BROKER_MASTER_PASSWORD" != "agent-master" ]; then
      echo "bad master" >&2
      exit 2
    fi
    printf '%s\n' 'session-123'
    ;;
  "--nointeraction --session session-123 sync")
    exit 0
    ;;
  "--nointeraction --session session-123 list items")
    printf '%s\n' '[{{"id":"item-1","name":"GitHub Readonly Token","type":1,"login":{{"username":"bot","password":"token-value"}}}}]'
    ;;
  "--nointeraction --session session-123 lock")
    exit 0
    ;;
  *)
    echo "unexpected args: $*" >&2
    exit 2
    ;;
esac
"#,
        call_log = shell_quote(call_log)
    )
}

#[tokio::test]
async fn bw_failure_reports_redacted_command() {
    let fixture = Fixture::new();
    let mut config = fixture.config(27443, true);
    config.bitwarden.bw_path = fixture
        .home()
        .join("failing-bw")
        .to_string_lossy()
        .to_string();
    write_executable(
        &fixture.home().join("failing-bw"),
        r#"#!/bin/sh
if [ "$*" = "--nointeraction status" ]; then
  printf '%s\n' '{"status":"unauthenticated"}'
  exit 0
fi
printf '%s\n' '{"response":null,"statusCode":422}' >&2
exit 1
"#,
    );
    save_config(fixture.home(), &config).unwrap();

    let err = run_from([
        "bw-broker",
        "--home",
        fixture.home().to_str().unwrap(),
        "build-catalog",
        "--allowed-client",
        "remote-agent",
        "--login-method",
        "0",
        "--login-code",
        "123456",
    ])
    .await
    .unwrap_err()
    .to_string();

    assert!(err.contains("bw command failed: `"));
    assert!(
        err.contains("--raw login ai-agent@example.com --passwordenv BW_BROKER_MASTER_PASSWORD")
    );
    assert!(err.contains("--method 0 --code <redacted>"));
    assert!(err.contains("statusCode\":422"));
    assert!(!err.contains("agent-master"));
    assert!(!err.contains("123456"));
}

fn fake_keychain_script() -> &'static str {
    r#"#!/bin/sh
case "$1" in
  exists)
    echo yes
    ;;
  read)
    printf '%s' 'agent-master'
    ;;
  store|delete)
    exit 0
    ;;
  *)
    exit 2
    ;;
esac
"#
}

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn wait_for_health(client: &reqwest::Client, port: u16) {
    for _ in 0..50 {
        if let Ok(response) = client
            .get(format!("https://127.0.0.1:{port}/health"))
            .send()
            .await
        {
            if response.status() == StatusCode::OK {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("server did not become healthy");
}
