use anyhow::{anyhow, Context, Result};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Map, Value};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Once;

use crate::approval::confirm_request;
use crate::audit::write_audit;
use crate::bw::BitwardenCli;
use crate::catalog::{extract_fields, load_catalog, require_secret, visible_catalog};
use crate::config::{expand_path, find_client, load_config, nonce_path, Config};
use crate::keychain::read_master_password;
use crate::nonce::NonceStore;
use crate::signing::{header_str, verify_signature, HEADER_CLIENT};

static RUSTLS_PROVIDER: Once = Once::new();

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub home: Arc<PathBuf>,
    pub nonces: Arc<NonceStore>,
}

#[derive(Debug)]
pub struct HttpError {
    status: StatusCode,
    message: String,
}

impl HttpError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.message }))).into_response()
    }
}

impl From<anyhow::Error> for HttpError {
    fn from(value: anyhow::Error) -> Self {
        Self::new(StatusCode::BAD_REQUEST, value.to_string())
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/catalog", get(catalog))
        .route("/v1/secret-requests", post(secret_request))
        .with_state(state)
}

async fn health() -> Json<Value> {
    Json(json!({ "ok": true }))
}

async fn catalog(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Json<Value>, HttpError> {
    let (client, _) = verify_request(&state, "GET", &target(&uri), &headers, &[])?;
    let catalog = load_catalog(&state.home)?;
    Ok(Json(visible_catalog(&catalog, &client)))
}

async fn secret_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    body: Bytes,
) -> Result<Json<Value>, HttpError> {
    if body.len() > state.config.server.max_body_bytes {
        return Err(HttpError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "request body too large",
        ));
    }
    let (client, client_id) = verify_request(&state, "POST", &target(&uri), &headers, &body)?;
    let payload: Value = serde_json::from_slice(&body)
        .map_err(|_| HttpError::new(StatusCode::BAD_REQUEST, "invalid JSON request body"))?;
    let secret_id = payload
        .get("secret_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let purpose = payload.get("purpose").and_then(Value::as_str).unwrap_or("");
    let run_id = payload.get("run_id").and_then(Value::as_str).unwrap_or("");
    if secret_id.is_empty() {
        return Err(HttpError::new(StatusCode::BAD_REQUEST, "missing secret_id"));
    }
    if purpose.is_empty() {
        return Err(HttpError::new(StatusCode::BAD_REQUEST, "missing purpose"));
    }

    let catalog = load_catalog(&state.home)?;
    let entry = require_secret(&catalog, &client, secret_id)
        .map_err(|err| HttpError::new(StatusCode::FORBIDDEN, err.to_string()))?
        .clone();
    let allowed_fields = entry.return_fields.clone();
    let requested_fields = match payload.get("fields").and_then(Value::as_array) {
        Some(fields) => {
            let mut out = Vec::new();
            for field in fields {
                let field = field.as_str().ok_or_else(|| {
                    HttpError::new(StatusCode::BAD_REQUEST, "fields must be strings")
                })?;
                if !allowed_fields.iter().any(|allowed| allowed == field) {
                    return Err(HttpError::new(
                        StatusCode::FORBIDDEN,
                        format!("field is not allowed for this secret: {field}"),
                    ));
                }
                out.push(field.to_string());
            }
            out
        }
        None => allowed_fields,
    };

    if entry.approval_required {
        if let Err(err) = confirm_request(&state.config, &client_id, secret_id, purpose, run_id) {
            let _ = audit_event(
                &state,
                "secret_denied",
                &client_id,
                secret_id,
                purpose,
                run_id,
                None,
            );
            return Err(HttpError::new(StatusCode::FORBIDDEN, err.to_string()));
        }
    }

    let config = state.config.clone();
    let home = state.home.clone();
    let secret_id_owned = secret_id.to_string();
    let client_id_owned = client_id.clone();
    let requested_fields_owned = requested_fields.clone();
    let item_id = entry.item_id.clone();
    let fields = tokio::task::spawn_blocking(move || -> Result<Map<String, Value>> {
        let reason = format!(
            "Unlock Vaultwarden agent account for {client_id_owned} to read {secret_id_owned}"
        );
        let master_password = read_master_password(&config, &home, &reason)?;
        let bw = BitwardenCli::new(&config, &home)?;
        let mut session = None;
        let result = (|| -> Result<Map<String, Value>> {
            let session_key = bw.unlock_or_login(&master_password)?;
            session = Some(session_key.clone());
            if config.bitwarden.sync_before_read {
                bw.sync(&session_key)?;
            }
            let item = bw.get_item(&item_id, &session_key)?;
            Ok(extract_fields(&item, &requested_fields_owned))
        })();
        bw.lock(session.as_deref());
        result
    })
    .await
    .map_err(|err| HttpError::new(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?
    .map_err(|err| HttpError::new(StatusCode::BAD_REQUEST, err.to_string()))?;

    let _ = audit_event(
        &state,
        "secret_released",
        &client_id,
        secret_id,
        purpose,
        run_id,
        Some(Value::Array(
            requested_fields.iter().map(|field| json!(field)).collect(),
        )),
    );
    Ok(Json(json!({
        "secret_id": secret_id,
        "fields": fields,
        "ttl_seconds": entry.ttl_seconds,
    })))
}

fn verify_request(
    state: &AppState,
    method: &str,
    target: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(crate::config::ClientConfig, String), HttpError> {
    let client_id = header_str(headers, HEADER_CLIENT)
        .map_err(|_| HttpError::new(StatusCode::UNAUTHORIZED, "missing client id"))?;
    let client = find_client(&state.config, client_id)
        .ok_or_else(|| HttpError::new(StatusCode::UNAUTHORIZED, "unknown client id"))?
        .clone();
    verify_signature(
        &client.secret,
        method,
        target,
        headers,
        body,
        state.config.signing.max_skew_seconds,
    )
    .map_err(|err| HttpError::new(StatusCode::UNAUTHORIZED, err.to_string()))?;
    let nonce = header_str(headers, crate::signing::HEADER_NONCE)
        .map_err(|_| HttpError::new(StatusCode::UNAUTHORIZED, "missing nonce"))?;
    state
        .nonces
        .check_and_store(client_id, nonce)
        .map_err(|err| HttpError::new(StatusCode::UNAUTHORIZED, err.to_string()))?;
    Ok((client, client_id.to_string()))
}

fn audit_event(
    state: &AppState,
    event: &str,
    client_id: &str,
    secret_id: &str,
    purpose: &str,
    run_id: &str,
    fields: Option<Value>,
) -> Result<()> {
    let mut map = Map::new();
    map.insert("client_id".to_string(), json!(client_id));
    map.insert("secret_id".to_string(), json!(secret_id));
    map.insert("purpose".to_string(), json!(purpose));
    map.insert("run_id".to_string(), json!(run_id));
    if let Some(fields) = fields {
        map.insert("fields".to_string(), fields);
    }
    write_audit(&state.config, &state.home, event, map)
}

fn target(uri: &Uri) -> String {
    uri.path_and_query()
        .map(|path_and_query| path_and_query.as_str().to_string())
        .unwrap_or_else(|| uri.path().to_string())
}

pub async fn serve(home: &Path) -> Result<()> {
    let config = load_config(home)?;
    serve_config(home.to_path_buf(), config).await
}

pub async fn serve_config(home: PathBuf, config: Config) -> Result<()> {
    RUSTLS_PROVIDER.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
    let cert_path = expand_path(&config.server.tls_cert, &home);
    let key_path = expand_path(&config.server.tls_key, &home);
    if !cert_path.exists() || !key_path.exists() {
        return Err(anyhow!(
            "missing TLS certificate/key; run `bw-broker bootstrap`"
        ));
    }
    let addr: SocketAddr = format!("{}:{}", config.server.host, config.server.port)
        .parse()
        .with_context(|| "invalid server host/port")?;
    let state = AppState {
        nonces: Arc::new(NonceStore::new(
            nonce_path(&home),
            config.signing.nonce_ttl_seconds,
        )),
        config: Arc::new(config),
        home: Arc::new(home),
    };
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_path, key_path).await?;
    println!("bw-touchid-broker listening on https://{addr}",);
    axum_server::bind_rustls(addr, tls)
        .serve(router(state).into_make_service())
        .await?;
    Ok(())
}
