use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::Path;

use crate::config::{catalog_path, write_private_json, ClientConfig};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Catalog {
    pub version: u8,
    pub secrets: BTreeMap<String, CatalogEntry>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CatalogEntry {
    pub item_id: String,
    pub kind: String,
    pub description: String,
    pub return_fields: Vec<String>,
    #[serde(default = "default_true")]
    pub approval_required: bool,
    #[serde(default = "default_ttl")]
    pub ttl_seconds: u64,
    #[serde(default)]
    pub allowed_clients: Vec<String>,
    #[serde(default)]
    pub metadata: Value,
}

fn default_true() -> bool {
    true
}

fn default_ttl() -> u64 {
    60
}

pub fn empty_catalog() -> Catalog {
    Catalog {
        version: 1,
        secrets: BTreeMap::new(),
    }
}

pub fn load_catalog(home: &Path) -> Result<Catalog> {
    let path = catalog_path(home);
    if !path.exists() {
        return Ok(empty_catalog());
    }
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

pub fn save_catalog(home: &Path, catalog: &Catalog) -> Result<()> {
    write_private_json(&catalog_path(home), catalog)
}

pub fn build_catalog(
    items: &[Value],
    allowed_clients: Vec<String>,
    redact_names: bool,
    default_ttl_seconds: u64,
) -> Catalog {
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut secrets = BTreeMap::new();
    for item in items {
        if !item.get("deletedDate").unwrap_or(&Value::Null).is_null() {
            continue;
        }
        let item_id = item.get("id").and_then(Value::as_str).unwrap_or("");
        if item_id.is_empty() {
            continue;
        }
        let name = item.get("name").and_then(Value::as_str).unwrap_or("secret");
        let mut alias = slugify(name);
        let count = counts.entry(alias.clone()).or_default();
        *count += 1;
        if *count > 1 {
            let suffix: String = item_id.chars().take(8).collect();
            alias = format!("{alias}_{suffix}");
        }
        let kind = type_name(item.get("type").and_then(Value::as_i64).unwrap_or(0)).to_string();
        let metadata = json!({
            "organization_id": item.get("organizationId").cloned().unwrap_or(Value::Null),
            "collection_ids": item.get("collectionIds").cloned().unwrap_or_else(|| json!([])),
            "login_urls": login_urls(item),
        });
        secrets.insert(
            alias,
            CatalogEntry {
                item_id: item_id.to_string(),
                kind: kind.clone(),
                description: if redact_names {
                    format!("{kind} item")
                } else {
                    name.to_string()
                },
                return_fields: infer_return_fields(item),
                approval_required: true,
                ttl_seconds: default_ttl_seconds,
                allowed_clients: allowed_clients.clone(),
                metadata,
            },
        );
    }
    Catalog {
        version: 1,
        secrets,
    }
}

pub fn visible_catalog(catalog: &Catalog, client: &ClientConfig) -> Value {
    let mut secrets = Vec::new();
    for (id, entry) in &catalog.secrets {
        if !client_allows_secret(client, id) || !entry_allows_client(entry, &client.id) {
            continue;
        }
        secrets.push(json!({
            "id": id,
            "kind": entry.kind,
            "description": entry.description,
            "login_urls": entry.metadata.get("login_urls").cloned().unwrap_or_else(|| json!([])),
            "return_fields": entry.return_fields,
            "approval_required": entry.approval_required && !client.approval.is_trusted(),
            "ttl_seconds": entry.ttl_seconds,
        }));
    }
    json!({ "version": catalog.version, "secrets": secrets })
}

pub fn require_secret<'a>(
    catalog: &'a Catalog,
    client: &ClientConfig,
    secret_id: &str,
) -> Result<&'a CatalogEntry> {
    let entry = catalog
        .secrets
        .get(secret_id)
        .ok_or_else(|| anyhow!("unknown secret id: {secret_id}"))?;
    if !client_allows_secret(client, secret_id) || !entry_allows_client(entry, &client.id) {
        return Err(anyhow!("client is not allowed to request this secret"));
    }
    Ok(entry)
}

pub fn extract_fields(item: &Value, requested_fields: &[String]) -> Map<String, Value> {
    let mut out = Map::new();
    let login = item.get("login").unwrap_or(&Value::Null);
    for field in requested_fields {
        let value = match field.as_str() {
            "name" => item.get("name").cloned().unwrap_or(Value::Null),
            "username" => login.get("username").cloned().unwrap_or(Value::Null),
            "password" => login.get("password").cloned().unwrap_or(Value::Null),
            "uris" => Value::Array(
                login
                    .get("uris")
                    .and_then(Value::as_array)
                    .unwrap_or(&Vec::new())
                    .iter()
                    .filter_map(|uri| uri.get("uri").cloned())
                    .collect(),
            ),
            "uri" => login
                .get("uris")
                .and_then(Value::as_array)
                .and_then(|uris| uris.iter().find_map(|uri| uri.get("uri").cloned()))
                .unwrap_or(Value::Null),
            "totp" => login.get("totp").cloned().unwrap_or(Value::Null),
            "notes" => item.get("notes").cloned().unwrap_or(Value::Null),
            _ if field.starts_with("custom.") => {
                custom_field_value(item, &field["custom.".len()..])
            }
            _ => Value::Null,
        };
        out.insert(field.clone(), value);
    }
    out
}

fn custom_field_value(item: &Value, name: &str) -> Value {
    item.get("fields")
        .and_then(Value::as_array)
        .and_then(|fields| {
            fields.iter().find_map(|field| {
                if field.get("name").and_then(Value::as_str) == Some(name) {
                    field.get("value").cloned()
                } else {
                    None
                }
            })
        })
        .unwrap_or(Value::Null)
}

fn login_urls(item: &Value) -> Vec<String> {
    item.get("login")
        .and_then(|login| login.get("uris"))
        .and_then(Value::as_array)
        .map(|uris| {
            uris.iter()
                .filter_map(|uri| uri.get("uri").and_then(Value::as_str))
                .filter(|uri| !uri.is_empty())
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn infer_return_fields(item: &Value) -> Vec<String> {
    let mut fields = Vec::new();
    let login = item.get("login").unwrap_or(&Value::Null);
    if !login.get("username").unwrap_or(&Value::Null).is_null() {
        fields.push("username".to_string());
    }
    if !login.get("password").unwrap_or(&Value::Null).is_null() {
        fields.push("password".to_string());
    }
    if login
        .get("uris")
        .and_then(Value::as_array)
        .map(|v| !v.is_empty())
        .unwrap_or(false)
    {
        fields.push("uris".to_string());
    }
    if !login.get("totp").unwrap_or(&Value::Null).is_null() {
        fields.push("totp".to_string());
    }
    if !item.get("notes").unwrap_or(&Value::Null).is_null() {
        fields.push("notes".to_string());
    }
    if let Some(custom_fields) = item.get("fields").and_then(Value::as_array) {
        for custom in custom_fields {
            if let Some(name) = custom.get("name").and_then(Value::as_str) {
                fields.push(format!("custom.{name}"));
            }
        }
    }
    if fields.is_empty() {
        fields.push("name".to_string());
    }
    fields
}

fn slugify(value: &str) -> String {
    let mut out = String::new();
    let mut last_was_sep = false;
    for ch in value.trim().chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            last_was_sep = false;
        } else if !last_was_sep {
            out.push('_');
            last_was_sep = true;
        }
    }
    let slug = out.trim_matches('_').to_string();
    if slug.is_empty() {
        "secret".to_string()
    } else {
        slug
    }
}

fn type_name(value: i64) -> &'static str {
    match value {
        1 => "login",
        2 => "secure_note",
        3 => "card",
        4 => "identity",
        _ => "item",
    }
}

fn client_allows_secret(client: &ClientConfig, secret_id: &str) -> bool {
    client
        .allowed_secrets
        .iter()
        .any(|item| item == "*" || item == secret_id)
}

fn entry_allows_client(entry: &CatalogEntry, client_id: &str) -> bool {
    entry.allowed_clients.is_empty()
        || entry
            .allowed_clients
            .iter()
            .any(|item| item == "*" || item == client_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ClientApprovalMode, ClientConfig};
    use serde_json::json;

    #[test]
    fn build_catalog_and_extract_login_fields() {
        let item = json!({
            "id": "item-1",
            "name": "GitHub Readonly Token",
            "type": 1,
            "login": {
                "username": "bot",
                "password": "secret",
                "uris": [{"uri": "https://github.com"}]
            },
            "fields": [{"name": "scope", "value": "read"}]
        });
        let catalog = build_catalog(
            std::slice::from_ref(&item),
            vec!["agent-a".to_string()],
            false,
            60,
        );
        let entry = catalog.secrets.get("github_readonly_token").unwrap();
        assert_eq!(
            entry.return_fields,
            vec!["username", "password", "uris", "custom.scope"]
        );
        assert_eq!(entry.metadata["login_urls"], json!(["https://github.com"]));
        let extracted = extract_fields(&item, &entry.return_fields);
        assert_eq!(extracted.get("username").unwrap(), "bot");
        assert_eq!(extracted.get("password").unwrap(), "secret");
        assert_eq!(
            extracted.get("uris").unwrap(),
            &json!(["https://github.com"])
        );
        assert_eq!(extracted.get("custom.scope").unwrap(), "read");

        let visible = visible_catalog(
            &catalog,
            &ClientConfig {
                id: "agent-a".to_string(),
                secret: "client-secret".to_string(),
                approval: ClientApprovalMode::Prompt,
                allowed_secrets: vec!["*".to_string()],
            },
        );
        assert_eq!(
            visible["secrets"][0]["login_urls"],
            json!(["https://github.com"])
        );
    }
}
