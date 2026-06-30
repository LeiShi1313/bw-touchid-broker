use anyhow::Result;
use serde_json::{json, Value};
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::config::{expand_path, Config};
use crate::signing::now_unix;

pub fn write_audit(
    config: &Config,
    home: &Path,
    event: &str,
    mut fields: serde_json::Map<String, Value>,
) -> Result<()> {
    if !config.audit.enabled {
        return Ok(());
    }
    let path = expand_path(&config.audit.path, home);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    fields.insert("ts".to_string(), json!(now_unix()));
    fields.insert("event".to_string(), json!(event));
    let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
    writeln!(file, "{}", Value::Object(fields))?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}
