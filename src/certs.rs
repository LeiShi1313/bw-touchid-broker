use anyhow::{anyhow, Context, Result};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

pub fn ensure_self_signed_cert(cert_path: &Path, key_path: &Path) -> Result<()> {
    if cert_path.exists() && key_path.exists() {
        return Ok(());
    }
    if let Some(parent) = cert_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = key_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let config = r#"
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
x509_extensions = v3_req

[dn]
CN = localhost

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
"#;
    let config_path = key_path.with_extension("openssl.cnf");
    fs::write(&config_path, config)?;
    let output = Command::new("openssl")
        .args([
            "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "825", "-keyout",
        ])
        .arg(key_path)
        .arg("-out")
        .arg(cert_path)
        .arg("-config")
        .arg(&config_path)
        .output()
        .context("failed to run openssl")?;
    let _ = fs::remove_file(&config_path);
    if !output.status.success() {
        return Err(anyhow!(
            "failed to create self-signed TLS certificate: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    fs::set_permissions(key_path, fs::Permissions::from_mode(0o600))?;
    fs::set_permissions(cert_path, fs::Permissions::from_mode(0o644))?;
    Ok(())
}
