use anyhow::{anyhow, Context, Result};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::config::{expand_path, project_root, Config};

pub fn helper_path(config: &Config, home: &Path) -> PathBuf {
    expand_path(&config.keychain.helper_path, home)
}

pub fn build_helper(config: &Config, home: &Path) -> Result<PathBuf> {
    let target = helper_path(config, home);
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    let source = project_root().join("keychain").join("TouchIDSecret.swift");
    let output = Command::new("swiftc")
        .arg(&source)
        .arg("-o")
        .arg(&target)
        .output()
        .with_context(|| format!("failed to run swiftc for {}", source.display()))?;
    if !output.status.success() {
        return Err(anyhow!(
            "failed to build keychain helper: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700))?;
    Ok(target)
}

fn helper_command(config: &Config, home: &Path, command: &str) -> Command {
    let mut cmd = Command::new(helper_path(config, home));
    cmd.arg(command)
        .arg("--service")
        .arg(&config.keychain.service)
        .arg("--account")
        .arg(&config.keychain.account);
    cmd
}

pub fn store_master_password(config: &Config, home: &Path, password: &str) -> Result<()> {
    let mut child = helper_command(config, home, "store")
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to launch keychain helper")?;
    child
        .stdin
        .as_mut()
        .context("keychain helper stdin unavailable")?
        .write_all(password.as_bytes())?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(anyhow!(
            "{}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

pub fn read_master_password(config: &Config, home: &Path, reason: &str) -> Result<String> {
    let output = helper_command(config, home, "read")
        .arg("--reason")
        .arg(reason)
        .output()
        .context("failed to launch keychain helper")?;
    if !output.status.success() {
        return Err(anyhow!(
            "{}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8(output.stdout)?)
}

pub fn has_master_password(config: &Config, home: &Path) -> bool {
    helper_command(config, home, "exists")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

pub fn delete_master_password(config: &Config, home: &Path) -> Result<()> {
    let output = helper_command(config, home, "delete").output()?;
    if !output.status.success() {
        return Err(anyhow!(
            "{}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

pub fn self_test(config: &Config, home: &Path) -> Result<()> {
    let helper = build_helper(config, home)?;
    let service = "bw-touchid-broker.self-test";
    let account = format!("self-test-{}", random_token(8));
    let value = format!("dummy-{}", random_token(16));
    let store = run_helper_with_stdin(&helper, "store", service, &account, None, value.as_bytes())?;
    if !store.status.success() {
        return Err(anyhow!("{}", String::from_utf8_lossy(&store.stderr).trim()));
    }
    let read = run_helper(
        &helper,
        "read",
        service,
        &account,
        Some("BW broker Keychain self-test"),
    )?;
    let delete_result = run_helper(&helper, "delete", service, &account, None);
    if !read.status.success() {
        let _ = delete_result;
        return Err(anyhow!("{}", String::from_utf8_lossy(&read.stderr).trim()));
    }
    if String::from_utf8(read.stdout)? != value {
        let _ = delete_result;
        return Err(anyhow!("self-test read returned unexpected value"));
    }
    delete_result?;
    Ok(())
}

fn run_helper(
    helper: &Path,
    command: &str,
    service: &str,
    account: &str,
    reason: Option<&str>,
) -> Result<std::process::Output> {
    let mut cmd = Command::new(helper);
    cmd.arg(command)
        .arg("--service")
        .arg(service)
        .arg("--account")
        .arg(account);
    if let Some(reason) = reason {
        cmd.arg("--reason").arg(reason);
    }
    Ok(cmd.output()?)
}

fn run_helper_with_stdin(
    helper: &Path,
    command: &str,
    service: &str,
    account: &str,
    reason: Option<&str>,
    stdin: &[u8],
) -> Result<std::process::Output> {
    let mut cmd = Command::new(helper);
    cmd.arg(command)
        .arg("--service")
        .arg(service)
        .arg("--account")
        .arg(account)
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .stdout(Stdio::piped());
    if let Some(reason) = reason {
        cmd.arg("--reason").arg(reason);
    }
    let mut child = cmd.spawn()?;
    child
        .stdin
        .as_mut()
        .context("helper stdin unavailable")?
        .write_all(stdin)?;
    Ok(child.wait_with_output()?)
}

fn random_token(bytes: usize) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use rand::RngCore;
    let mut raw = vec![0_u8; bytes];
    rand::thread_rng().fill_bytes(&mut raw);
    URL_SAFE_NO_PAD.encode(raw)
}
