use anyhow::{anyhow, Result};
use std::process::Command;

use crate::config::Config;

pub fn confirm_request(
    config: &Config,
    client_id: &str,
    secret_id: &str,
    purpose: &str,
    run_id: &str,
) -> Result<()> {
    if !config.approval.confirm_dialog {
        return Ok(());
    }
    let message = [
        "A remote agent is requesting a Vaultwarden secret.",
        "",
        &format!("Client: {client_id}"),
        &format!("Secret: {secret_id}"),
        &format!(
            "Purpose: {}",
            if purpose.is_empty() {
                "(not provided)"
            } else {
                purpose
            }
        ),
        &format!(
            "Run ID: {}",
            if run_id.is_empty() {
                "(not provided)"
            } else {
                run_id
            }
        ),
        "",
        "Approve only if this matches the task you expect.",
    ]
    .join("\n");
    let script = format!(
        "display dialog {} buttons {{\"Deny\", \"Allow\"}} default button \"Deny\" cancel button \"Deny\" with title \"BW Broker Approval\" giving up after {}",
        applescript_string(&message),
        config.approval.dialog_timeout_seconds
    );
    let output = Command::new("osascript").arg("-e").arg(script).output()?;
    if output.status.success()
        && String::from_utf8_lossy(&output.stdout).contains("button returned:Allow")
    {
        Ok(())
    } else {
        Err(anyhow!("secret request was not approved"))
    }
}

fn applescript_string(value: &str) -> String {
    let escaped = value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n");
    format!("\"{escaped}\"")
}
