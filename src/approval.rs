use anyhow::{anyhow, Result};
use std::process::Command;

use crate::config::Config;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalDecision {
    AllowOnce,
    TrustClient,
}

pub fn confirm_request(
    config: &Config,
    client_id: &str,
    secret_id: &str,
    purpose: &str,
    run_id: &str,
) -> Result<ApprovalDecision> {
    if !config.approval.confirm_dialog {
        return Ok(ApprovalDecision::AllowOnce);
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
        "Allow Once approves this request only.",
        "Trust Client approves this request and skips future approval prompts for this client.",
    ]
    .join("\n");
    let script = format!(
        "display dialog {} buttons {{\"Deny\", \"Allow Once\", \"Trust Client\"}} default button \"Deny\" cancel button \"Deny\" with title \"BW Broker Approval\" giving up after {}",
        applescript_string(&message),
        config.approval.dialog_timeout_seconds
    );
    let output = Command::new("osascript").arg("-e").arg(script).output()?;
    if output.status.success() {
        return parse_approval_output(&String::from_utf8_lossy(&output.stdout));
    }
    Err(anyhow!("secret request was not approved"))
}

fn applescript_string(value: &str) -> String {
    let escaped = value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n");
    format!("\"{escaped}\"")
}

fn parse_approval_output(output: &str) -> Result<ApprovalDecision> {
    if output.contains("button returned:Trust Client") {
        Ok(ApprovalDecision::TrustClient)
    } else if output.contains("button returned:Allow Once") {
        Ok(ApprovalDecision::AllowOnce)
    } else {
        Err(anyhow!("secret request was not approved"))
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_approval_output, ApprovalDecision};

    #[test]
    fn parses_allow_once_decision() {
        assert_eq!(
            parse_approval_output("button returned:Allow Once").unwrap(),
            ApprovalDecision::AllowOnce
        );
    }

    #[test]
    fn parses_trust_client_decision() {
        assert_eq!(
            parse_approval_output("button returned:Trust Client").unwrap(),
            ApprovalDecision::TrustClient
        );
    }
}
