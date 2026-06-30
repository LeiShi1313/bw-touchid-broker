use anyhow::{anyhow, Context, Result};
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::config::{expand_path, Config};

#[derive(Debug)]
pub struct BitwardenCli {
    config: Config,
    appdata_dir: PathBuf,
}

#[derive(Debug, Default)]
pub struct LoginOptions {
    pub two_factor_method: Option<String>,
    pub two_factor_code: Option<String>,
}

impl LoginOptions {
    pub fn validate(&self) -> Result<()> {
        self.validate_with_names("two-step login method", "two-step login code")
    }

    pub fn validate_with_names(&self, method_arg: &str, code_arg: &str) -> Result<()> {
        match (&self.two_factor_method, &self.two_factor_code) {
            (Some(_), Some(_)) | (None, None) => Ok(()),
            (Some(_), None) => Err(anyhow!("{method_arg} requires {code_arg}")),
            (None, Some(_)) => Err(anyhow!("{code_arg} requires {method_arg}")),
        }
    }
}

impl BitwardenCli {
    pub fn new(config: &Config, home: &Path) -> Result<Self> {
        let appdata_dir = expand_path(&config.bitwarden.appdata_dir, home);
        fs::create_dir_all(&appdata_dir)?;
        Ok(Self {
            config: config.clone(),
            appdata_dir,
        })
    }

    fn run(
        &self,
        args: &[String],
        session: Option<&str>,
        envs: Option<&HashMap<String, String>>,
        raw: bool,
    ) -> Result<std::process::Output> {
        let mut cmd = Command::new(&self.config.bitwarden.bw_path);
        cmd.arg("--nointeraction");
        if raw {
            cmd.arg("--raw");
        }
        if let Some(session) = session {
            cmd.arg("--session").arg(session);
        }
        cmd.args(args)
            .env("BITWARDENCLI_APPDATA_DIR", &self.appdata_dir)
            .env("BW_NOINTERACTION", "true");
        if let Some(envs) = envs {
            for (key, value) in envs {
                cmd.env(key, value);
            }
        }
        cmd.output()
            .with_context(|| format!("failed to run {}", self.config.bitwarden.bw_path))
    }

    fn display_command(&self, args: &[String], session: Option<&str>, raw: bool) -> String {
        let mut parts = vec![
            self.config.bitwarden.bw_path.clone(),
            "--nointeraction".to_string(),
        ];
        if raw {
            parts.push("--raw".to_string());
        }
        if session.is_some() {
            parts.push("--session".to_string());
            parts.push("<redacted>".to_string());
        }
        parts.extend(redacted_display_args(args));
        parts.join(" ")
    }

    fn checked(
        &self,
        args: &[String],
        session: Option<&str>,
        envs: Option<&HashMap<String, String>>,
        raw: bool,
    ) -> Result<std::process::Output> {
        let output = self.run(args, session, envs, raw)?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(if output.stderr.is_empty() {
                &output.stdout
            } else {
                &output.stderr
            });
            return Err(anyhow!(
                "bw command failed: `{}` exited with {}; output: {}",
                self.display_command(args, session, raw),
                output.status,
                stderr.trim()
            ));
        }
        Ok(output)
    }

    pub fn configure_server(&self) -> Result<()> {
        if !self.config.bitwarden.server_url.is_empty() {
            self.checked(
                &[
                    "config".into(),
                    "server".into(),
                    self.config.bitwarden.server_url.clone(),
                ],
                None,
                None,
                false,
            )?;
        }
        Ok(())
    }

    fn ensure_server_for_status(&self, status: &Value) -> Result<()> {
        let expected = self.config.bitwarden.server_url.as_str();
        if expected.is_empty() {
            return Ok(());
        }

        let current = status
            .get("serverUrl")
            .and_then(Value::as_str)
            .unwrap_or("");
        if current == expected {
            return Ok(());
        }

        let auth_status = status.get("status").and_then(Value::as_str).unwrap_or("");
        if auth_status == "unauthenticated" {
            return self.configure_server();
        }

        Err(anyhow!(
            "bw profile is logged in to server `{current}`, but broker config requires `{expected}`; log out of the isolated broker profile before changing server URL"
        ))
    }

    pub fn status(&self) -> Result<Value> {
        let output = self.checked(&["status".into()], None, None, false)?;
        Ok(serde_json::from_slice(&output.stdout)?)
    }

    pub fn unlock_or_login(&self, master_password: &str) -> Result<String> {
        self.unlock_or_login_with_options(master_password, &LoginOptions::default())
    }

    pub fn unlock_or_login_with_options(
        &self,
        master_password: &str,
        login_options: &LoginOptions,
    ) -> Result<String> {
        login_options.validate()?;
        let mut envs = HashMap::new();
        envs.insert(
            "BW_BROKER_MASTER_PASSWORD".to_string(),
            master_password.to_string(),
        );
        let mut status = self.status()?;
        self.ensure_server_for_status(&status)?;
        status = self.status()?;
        let status = status.get("status").and_then(Value::as_str).unwrap_or("");
        let output = if status == "unauthenticated" {
            if self.config.bitwarden.email.is_empty() {
                return Err(anyhow!(
                    "bw is unauthenticated and bitwarden.email is not configured"
                ));
            }
            let mut args = vec![
                "login".to_string(),
                self.config.bitwarden.email.clone(),
                "--passwordenv".to_string(),
                "BW_BROKER_MASTER_PASSWORD".to_string(),
            ];
            if let (Some(method), Some(code)) = (
                &login_options.two_factor_method,
                &login_options.two_factor_code,
            ) {
                args.push("--method".to_string());
                args.push(method.clone());
                args.push("--code".to_string());
                args.push(code.clone());
            }
            self.checked(&args, None, Some(&envs), true)?
        } else {
            self.checked(
                &[
                    "unlock".into(),
                    "--passwordenv".into(),
                    "BW_BROKER_MASTER_PASSWORD".into(),
                ],
                None,
                Some(&envs),
                true,
            )?
        };
        let session = String::from_utf8(output.stdout)?.trim().to_string();
        if session.is_empty() {
            return Err(anyhow!("bw did not return a session key"));
        }
        Ok(session)
    }

    pub fn lock(&self, session: Option<&str>) {
        if let Some(session) = session {
            let _ = self.run(&["lock".into()], Some(session), None, false);
        }
    }

    pub fn sync(&self, session: &str) -> Result<()> {
        self.checked(&["sync".into()], Some(session), None, false)?;
        Ok(())
    }

    pub fn get_item(&self, item_id: &str, session: &str) -> Result<Value> {
        let output = self.checked(
            &["get".into(), "item".into(), item_id.into()],
            Some(session),
            None,
            false,
        )?;
        Ok(serde_json::from_slice(&output.stdout)?)
    }

    pub fn list_items(
        &self,
        session: &str,
        collection_id: Option<&str>,
        organization_id: Option<&str>,
    ) -> Result<Vec<Value>> {
        let mut args = vec!["list".to_string(), "items".to_string()];
        if let Some(collection_id) = collection_id {
            args.push("--collectionid".to_string());
            args.push(collection_id.to_string());
        }
        if let Some(organization_id) = organization_id {
            args.push("--organizationid".to_string());
            args.push(organization_id.to_string());
        }
        let output = self.checked(&args, Some(session), None, false)?;
        Ok(serde_json::from_slice(&output.stdout)?)
    }
}

fn redacted_display_args(args: &[String]) -> Vec<String> {
    let mut redacted = Vec::with_capacity(args.len());
    let mut redact_next = false;
    for arg in args {
        if redact_next {
            redacted.push("<redacted>".to_string());
            redact_next = false;
            continue;
        }
        redacted.push(arg.clone());
        if arg == "--code" {
            redact_next = true;
        }
    }
    redacted
}
