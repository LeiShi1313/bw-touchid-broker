use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

use crate::config::write_private_json;
use crate::signing::now_unix;

#[derive(Debug)]
pub struct NonceStore {
    path: PathBuf,
    ttl_seconds: i64,
    lock: Mutex<()>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct NonceDb {
    nonces: HashMap<String, i64>,
}

impl NonceStore {
    pub fn new(path: PathBuf, ttl_seconds: i64) -> Self {
        Self {
            path,
            ttl_seconds,
            lock: Mutex::new(()),
        }
    }

    pub fn check_and_store(&self, client_id: &str, nonce: &str) -> Result<()> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| anyhow!("nonce lock poisoned"))?;
        let now = now_unix();
        let cutoff = now - self.ttl_seconds;
        let mut db = self.load()?;
        db.nonces.retain(|_, created_at| *created_at >= cutoff);
        let key = format!("{client_id}:{nonce}");
        if db.nonces.contains_key(&key) {
            return Err(anyhow!("replay detected for request nonce"));
        }
        db.nonces.insert(key, now);
        write_private_json(&self.path, &db)?;
        Ok(())
    }

    fn load(&self) -> Result<NonceDb> {
        if !self.path.exists() {
            return Ok(NonceDb::default());
        }
        let text = fs::read_to_string(&self.path)?;
        Ok(serde_json::from_str(&text)?)
    }
}
