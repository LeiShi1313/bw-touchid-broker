use anyhow::{anyhow, Result};
use hmac::{Hmac, Mac};
use http::HeaderMap;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

pub const HEADER_CLIENT: &str = "x-bw-broker-client-id";
pub const HEADER_TIMESTAMP: &str = "x-bw-broker-timestamp";
pub const HEADER_NONCE: &str = "x-bw-broker-nonce";
pub const HEADER_SIGNATURE: &str = "x-bw-broker-signature";

pub fn body_digest(body: &[u8]) -> String {
    hex::encode(Sha256::digest(body))
}

pub fn canonical_request(
    method: &str,
    target: &str,
    timestamp: &str,
    nonce: &str,
    body: &[u8],
) -> String {
    format!(
        "{}\n{}\n{}\n{}\n{}",
        method.to_ascii_uppercase(),
        target,
        timestamp,
        nonce,
        body_digest(body)
    )
}

pub fn sign(
    secret: &str,
    method: &str,
    target: &str,
    timestamp: &str,
    nonce: &str,
    body: &[u8],
) -> Result<String> {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).map_err(|_| anyhow!("invalid hmac key"))?;
    mac.update(canonical_request(method, target, timestamp, nonce, body).as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

pub fn verify_signature(
    secret: &str,
    method: &str,
    target: &str,
    headers: &HeaderMap,
    body: &[u8],
    max_skew_seconds: i64,
) -> Result<(String, String)> {
    let timestamp = header_str(headers, HEADER_TIMESTAMP)?;
    let nonce = header_str(headers, HEADER_NONCE)?;
    let provided = header_str(headers, HEADER_SIGNATURE)?;
    let ts = timestamp
        .parse::<i64>()
        .map_err(|_| anyhow!("invalid signature timestamp"))?;
    if (now_unix() - ts).abs() > max_skew_seconds {
        return Err(anyhow!("signature timestamp outside allowed skew"));
    }
    let expected = sign(secret, method, target, timestamp, nonce, body)?;
    if !constant_time_eq(expected.as_bytes(), provided.as_bytes()) {
        return Err(anyhow!("invalid request signature"));
    }
    Ok((timestamp.to_string(), nonce.to_string()))
}

pub fn signed_headers_json(
    client_id: &str,
    client_secret: &str,
    method: &str,
    target: &str,
    body: &[u8],
    nonce: &str,
) -> Result<serde_json::Value> {
    let timestamp = now_unix().to_string();
    Ok(json!({
        "X-BW-Broker-Client-Id": client_id,
        "X-BW-Broker-Timestamp": timestamp,
        "X-BW-Broker-Nonce": nonce,
        "X-BW-Broker-Signature": sign(client_secret, method, target, &timestamp, nonce, body)?,
    }))
}

pub fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str> {
    headers
        .get(name)
        .ok_or_else(|| anyhow!("missing header {name}"))?
        .to_str()
        .map_err(|_| anyhow!("invalid header {name}"))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (left, right) in a.iter().zip(b.iter()) {
        diff |= left ^ right;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_round_trips() {
        let body = br#"{"x":1}"#;
        let timestamp = now_unix().to_string();
        let nonce = "nonce-1";
        let signature = sign(
            "shared-secret",
            "POST",
            "/v1/secret-requests",
            &timestamp,
            nonce,
            body,
        )
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(HEADER_TIMESTAMP, timestamp.parse().unwrap());
        headers.insert(HEADER_NONCE, nonce.parse().unwrap());
        headers.insert(HEADER_SIGNATURE, signature.parse().unwrap());
        verify_signature(
            "shared-secret",
            "POST",
            "/v1/secret-requests",
            &headers,
            body,
            300,
        )
        .unwrap();
    }
}
