#!/usr/bin/env python3
import hashlib
import hmac
import json
import os
import secrets
import ssl
import sys
import time
import urllib.request


def sign(secret, method, target, timestamp, nonce, body):
    digest = hashlib.sha256(body).hexdigest()
    canonical = "\n".join([method.upper(), target, timestamp, nonce, digest])
    return hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()


def request(method, path, body=b""):
    base_url = os.environ["BW_BROKER_URL"].rstrip("/")
    client_id = os.environ["BW_BROKER_CLIENT_ID"]
    client_secret = os.environ["BW_BROKER_CLIENT_SECRET"]
    timestamp = str(int(time.time()))
    nonce = secrets.token_urlsafe(18)
    headers = {
        "Content-Type": "application/json",
        "X-BW-Broker-Client-Id": client_id,
        "X-BW-Broker-Timestamp": timestamp,
        "X-BW-Broker-Nonce": nonce,
        "X-BW-Broker-Signature": sign(client_secret, method, path, timestamp, nonce, body),
    }
    req = urllib.request.Request(base_url + path, data=body if method != "GET" else None, method=method, headers=headers)
    # For local self-signed certs. Prefer a trusted cert or tunnel TLS for real remote use.
    context = ssl._create_unverified_context()
    with urllib.request.urlopen(req, context=context) as resp:
        return json.loads(resp.read().decode())


if __name__ == "__main__":
    if len(sys.argv) == 1:
        print(json.dumps(request("GET", "/v1/catalog"), indent=2))
    else:
        payload = {
            "secret_id": sys.argv[1],
            "purpose": sys.argv[2] if len(sys.argv) > 2 else "manual test request",
            "run_id": os.environ.get("RUN_ID", "manual"),
        }
        body = json.dumps(payload, separators=(",", ":")).encode()
        print(json.dumps(request("POST", "/v1/secret-requests", body), indent=2))
