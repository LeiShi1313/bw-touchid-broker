---
name: bw-broker-agent
description: Broker secret access for remote agents. Use when a task needs a credential available through BW_BROKER_URL, needs to inspect the broker catalog, or must sign and send bw-touchid-broker secret requests without asking for Vaultwarden passwords, Bitwarden API keys, or BW_SESSION.
---

# BW Broker Agent

The broker is a narrow, approval-gated secret API. Never ask the user for a Vaultwarden/Bitwarden master password, Bitwarden API key, or `BW_SESSION`.

## Broker Flow

1. Check broker config.

   Require `BW_BROKER_URL`, `BW_BROKER_CLIENT_ID`, and `BW_BROKER_CLIENT_SECRET` from the runtime or operator. Treat `BW_BROKER_CLIENT_SECRET` as sensitive: do not print it, commit it, store it in logs, or include it in task output.

   Completion criterion: all three broker values are available to the request code, and the client secret has not been displayed.

2. Catalog first.

   Send a signed `GET /v1/catalog` request before requesting any secret. Use only `secret_id` values and fields returned by the catalog. Use `login_urls` when present to choose the matching login item. Do not infer, guess, or invent secret names.

   Completion criterion: the chosen `secret_id` and requested fields are present in the catalog.

3. Request narrowly.

   Send a signed `POST /v1/secret-requests` request with a concrete `purpose`, stable `run_id`, and only the fields needed for the immediate action. Prefer scoped tokens over broad account passwords. Do not request both `password` and `totp` unless the current action specifically requires both and the catalog allows both.

   Completion criterion: the request body is human-verifiable in the local approval prompt, and every requested field is necessary for the next action.

4. Use and forget.

   Use returned values only for the current action. Respect `ttl_seconds`. Remove secrets from temporary files, environment variables, shell history, debug output, and logs when the action is done.

   Completion criterion: the action is complete or blocked, and no returned secret value remains in user-visible output or durable artifacts.

5. Stop on broker denial.

   If the broker returns `401`, `403`, timeout, approval failure, unknown secret, or field-denied errors, stop. Report that broker approval or policy blocked the request. Do not retry with guessed names, broader fields, or raw user-provided vault credentials.

   Completion criterion: the user sees the blocker without any secret value or client secret.

## Signing Reference

For every broker request, send these headers:

```text
X-BW-Broker-Client-Id: <client id>
X-BW-Broker-Timestamp: <unix seconds>
X-BW-Broker-Nonce: <unique random value>
X-BW-Broker-Signature: <hex hmac>
```

Compute the signature over the exact request target and body bytes:

```text
body_sha = SHA256(BODY).hexdigest()
canonical = METHOD + "\n" + PATH + "\n" + TIMESTAMP + "\n" + NONCE + "\n" + body_sha
signature = HMAC_SHA256(BW_BROKER_CLIENT_SECRET, canonical).hexdigest()
```

Rules:

- `METHOD` is uppercase, such as `GET` or `POST`.
- `PATH` is the exact request path, including query string when present.
- `BODY` is empty bytes for `GET`.
- For JSON, sign the exact bytes sent on the wire.
- Use a fresh nonce for every request.

## Endpoints

Catalog:

```http
GET /v1/catalog
```

Secret request:

```http
POST /v1/secret-requests
Content-Type: application/json

{
  "secret_id": "github_readonly_token",
  "purpose": "clone repo owner/name for task abc",
  "run_id": "task-or-session-id",
  "fields": ["password"]
}
```

Successful secret response:

```json
{
  "secret_id": "github_readonly_token",
  "fields": {
    "password": "..."
  },
  "ttl_seconds": 60
}
```

The catalog may expose an item-level `totp` field. That is not broker login 2FA; request it only when the target service login requires it for the current task.
