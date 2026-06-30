# bw-touchid-broker

Rust local HTTPS broker for remote AI agents that need narrowly scoped Vaultwarden/Bitwarden CLI secrets.

The broker runs on macOS, keeps the Vaultwarden agent account master password in Keychain, prompts with Touch ID/passcode before reading it, and uses `bw` locally to fetch one catalog-approved item after a signed request and local approval.

The broker, CLI, request signing, catalog builder, HTTPS server, audit log, and `bw` wrapper are Rust. The macOS Keychain user-presence operation is handled by a tiny Swift helper compiled by `bw-broker init`/`bootstrap`, because that is the narrowest bridge to Apple's Security and LocalAuthentication APIs.

## Security model

- The remote agent never receives the Vaultwarden master password, API key, or `BW_SESSION`.
- The remote agent can only see the local broker catalog, not the whole vault.
- Each secret request is HMAC-signed, timestamped, nonce-checked, shown in a macOS approval dialog, and then gated by Touch ID/passcode when the Keychain item is read.
- Secret request denials/releases are written to `~/.bw-broker/audit.log` without secret values.
- The first pass supports HTTPS plus signed requests. Use Tailscale or Cloudflare Tunnel for reachability; mTLS/client certificates should be added before exposing this broadly.

If the remote runtime receives a password, assume that password can be captured by that runtime. Prefer scoped tokens, throwaway accounts, short TTLs, and read-only credentials.

Same-user malware can still try to invoke the Keychain helper and trigger a user-presence prompt. The prompt protects broker-mediated reads; it does not make a compromised local session safe. A hardened second version should use a signed helper/app, mTLS, and preferably hardware-backed or phone-side request approval.

## Setup

```bash
cd /Users/lei/workspace/bw-touchid-broker
cargo build --release
./target/release/bw-broker init --email ai-agent@example.com --server-url https://vaultwarden.example.com
./target/release/bw-broker store-master-password
./target/release/bw-broker login
./target/release/bw-broker build-catalog --sync
./target/release/bw-broker serve
```

If the agent account requires two-step login, pass the current code during first login:

```bash
./target/release/bw-broker login --method 0 --code <current-code>
```

For a local self-signed cert test, export the printed client config:

```bash
export BW_BROKER_URL=https://127.0.0.1:27443
export BW_BROKER_CLIENT_ID=remote-agent
export BW_BROKER_CLIENT_SECRET='printed-by-init-or-show-client'
python3 examples/agent_request.py
python3 examples/agent_request.py github_readonly_token "clone repo example/foo"
```

## macOS app

The native app is a SwiftUI menu bar app that starts and stops the Rust broker, runs bootstrap/catalog commands, opens the broker home folder, copies the configured broker URL, and shows recent command output. It embeds the `bw-broker` binary in the app bundle, so you do not need to keep a terminal running for `serve`.

Build the app bundle:

```bash
scripts/build-macos-app.sh
```

Open it:

```bash
open "build/macos/BW Broker.app"
```

The first app version assumes the broker has already been initialized:

```bash
./target/release/bw-broker init --email ai-agent@example.com --server-url https://vaultwarden.example.com
./target/release/bw-broker store-master-password
./target/release/bw-broker login --method 0 --code <current-code>
```

After that, open the menu bar app. It starts the broker automatically by default and keeps `bw-broker serve` as its child process. Use the Start at Launch toggle if you want to disable automatic serving.

The Network section edits the broker bind host, port, and public URL:

- Bind host is where the broker listens, such as `127.0.0.1`, a Tailscale IP, or `0.0.0.0`.
- Public URL is what the remote agent calls, such as `https://100.x.y.z:27443` or a tunnel URL.
- Stop the broker before saving network changes; they take effect on the next start.

The app intentionally does not display generated client secrets; use `bw-broker show-client` in a trusted terminal when you need to provision a remote client.

The generated development TLS certificate is self-signed. Remote test clients must either trust it or skip certificate verification for local testing, for example `curl -k https://<public-url>/health`.

### Clients and approval

Each remote agent is a signing client with its own HMAC secret, allowed secret ids, and approval mode:

- `prompt` requires local approval for catalog entries that require approval.
- `trusted` skips the per-request approval dialog for that client.

Trust does not expand access. A trusted client still needs a valid HMAC signature, fresh nonce, valid timestamp, catalog permission, and field permission. Use it for a client/runtime you are willing to let request its allowed catalog entries without another click.

The menu bar app can add a client and shows the generated client secret once. Existing client secrets are not displayed in the app. CLI equivalents:

```bash
./target/release/bw-broker list-clients
./target/release/bw-broker add-client --client-id ci-agent --allowed-secret github_readonly_token --trusted
./target/release/bw-broker trust-client --client-id ci-agent
./target/release/bw-broker untrust-client --client-id ci-agent
```

## Remote exposure

Keep the broker on a private interface when possible. For Tailscale, bind to your Tailscale IP and set the public URL to that private HTTPS address:

```bash
./target/release/bw-broker init \
  --email ai-agent@example.com \
  --server-url https://vaultwarden.example.com \
  --host 100.x.y.z \
  --public-url https://100.x.y.z:27443
```

For Cloudflare Tunnel, keep the broker bound to localhost and point the tunnel at `https://127.0.0.1:27443`. The signed-request layer is the first-pass client authentication; add mTLS or Cloudflare Access before broad exposure.

## Commands

```bash
./target/release/bw-broker init
./target/release/bw-broker bootstrap
./target/release/bw-broker store-master-password
./target/release/bw-broker login
./target/release/bw-broker self-test-keychain
./target/release/bw-broker has-master-password
./target/release/bw-broker delete-master-password
./target/release/bw-broker build-catalog --sync
./target/release/bw-broker serve
./target/release/bw-broker show-client
./target/release/bw-broker sign-request --client-id remote-agent --client-secret ... --method GET --path /v1/catalog
```

`self-test-keychain` stores a throwaway secret under a separate Keychain service, reads it back through the same Touch ID/passcode path, and deletes it. It does not touch the stored Vaultwarden master password.

On some macOS command-line contexts, Keychain rejects `SecAccessControl.userPresence` storage with `errSecMissingEntitlement` (`-34018`). The helper handles that by falling back to normal local Keychain storage while still requiring `LocalAuthentication` before every broker read.

## First login and 2FA

The broker uses an isolated `bw` CLI profile under `~/.bw-broker/bw-cli`. If that profile is unauthenticated, the broker must run `bw login` once. If the account has two-step login enabled, provide the same `--method` and `--code` values accepted by `bw login`:

```bash
./target/release/bw-broker login --method 0 --code <current-code>
```

Current Bitwarden CLI method values are `0` for authenticator app/TOTP, `1` for email, and `3` for YubiKey OTP. FIDO2/WebAuthn and Duo are not supported by the Bitwarden CLI login enum.

After the isolated profile is logged in, normal broker operations should only need to unlock with the stored master password:

```bash
./target/release/bw-broker build-catalog --sync
./target/release/bw-broker serve
```

If you want to combine first login with catalog generation, `build-catalog` also accepts first-login-only options:

```bash
./target/release/bw-broker build-catalog --sync --login-method 0 --login-code <current-code>
```

Passkey/WebAuthn two-step login is not a Touch ID unlock for `bw`. The broker's Touch ID/passcode prompt is local Keychain approval before it releases the stored master password to `bw unlock`; it does not make `bw unlock` itself passkey-based.

## Catalog

`~/.bw-broker/catalog.json` stores aliases, `bw` item IDs, allowed fields, TTLs, and client policy. It does not store password values.

`build-catalog` unlocks the dedicated agent account, reads items available to that account, and generates aliases from item names. Put only automation-safe items in the Vaultwarden collection visible to the agent account before building the catalog.

If the agent account can see more than one collection, narrow catalog generation:

```bash
./target/release/bw-broker build-catalog --collection-id <collection-id>
./target/release/bw-broker build-catalog --organization-id <organization-id>
```

To install the agent instructions into Codex later, copy or symlink `agent-skill/bw-broker-agent` into your Codex skills directory.

## Request signing

The signature is:

```text
HMAC_SHA256(client_secret, METHOD + "\n" + PATH + "\n" + TIMESTAMP + "\n" + NONCE + "\n" + SHA256(BODY).hexdigest())
```

Headers:

```text
X-BW-Broker-Client-Id
X-BW-Broker-Timestamp
X-BW-Broker-Nonce
X-BW-Broker-Signature
```

Sign the exact path used in the HTTP request, including query string when present.
