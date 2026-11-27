# Plaintext design

Plaintext is a self-hosted password manager whose server is assumed hostile. A stolen database, a malicious admin or a compromised host must not be able to read a vault, crack a password offline, or change a vault without the clients noticing. The name is the joke: the server only ever sees ciphertext.

This document is the protocol (v1). `core/` implements all of it and is the only implementation: every app reaches it through `client/` (Rust), UniFFI (Swift, Kotlin) or WASM (browser), never a reimplementation. Feature coverage against 1Password is in [PARITY.md](PARITY.md).

## Threat model

The server is untrusted, not merely the database dump. It can lie in any response, replay old data, drop or reorder items, hand out wrong public keys, and log everything it receives. The clients are trusted: native apps and signed store builds. The server never serves code that touches keys (no server-hosted web vault).

| The server can | The server cannot |
|---|---|
| See usernames, who is in which vault with which role, item counts, padded blob sizes, write times, device names, IPs | Read any item, title, URL, note, vault name, inbox message or attachment |
| Refuse service, delete everything | Brute-force a password offline (it would also need the 128-bit Secret Key) |
| Serve a brand-new device an old but genuine vault; keep two devices on different branches forever (see Known limits) | Swap, drop, add or alter items, roll a device back, or splice two branches, without the client detecting it |
| Introduce a fake user to someone who hasn't verified anyone yet (trust on first use) | Replace the keys of a user you have pinned or verified; give you a vault key the owner didn't commit to |
| Let a reader or removed member write on the server side | Make other members accept that write: manifests are signed and checked against the roster |

## Secrets and keys

```
password ──NFKD──► Argon2id(m=64 MiB, t=3, p=1, salt=SHA256("plaintext/v1/argon-salt" ‖ SK)) ─┐
                                                                                            ▼
Secret Key SK (128 random bits, A1-XXXXXXX-XXXXXXX-XXXXXXX-XXXXXXX) ──────────► HKDF-SHA256(salt = SK)
                                                                         ├─ "plaintext/v1/unlock" → Account Unlock Key (AUK)
                                                                         └─ "plaintext/v1/auth"   → Ed25519 login key
SK ── HKDF "plaintext/v1/account-id" → account id

AUK ──seals──► Account Key (random) ──seals──► keyring: identity keys (Ed25519 sign, X25519 enc) + pinned contacts + invite secrets
                                            └─► device snapshots of vaults
identity enc key ◄──sealed to── Vault Key (random per vault and epoch) ──seals──► items, manifest (vault name inside)
```

- **Secret Key.** Generated on the first device, never sent anywhere. Devices keep it in the OS keychain; the user keeps it in an Emergency Kit. The last two characters are a checksum.
- **Agents** have a 256-bit `ptk_…` key instead of password + Secret Key: `HKDF(salt="plaintext/v1/agent", ikm=key)` gives the same three outputs, with no Argon2 because the key has full entropy.
- **Nothing server-chosen feeds a key.** Salt and Argon2 parameters are fixed per protocol version; there is no prelogin call to lie in.
- **Identity keys are random**, not derived from the password, so a password change keeps the identity, the pins others made of it, and every vault.
- **Password change** re-seals the Account Key under the new AUK and replaces the login public key, signed by the old login key. Other sessions end.
- **No recovery.** Lose the password, or the Secret Key along with every device, and the data is gone. Admin or family recovery would be key escrow, the attack class in the table below, so there is none.

## Login and sessions

The client signs `"plaintext/v1/login" ‖ account_id ‖ unix_ms`. The server stores only the public key, accepts a timestamp within ±120 s that is strictly newer than the account's last login, and returns a random bearer token, storing only its SHA-256. Sessions can be listed and ended; disabling an account ends them all.

## Users, invites and verification

- Usernames are per server (2–32 of `a-z 0-9 . _ -`). The first account is the admin (if the server was started with `PLAINTEXT_SETUP_CODE`, it must present that code); everyone else needs a one-use invite (7 days) from an admin. No emails are stored.
- Each account publishes a self-signed identity `{username, kind: human|agent, owner?, sign_pk, enc_pk}`.
- **Pinning.** A client pins a user's keys the first time it sees them (directory lookup, a vault roster, an inbox message) and refuses any later difference (`KeyChanged`). Pins live in the synced keyring.
- **Verification** marks a pin as confirmed out of band. Two ways: compare the fingerprint (`fingerprint(username, sign_pk, enc_pk)`, 4 groups of 6) in person or by QR; or an invite, which verifies both sides. An invite code is `id.secret.inviter.fingerprint`. The inviter's keyring keeps the secret; the new user sends `HMAC(secret, identity)` at signup, and the inviter's devices check it and mark the new user verified (a server that substitutes the new user's identity can't produce the proof). The new user's client looks the inviter up and marks them verified only if their fingerprint matches the one in the code.
- **The keyring can be rolled back by the server**, so each device also keeps its own sealed copy and merges it in after signing in: pins are only ever added, and a pin the device holds is never replaced by the server's copy. A brand-new device trusts the server's keyring (first-use trust).
- Apps show "not verified" next to anyone unverified, everywhere it matters (sharing, vault members, inbox).

## Vaults, roles and sharing

A vault's membership is a **roster**, a signed and hash-chained document:

`Roster {vault_id, version, prev = SHA256(previous signed body), epoch, key_check, members: [{username, sign_pk, enc_pk, role: reader|writer|owner, expires?}]}`

- Version 0 is signed by an owner listed in it; every later version is signed by an owner of the previous version. Clients verify the whole chain from version 0 the first time they see a vault, then each new version. Every member's keys are pinned on sight.
- The **vault key** for each epoch is sealed to each member's X25519 key (`ephemeral ECDH → HKDF → XChaCha20-Poly1305`, AD names vault, epoch and username). Because anyone can seal to a public key, the roster carries `key_check = HMAC(vault key, "plaintext/v1/key-check" ‖ vault_id ‖ epoch)`, signed by the owner. A member accepts an unwrapped key only if it matches.
- **Granting** (add someone, promote, change expiry) is a new roster version; a new member also gets the current vault key and can read the vault's history. **Demoting** a writer or owner rotates the key like a removal, since the demoted member still holds it.
- **Revoking** starts a new epoch: a fresh vault key, sealed to the remaining members, and every item re-sealed in the same request. Nothing written afterwards is readable with the old key. Attachments keep their own keys (below), so they are not re-uploaded; a removed member who saved an item's file key while they had access can still decrypt that one file if they also kept its download.
- **Roles.** Readers hold the vault key, so they could produce a valid blob; what stops them is that every manifest names the roster version it was written under and must be signed by a writer or owner of that version, in that version's epoch, and the latest manifest must be in the current epoch. Because demotion and removal start a new epoch, anything accepted under the current key was written by someone who could write at the time. The server enforces roles too, for honest deployments.
- **Expiry** (for people and agents) makes a member count as removed after the time: the server stops serving them, and the first device of an owner that syncs afterwards revokes them for real (new key). Until then, an expired member who kept the key could still write through a malicious server.

## Blobs

One construction everywhere: `0x01 ‖ nonce(24) ‖ XChaCha20-Poly1305(plaintext)`, version byte in the AD. No second cipher, no legacy path. Item JSON is padded with spaces to a multiple of 256 bytes. Unknown JSON fields are preserved, so an older client never drops data written by a newer one.

| Blob | Key | AD |
|---|---|---|
| Account Key | AUK | `plaintext/v1/account-key ‖ account_id` |
| Keyring | Account Key | `plaintext/v1/keyring ‖ account_id` |
| Vault key (per member) | sealed to member's X25519 | `plaintext/v1/vault-key ‖ vault_id ‖ epoch ‖ username` |
| Manifest contents | Vault Key | `plaintext/v1/manifest ‖ vault_id` |
| Item | Vault Key | `plaintext/v1/item ‖ vault_id ‖ item_id` |
| Attachment | its own random key (stored in the item) | `plaintext/v1/file ‖ vault_id ‖ file_id` |
| Inbox message | sealed to recipient's X25519 | `plaintext/v1/message ‖ message_id ‖ recipient` |
| Share link | random key, only in the URL fragment | `plaintext/v1/link ‖ link_id` |
| Device snapshot | Account Key | `plaintext/v1/vault-snapshot ‖ account_id ‖ vault_id` |

Signatures are Ed25519 over `plaintext/v1/<domain> ‖ body` with domains `identity`, `roster`, `manifest`, `message`, so a signature for one purpose is never valid for another. Signed documents travel as `{body, signer, sig}` with the exact signed bytes.

## Items

An item is one JSON object: `kind` (login, password, note, card, identity, document, bank, database, server, ssh_key, api_credential, wifi, passport, driver_license, membership, crypto_wallet, …), `title`, the login designations (`username`, `password`, `urls`, `totp`), `notes`, free sections of typed fields (text, concealed, url, email, phone, date, month_year, otp, address, menu, card_number, card_type, ssh_key, boolean), `tags`, `favorite`, `archived`, `files`, `passkeys`, `password_history`, and up to 10 earlier versions in `history`. This mirrors 1Password's model so imports are lossless.

## Sync

Each vault has a counter and a **manifest chain**. A manifest is a signed envelope `{vault_id, counter, epoch, roster (version), prev = SHA256(previous manifest's signed body), sealed}`, where `sealed` holds the vault name and `{item_id → SHA256(item blob)}`.

- **Pull** `GET /v1/vaults/{id}?since=N&roster=V` returns every roster after V, every manifest after N, the caller's wrapped key for the current epoch, and every item written after N. The client checks: the roster chain; the key against `key_check`; that the manifests are consecutive, each links to the one before (starting from the last one this device verified), and each is signed by someone who could write; that the latest is under the current epoch and signed by a current, unexpired writer; and that every item blob matches the latest manifest's hash. Any failure rejects the whole response and changes nothing.
- **Push** `PUT /v1/vaults/{id}` carries `expected_counter`, a new signed manifest, upserts and deletes. The server applies it only if the counter matches and the manifest extends its chain; otherwise 409, and the client pulls, merges and retries.
- **Merge.** Local unpushed edits win. If the server's copy of an item also changed since the local edit began, it is kept as a conflict copy ("… (conflict)") so nothing is lost.
- **Rollback guard.** Each device persists its last verified counter and manifest hash (in its sealed snapshot). The server can't serve an older state, or a different branch, to a device that has seen a newer one: the hash chain won't link. A vault the server stops listing keeps its verified state on the device, so it can't come back older. A device with no state starts from the latest manifest (`latest=true`) instead of replaying the whole chain.
- **Default vault.** New items go to the vault the account made at signup (recorded in the keyring) or another vault it created, never a vault someone shared with it, so nobody can collect your logins by sharing you a vault called "Personal".

## Inbox, requests and links

- **Sharing one item with a user:** the item is sealed to their pinned key, signed, and placed in their inbox with an optional expiry. They save it into a vault or delete it.
- **Access requests:** an agent sends its owner a sealed, signed request ("need the prod DB password for the migration"). The owner grants vault access or sends the item.
- **Share links** for people without an account: the item's current fields (no password history, earlier versions, passkeys or attachments) are sealed with a random key that exists only in the link's `#fragment`; the server stores the blob with an expiry (≤ 30 days) and optional view limit, and serves it without authentication. The link opens a static viewer at `getplaintext.org/s/`, so the self-hosted server never serves the code that decrypts. Whoever controls getplaintext.org's hosting could, in principle, serve a malicious viewer; that page is static, open source and small.

## Agents

Agents are first-class accounts owned by a human, built for automation and AI tools:

- `plaintext agent create ci-bot --vault CI --role reader --expires 30d` makes the account, pins and verifies it for the owner, grants access, and prints the `ptk_…` key once.
- Access is per vault, with a role and an expiry, enforced by keys (an agent only ever receives the keys of vaults it's in). Agents can't create vaults, invite people or create agents. The owner (or an admin) can disable an agent instantly.
- Every agent read and every write is in the vault's audit log, visible to its owners.
- **Use without seeing:** `plaintext run -- cmd` and `plaintext inject` resolve `pt://Vault/Item/field` references into environment variables or files. The MCP server (`plaintext mcp`) gives AI agents search, non-secret fields, `run_with_secrets` (secrets go into the command's environment and are scrubbed from its output), `create_item` with a generated password the model never sees, and `request_access`. Returning secret values to the model needs `PLAINTEXT_MCP_REVEAL=1`. This keeps secrets out of model context and transcripts by accident; it is not a boundary against a model determined to read them (a command can transform a secret before printing it). The boundary is which vaults the agent account can read.

## Wire API

| | |
|---|---|
| `POST /v1/signup` | `SignupRequest`; first account free, then an invite proof |
| `POST /v1/agents` | `SignupRequest` for an agent, by its owner's session |
| `POST /v1/login`, `/v1/logout` | |
| `GET /v1/account` | username, admin, sealed Account Key and keyring, vault ids |
| `PUT /v1/account/keyring` | compare-and-swap on the keyring counter |
| `POST /v1/account/password` | signed by the current login key |
| `GET /v1/sessions`, `DELETE /v1/sessions/{id}` | |
| `GET /v1/users`, `POST /v1/users/{name}/disable`, `POST /v1/invites` | directory; admin actions (owners may disable their agents) |
| `POST /v1/vaults` | new vault (roster v0, keys, first manifest) |
| `GET`/`PUT /v1/vaults/{id}` | pull / push |
| `POST /v1/vaults/{id}/roster` | grant, change or revoke (with rotation) |
| `GET /v1/vaults/{id}/audit` | owners |
| `PUT`/`GET`/`DELETE /v1/vaults/{id}/files/{fid}` | sealed attachments, up to 64 MB |
| `GET`/`POST /v1/messages`, `DELETE /v1/messages/{id}` | inbox |
| `POST /v1/links`, `GET`/`DELETE /v1/links/{id}` | share links (GET is public, CORS open) |

Types are in `core/src/api.rs`; ids are hex, blobs base64.

## Code layout

| Crate | What |
|---|---|
| `core/` | crypto, keys, rosters, sync rules, items, generator, TOTP, Watchtower. Sans-IO. Known-answer vectors cross-checked by `tools/kat.py` (Python + libsodium). |
| `client/` | sync orchestration over a `Transport` (ureq by default), importers. Used by the CLI and the app bindings. End-to-end test over real HTTP. |
| `server/` | axum + SQLite, one binary, the same stack as Tugport. |
| `cli/` | the `plaintext` command and MCP server. |

## Apps

| Platform | Shape | Unlock |
|---|---|---|
| iOS + iPadOS | SwiftUI; AutoFill credential provider and passkey provider extension | Face ID / Touch ID releases the Account Key from the Keychain (Secure Enclave-bound access control) |
| macOS | SwiftUI app hosting the Safari Web Extension; native-messaging host for Chrome and Firefox | Touch ID, Keychain |
| Android | Compose; Autofill service; Credential Manager passkey provider | BiometricPrompt + Android Keystore (StrongBox when present) |
| Windows, Linux | the CLI plus a small desktop app; native-messaging host for the extensions | Windows Hello + Credential Manager; Secret Service |
| Chrome, Firefox | MV3 extension on core compiled to WASM | the desktop app's host when present; otherwise password + Secret Key |
| Safari | Safari Web Extension inside the Apple app, sharing its keychain group | same as the app |

Quick unlock always means the Account Key sits in the OS keychain behind biometrics; the master password is never stored. Clients never fetch icons or anything else by an item's URL (Bitwarden's BW06 leak). UI rules for every app are in [UI.md](UI.md).

## Lessons from Vaultwarden and Bitwarden

Vaultwarden (read at `dbd7829`) is a faithful Bitwarden server, so it inherits the protocol attacks in Scarlata et al., *Zero Knowledge (About) Encryption: A Comparative Security Analysis of Four Cloud-based Password Managers*, USENIX Security 2026 ([ePrint 2026/058](https://eprint.iacr.org/2026/058)).

| Bitwarden/Vaultwarden | Attack | Plaintext |
|---|---|---|
| The server returns KDF type and iterations at prelogin; email is the salt | BW07 KDF downgrade | No prelogin; parameters pinned; salt from the Secret Key |
| The login hash is derived from the password; the server re-hashes it | A DB leak allows offline guessing of weak passwords | The verifier is an Ed25519 public key that also needs the 128-bit Secret Key |
| Each field is a separate EncString; metadata in clear | BW04/BW05 field and item swapping | One AEAD blob per item, ids in the AD, every blob committed to by a signed manifest |
| Legacy AES-CBC (type 0, no MAC) still decryptable | BW11/BW12 | One AEAD, a version byte, no legacy path |
| Per-item keys can be switched off by the server | BW10 | No server-controlled crypto flags |
| Org keys RSA-wrapped to server-supplied public keys; auto-enrolment escrow | BW01/02/08/09 key escrow and injection | Pinned identities, invite proofs and fingerprints; owner-signed rosters; `key_check` on every wrapped key; no escrow or admin recovery |
| Emergency access waits are enforced only by the server | trust in the server | Not offered |
| The server serves the web vault JS | malicious code reads keys | No server-hosted vault; link viewer is static on getplaintext.org |

## Known limits

- **Forks between devices.** The server can keep device A's writes from device B indefinitely. Each device's own history is consistent and can never be spliced with the other branch, but they stay split until the server reunites them. Detecting a permanent split needs devices to compare state out of band (comparing a vault's latest manifest hash, which the apps can show).
- **A new device trusts its first sync,** and a user who hasn't verified anyone trusts the directory on first use. Invites and fingerprints close the second gap.
- **Metadata** (usernames, memberships, sizes, timing) is visible to the server.
- **Manifest history** is kept in full so any device can verify the chain from where it left off. Signed checkpoints can trim it if it ever gets large.
