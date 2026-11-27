# Plaintext design

Plaintext is a self-hosted password manager whose server is assumed hostile. A stolen database, a malicious admin or a compromised host must not be able to read a vault, crack a password offline, or change a vault without the clients noticing. The name is the joke: the server only ever sees ciphertext.

## Threat model

The server is untrusted, not merely the database dump. It can lie in any response, replay old data, drop or reorder items, and log everything it receives. The clients are trusted: they are native apps and signed store builds, and the server never serves code that touches keys, so there is no web vault served from the server.

| The server can | The server cannot |
|---|---|
| See how many items and vaults an account has, rough blob sizes (padded to 256 bytes), write times, device names, IPs | Read any item, title, URL, username or note |
| Refuse service, delete everything | Brute-force the password offline (it would also need the 128-bit Secret Key) |
| Serve a brand-new device an old but genuine vault state; fork two devices onto different branches (see Known limits) | Swap, add or alter items, or roll a device back to an older state it already verified, without the client detecting it |
| | Downgrade the KDF or cipher (it supplies neither) |

## Secrets and keys

```
password ──NFKD──► Argon2id(m=64 MiB, t=3, p=1, salt=SHA256("plaintext/v1/argon-salt" ‖ SK)) ─┐
                                                                                            ▼
Secret Key SK (128 random bits, A1-XXXXXXX-XXXXXXX-XXXXXXX-XXXXXXX) ──────────► HKDF-SHA256(salt = SK)
                                                                         ├─ "plaintext/v1/unlock" → Account Unlock Key (AUK)
                                                                         └─ "plaintext/v1/auth"   → Ed25519 login key
SK ── HKDF "plaintext/v1/account-id" → account id (16 bytes, how the server finds the account)

AUK ──wraps──► Account Key (random 256-bit) ──wraps──► Vault Key (random, one per vault) ──seals──► items, manifest
```

- **Secret Key.** It is generated on the first device and never sent anywhere. Each device keeps it in the OS keychain (Apple Keychain, Android Keystore, Windows Credential Manager/DPAPI, Linux Secret Service), and the user keeps it in an Emergency Kit. A new device gets it by QR from an existing device or by typing it. Because it is mixed into every derived key, the server holds nothing that a weak password protects alone. The last two characters are a checksum, so a typo is caught before any key is derived.
- **Nothing server-chosen feeds a key.** The salt comes from the Secret Key and the Argon2 parameters are fixed per protocol version, so there is no prelogin call to lie in. The account id is a function of the Secret Key, which is why the server stores no email.
- **Password change** re-wraps the Account Key and replaces the login public key; items are untouched. *(Not built yet.)*
- **No recovery.** If the password, or the Secret Key together with every device, is lost, the data is gone. That is the cost of the threat model, and the UI must say so at signup.

## Login

The client signs `"plaintext/v1/login" ‖ account_id ‖ unix_ms` with the Ed25519 key. The server stores only the public key, accepts a timestamp (milliseconds) within ±120 s that is strictly newer than the account's last login (so a captured login can't be replayed), and returns a random bearer token. It stores only the token's SHA-256. The server never receives anything password-equivalent, and its stored public key can't be attacked without the Secret Key. A PAKE would add nothing here, because the server's verifier is already out of reach.

## Blobs

All encryption uses one construction: `0x01 ‖ nonce(24) ‖ XChaCha20-Poly1305(plaintext)`, with the version byte included in the associated data. There is no second cipher and no legacy path to downgrade to. The associated data names what a blob is and where it belongs:

| Blob | Key | AD |
|---|---|---|
| Account Key | AUK | `plaintext/v1/account-key ‖ account_id` |
| Vault Key | Account Key | `plaintext/v1/vault-key ‖ vault_id` |
| Manifest | Vault Key | `plaintext/v1/manifest ‖ vault_id` |
| Item | Vault Key | `plaintext/v1/item ‖ vault_id ‖ item_id` |

An item is a single JSON object sealed as one blob, so fields can't be swapped between items or between fields of one item. The JSON is padded with spaces to a multiple of 256 bytes. Unknown JSON fields are preserved, so an older client never drops data written by a newer one.

## Sync

Each vault has a counter and an encrypted **manifest** holding `{counter, item_id → SHA-256(item blob)}`. Only holders of the Vault Key can produce one.

- **Pull.** `GET /v1/vaults/{id}?since=N` returns the manifest and every item written after counter N. The client checks that every received blob matches its manifest hash and that every other manifest entry matches a blob it already holds. It also checks that the manifest's counter equals the server's counter and is not lower than the last counter this device verified. Any mismatch rejects the whole response and leaves local state untouched.
- **Push.** `PUT /v1/vaults/{id}` carries `expected_counter`, the new manifest, upserts and deletes. The server applies it only if the counter still matches, and otherwise answers 409. On a 409 the client pulls, keeps its own unpushed edits, and pushes again.
- **The rollback guard** is the per-device last-verified counter, persisted with the device's encrypted `VaultSnapshot`. A manifest with a lower counter is refused. A manifest at the same counter must describe exactly what the device already verified, which catches a server that stored a push it answered with an error and serves it later.
- **Concurrent edits of the same item:** the device that pushes second wins on its retry. There is no conflict copy yet.

## Known limits

- **Forks.** The server can hide device A's write from device B, let B push on top, and then serve B's branch to A, where A's item looks deleted. Each device's own history stays consistent, but two devices can be split. Detecting this needs devices to compare state with each other (for example a manifest hash shown on both, or devices gossiping their last manifest through the vault itself). The ETH Zurich paper below calls full rollback protection without trusted state an open problem.
- **A new device trusts its first sync.** It has no counter yet, so it can be shown an old but genuine state.
- **Metadata.** The server sees item counts, padded sizes, write times, device names and IPs.

## Wire API

| | |
|---|---|
| `POST /v1/signup` | `{account_id, auth_key, account_key, vault:{id, vault_key, manifest}}`. The first account needs nothing; later ones need `x-invite: $PLAINTEXT_INVITE`. |
| `POST /v1/login` | `{account_id, ts, sig, device}` → `{token}` |
| `POST /v1/logout` | Ends the session. |
| `GET /v1/account` | `{account_key, vaults:[{id, vault_key, counter}]}` |
| `GET /v1/vaults/{id}?since=N` | `{counter, manifest, items:[{id, blob}]}` |
| `PUT /v1/vaults/{id}` | `{expected_counter, manifest, upserts, deletes}` → 204, or 409 |

Ids are hex and blobs are base64. Types are in `core/src/api.rs`.

## Code layout

- **`core/`** (`plaintext-core`) holds every crypto and sync rule, sans-IO: clients move the request and response types over their own HTTP stack. It is the only crypto implementation. Native apps get it through UniFFI (Swift, Kotlin) and extensions through WASM, so no platform reimplements it. `tools/kat.py` is an independent Python implementation of the key derivation, which pins the known-answer vectors in the core tests.
- **`server/`** (`plaintext-server`) is one binary on axum + SQLite, the same stack as Tugport. It enforces only ownership, sizes and the counter compare-and-swap.

## Clients (planned)

| Platform | Shape | Unlock |
|---|---|---|
| iOS + iPadOS | SwiftUI app, AutoFill credential provider extension, passkey provider | Face ID / Touch ID releasing the Account Key from the Keychain (Secure Enclave-bound) |
| macOS | SwiftUI app hosting the Safari Web Extension; native-messaging host for Chrome and Firefox | Touch ID, Keychain |
| Android | Compose app, Autofill service, Credential Manager passkey provider | BiometricPrompt + Keystore (StrongBox if present) |
| Windows, Linux | Small Rust tray app; native-messaging host for the extensions | Windows Hello + DPAPI; Secret Service (libsecret) |
| Chrome, Firefox | MV3 extension, core via WASM | The desktop host unlocks via the OS keychain; without a host, password + Secret Key in extension storage |
| Safari | Safari Web Extension inside the macOS/iOS app, sharing its keychain group | Same as the host app |

Quick unlock always means that the Account Key is kept in the OS keychain behind biometrics. The master password is never stored. Clients never fetch icons or anything else by an item's URL (Bitwarden's BW06 leak).

## Lessons from Vaultwarden and Bitwarden

Vaultwarden (read at `dbd7829`) is a faithful Bitwarden server, so it inherits the protocol attacks in Scarlata et al., *Zero Knowledge (About) Encryption: A Comparative Security Analysis of Four Cloud-based Password Managers*, USENIX Security 2026 ([ePrint 2026/058](https://eprint.iacr.org/2026/058)).

| Bitwarden/Vaultwarden | Attack | Plaintext |
|---|---|---|
| The server returns KDF type and iterations at prelogin; email is the salt | BW07 KDF downgrade | No prelogin; parameters pinned by the client; salt from the Secret Key |
| The login hash is PBKDF2(master key, password); the server re-hashes it | A DB leak allows offline guessing of weak passwords | The verifier is an Ed25519 public key that also needs the 128-bit Secret Key |
| Each field is a separate EncString; metadata (type, folder, flags) in clear | BW04/BW05 field and item swapping | One AEAD blob per item, with ids in the AD |
| Legacy AES-CBC (type 0, no MAC) is still decryptable | BW11/BW12 padding oracle, key recovery | A single AEAD with a version byte; no legacy path |
| Per-item keys can be switched off by the server | BW10 | No server-controlled crypto flags |
| Org keys are RSA-wrapped to server-supplied public keys; auto-enrolment escrow | BW01/02/08/09 key escrow and injection | No sharing yet. When it comes, see below. |
| The server serves the web vault JS | Malicious code reads keys | No web vault from the server |
| The TOTP 2FA secret is stored on the server | 2FA protects login, not data | The Secret Key does what 2FA can't: it protects the data itself |

**Sharing, when built.** Every account gets an Ed25519 signing key and an X25519 key. Public keys are pinned on first use and shown as a fingerprint to compare in person or by QR. Wrapped vault keys and membership changes are signed by the sender. There is no auto-enrolment, no admin recovery, and no server-timed emergency access (a timer only the server enforces is trust in the server).

## Milestones

1. **Core and server.** Done: key derivation, blobs, sync, signup/login, e2e test showing the database holds no plaintext.
2. Password change, device list and revocation, attachments, deployment image, a public instance for dogfooding.
3. CLI (`plaintext`) on the core, plus an importer for Bitwarden JSON, 1Password 1PUX and CSV.
4. UniFFI bindings, then iOS + macOS app with Safari extension and AutoFill.
5. Android app with Autofill service.
6. Chrome and Firefox extensions (WASM) plus a native-messaging host for OS-keychain unlock on Windows, Linux and macOS.
7. Passkeys (store and serve as provider), TOTP codes, sharing (above), and a security audit before 1.0.
