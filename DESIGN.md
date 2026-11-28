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
| Claim a member's account was deleted, so an owner's device removes them from a shared vault (an owner can add them back) | Add anyone to a vault, or keep a removed member able to read what's written after the new key |

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

The client signs `"plaintext/v1/login" ‖ account_id ‖ unix_ms ‖ host`, where `host` is the server address the user typed, reduced to lowercase host and port (`crypto::server_host`: no scheme, path or default port). The server accepts only its own host: the names in `PLAINTEXT_URL` (comma-separated). A look-alike server can't relay a login to the real one for a session, since the signature names the look-alike. Without `PLAINTEXT_URL` the server knows its address only from the request's `Host` header, which a relaying server sets to anything, so it then accepts logins only for `localhost`, `127.0.0.1` or `[::1]` (any port) and refuses others with 403, asking the operator to set it. The server stores only the public key, accepts a timestamp within ±120 s that is strictly newer than the account's last login, and returns a random bearer token, storing only its SHA-256. A session lasts 30 days, or less if the login asks for it (`ttl` in seconds); after that the server refuses the token. Sessions can be listed and ended; disabling an account ends them all. Disabling a person disables the agents they own too, since they hold those agents' keys. Apps that keep only the Account Key for quick unlock ask for the password again when the session runs out.

## Servers and accounts

Every server is independent and can sit at any address: a family's own domain, an IP on the LAN, a Tailscale name, or a hosted service. Nothing in the protocol names a particular server. One person can hold accounts on several servers. Each account is its own (server, username, Secret Key), and apps hold one `Session` per account and show their vaults side by side. Vaults are shared only within a server. Moving items between accounts is a copy made by a client holding both accounts, which re-encrypts the items.

`GET /v1/info` (no session) tells an app what to ask for before signup: `{version, open, setup}`. `open` means anyone may sign up; `setup` means the server has no accounts yet and the first one needs the setup code.

A hosted server runs with `PLAINTEXT_SIGNUP=open`, and must also set `PLAINTEXT_SETUP_CODE` while it has no accounts (it refuses to start otherwise), so the operator rather than the first stranger becomes the admin. On such a server:
- anyone may sign up, and any person may create invites, which still verify both sides;
- the directory doesn't list everyone: `GET /v1/users` returns only the people who joined with your invites (admins see everyone), and people are found by exact username (`GET /v1/users/{name}`). Otherwise a hosted server would hand every customer the list of all the others;
- signups and failed logins are rate-limited per client address (10 signups and 30 failed logins an hour; IPv6 per /64). Successful logins don't count, since agents sign in on every run, and a correct login works even from an address over its limit, so nobody sharing an address (or a proxy) can lock the others out. Behind a reverse proxy, `PLAINTEXT_TRUST_PROXY=1` takes the address from the last `X-Forwarded-For` entry (in the last header line), the one a single proxy adds. The counts live in memory and reset when the server restarts. At most 100,000 addresses are tracked an hour; past that, new addresses can't sign up but can still log in.

`PLAINTEXT_QUOTA_MB` limits each account's storage on any server: the item blobs, files, staged items (see "Sync") and every roster version and manifest of the vaults that count against it (below), and the share links and inbox messages it and its agents sent. A sent message counts until the recipient deletes it, it expires or the sender deletes it (`DELETE /v1/messages/{id}` works for either end), and stops counting if the sender's account is deleted. Agents never pay for a vault: when one would, its owner does. A vault counts against its creator. If an owner removes the creator, it counts against that owner from then on (against the person who owns the agent, if an agent signed the roster); a creator with an agent still listed keeps paying. If the creator's account is deleted or the creator leaves the vault, it counts against a remaining member, owners first; whoever ends up with a vault they don't want can leave it too (see "Vaults, roles and sharing"). A write that would take that account past the quota gets 507 (Insufficient Storage), including writes by other members of the vault and new vaults. Every push adds a manifest to the counted history, so over the quota a push goes through only if it removes items and nothing else grows: not the items' bytes, the sealed manifest or the envelope's unknown fields. So reading and deleting keep working, and so does replacing a vault key, which re-seals the same items and needn't remove any; edits wait until there's room, even ones that take no more. Every roster version counts too. A roster change that removes or demotes someone, and adds or promotes nobody and gives nobody a later expiry (or none), always goes through; any other (adding someone, a promotion, a later expiry) needs room in the account that pays once the change is stored: for the new version, or for the whole vault if the same change removes the creator and the vault moves to the signer. Demoting or removing someone (a new key) needs the device's unpushed changes to that vault sent or deleted first, and so does any roster change while someone who left is still listed. An owner can't take themselves out of the roster (they leave instead), and every roster keeps at least one owner. No counted document may grow by fields the server doesn't know when the account paying for it ends up over the quota; a roster change that keeps the unknown fields it had needs no room for them. A refused change stays on the device and is pushed again once there's room (if that takes more than a week, other devices may have collected the attachments it uploaded; see "Attachments"); the account's other vaults keep syncing. Attachments are freed about a week after nothing refers to them, by a device that syncs the vault (see "Attachments" below), so deleting an item makes room for its files only then. Unset means unlimited. `GET /v1/account` reports `quota` and `usage` in bytes, and the vaults that count against the account as `paid`. Wrapped keys aren't counted (the server keeps them only for the members of the latest roster at its epoch, so they come to at most about 1 MiB per vault), and a vault's audit log keeps its newest 1000 entries. So what an account stores goes past its quota only by a manifest envelope (about 400 bytes) for each item a push removes, a roster version and an envelope for each member removed or demoted, and what owners stage for a new key (see "Sync"). An owner over the quota who wants to make someone else an owner makes room first, or leaves the vault (below). Rosters and manifests stored before this rule count only while they're the latest: nobody can delete them, and counting a long-used vault's old ones (old manifests carry their sealed part, see "Sync") would fill its account with data it can't delete.

### Deleting an account

`DELETE /v1/account` needs the password again: it carries `{ts, sig}`, a signature by the login key over `"plaintext/v1/account-delete" ‖ account_id ‖ ts ‖ host` (±120 s, and the host as for a login), so a stolen session token can't delete an account. It deletes the account and the agents it owns, with their sessions, inbox, share links and invites, and their vaults:

- A vault nobody else uses (no current, enabled member outside the account and its agents) is deleted with its items and files.
- In a shared vault the server stops serving them and drops their wrapped keys, as with an expired member. It can't change the signed roster, so pulls list them under `gone` until an owner's device notices and removes them for real with a new key, all in one roster version (a roster that names a deleted account is refused). Their audit entries stay.
- **The only owner of a vault others use can't delete their account** (an account that is only a reader or writer there may, even if no owner is left). Ownerless vaults could never change key or members again, and deleting them would take the data from everyone else. The client names those vaults; the user makes someone else an owner, removes the others or leaves those vaults (below) first. The server refuses with 409 as well.
- The admin can't delete their account while others use the server, since nobody else could invite or disable accounts. The last account may go, and the server is fresh again.

A deleted username is free to sign up again. Whoever pinned the old account gets `KeyChanged` for the new one, so nobody mistakes them for each other.

## Users, invites and verification

- Usernames are per server (2–32 of `a-z 0-9 . _ -`). The first account is the admin (if the server was started with `PLAINTEXT_SETUP_CODE`, it must present that code). On an invite-only server, everyone else needs a one-use invite (7 days) from an admin. No emails are stored.
- Each account publishes a self-signed identity `{username, kind: human|agent, owner?, sign_pk, enc_pk}`. An agent's `owner` is the agent's own claim: clients show an agent as yours only if you made it (it's pinned and verified in your keyring from creation).
- **Pinning.** A client pins a user's keys the first time it sees them (directory lookup, a vault roster that verifies, an inbox message) and refuses any later difference (`KeyChanged`). Pins live in the synced keyring. A response that fails verification pins nothing.
- **Fixing a pin.** A pin is replaced only by a key confirmed out of band: `plaintext user verify NAME --fingerprint …` (the fingerprint they read to you, or scanned from their screen) re-pins them if the directory's key has that fingerprint, which repairs a key the server substituted on first use.
- **Verification** marks a pin as confirmed out of band. Two ways: compare the fingerprint (`fingerprint(username, sign_pk, enc_pk)`, 4 groups of 6) in person or by QR; or an invite, which verifies both sides. An invite code is `id.secret.inviter.fingerprint`. The inviter's keyring keeps the secret; the new user sends `HMAC(secret, identity)` at signup, and the inviter's devices check it and mark the new user verified (a server that substitutes the new user's identity can't produce the proof). If a valid proof's identity differs from keys already pinned under that name, neither wins silently: a first-use pin is the server's word, and the proof only shows that whoever held the code made that identity, while the server chose the name it's listed under. The app reports the conflict and keeps the invite until the user compares fingerprints. The new user's client looks the inviter up after the account exists (so a mismatch never costs the Secret Key) and pins them, verified, only if their fingerprint matches the one in the code; otherwise it pins nothing and warns.
- **The keyring can be rolled back by the server**, so each device also keeps its own sealed copy and merges it in after signing in: pins are only ever added, and a pin the device holds is never replaced by the server's copy. A brand-new device trusts the server's keyring (first-use trust). The keyring is padded like items, so its size doesn't reveal when someone was verified.
- Apps show "not verified" next to anyone unverified, everywhere it matters (sharing, vault members, inbox).

## Vaults, roles and sharing

A vault's membership is a **roster**, a signed and hash-chained document:

`Roster {vault_id, version, prev = SHA256(previous signed body), epoch, key_check, members: [{username, sign_pk, enc_pk, role: reader|writer|owner, expires?}]}`

- Version 0 is signed by an owner listed in it; every later version is signed by an owner of the previous version. Clients verify the whole chain from version 0 the first time they see a vault, then each new version. Every member's keys are pinned on sight, once the version verifies.
- **Owners never expire** (a roster giving an owner an expiry is invalid): who signed each version must stay checkable on any device at any later time. Give someone edit access with an expiry instead.
- **Roster checkpoints.** The keyring records, per vault, the newest roster version (and its hash) any of the account's devices has verified. A device shown an older roster, for example a new phone the server tries to keep on the vault as it was before someone was removed, rejects it as a rollback.
- The **vault key** for each epoch is sealed to each member's X25519 key (`ephemeral ECDH → HKDF → XChaCha20-Poly1305`, AD names vault, epoch and username). Because anyone can seal to a public key, the roster carries `key_check = HMAC(vault key, "plaintext/v1/key-check" ‖ vault_id ‖ epoch)`, signed by the owner. A member accepts an unwrapped key only if it matches.
- **Granting** (add someone, promote, change expiry) is a new roster version; a new member also gets the current vault key and can read the vault's history. **Demoting** a writer or owner rotates the key like a removal, since the demoted member still holds it.
- **Revoking** starts a new epoch: a fresh vault key, sealed to the remaining members, and every item re-sealed in the same roster change (staged in parts first when they don't fit in one request, see "Sync"). Nothing written afterwards is readable with the old key. Attachments keep their own keys (below), so they are not re-uploaded; a removed member who saved an item's file key while they had access can still decrypt that one file if they also kept its download.
- **Roles.** Readers hold the vault key, so they could produce a valid blob; what stops them is that every manifest names the roster version it was written under and must be signed by a writer or owner of that version, in that version's epoch, and the latest manifest must be in the current epoch. Because demotion and removal start a new epoch, anything accepted under the current key was written by someone who could write at the time. The server enforces roles too, for honest deployments.
- **Leaving.** `POST /v1/vaults/{id}/leave`, signed by the member's identity key (`{vault_id, ts}`, ±120 s) so a stolen session token alone can't delete a vault, takes a member and their agents out of a vault, by the rules account deletion applies to each vault: the server stops serving them and drops their wrapped keys, pulls list them under `gone` until an owner's device removes them with a new key (a roster change that still lists them is refused with 409, so a device that hasn't seen them leave can't bring them back), and the vault is deleted if nobody else uses it. A vault that counts against them counts against a remaining member from then on, owners first. Nobody is asked before being added, so anyone listed can leave, whatever their device can make of the vault: a member whose membership expired, a person on behalf of an agent of theirs who is listed, and the only owner of a vault others use. That last one leaves the others an ownerless vault whose members and key can't change any more, and the leaver keeps the key they had (the server no longer serves them the vault, though); the client says so before leaving. So someone left holding a vault they don't want (its creator made them an owner and left, and now it counts against them), even one their device can't open, gives it up by leaving: `plaintext vault leave` takes the full id the sync names. To find such vaults, `GET /v1/account` lists every vault that counts against the account under `paid` (also ones it isn't a current member of), sync names them together with that command and that they count against the account: one it isn't a current member of always, one that fails to sync unless the account created it (roster v0's signer) and opened it before (so a server serving an old copy of your own vault doesn't talk you into deleting it), and one it can open but didn't create only when the server limits storage (otherwise it costs nothing, and someone who took a vault over on purpose would be told on every sync), and the 507 text mentions leaving a vault someone handed you. Leaving works over the quota.
- **Expiry** (for people and agents) makes a member count as removed after the time: the server stops serving them, and the first device of an owner that syncs afterwards revokes them for real (new key). Until then, an expired member who kept the key could still write through a malicious server.

## Blobs

One construction everywhere: `0x01 ‖ nonce(24) ‖ XChaCha20-Poly1305(plaintext)`, version byte in the AD. No second cipher, no legacy path. Item JSON is padded with spaces to a multiple of 256 bytes. Attachments are padded with zero bytes using Padmé: with L = max(length, 256) and E = ⌊log2 L⌋, L rounds up to a multiple of 2^(E − ⌊log2 E⌋ − 1). Beyond the 256-byte minimum, that adds under 1/16 (at most about 6%) and leaves only O(log log n) bits of the size visible. The result is capped at 64 MiB − 41 bytes, so the sealed file never exceeds what the server stores. The real size is in the item's `FileRef.size`, and the client cuts the opened file back to it (refusing a size larger than the file), so files sealed before padding open unchanged and readers don't depend on the exact padding rule. Clients from before padding save a padded file with zero bytes at the end. The server stores the padded size. Unknown JSON fields are preserved, so an older client never drops data written by a newer one. (Passkeys gained their own `extra` map after v1's first clients; those clients drop a passkey's extra fields when they save the item.)

| Blob | Key | AD |
|---|---|---|
| Account Key | AUK | `plaintext/v1/account-key ‖ account_id` |
| Keyring | Account Key | `plaintext/v1/keyring ‖ account_id` |
| Vault key (per member) | sealed to member's X25519 | `plaintext/v1/vault-key ‖ vault_id ‖ epoch ‖ username` |
| Manifest contents | Vault Key | `plaintext/v1/manifest ‖ vault_id` |
| Item | Vault Key | `plaintext/v1/item ‖ vault_id ‖ item_id` |
| Attachment | its own random key (stored in the item) | `plaintext/v1/file ‖ vault_id ‖ file_id` |
| Inbox message | sealed to recipient's X25519 | `plaintext/v1/message ‖ message_id ‖ sender ‖ 0x00 ‖ recipient` |
| Share link | random key, only in the URL fragment | `plaintext/v1/link ‖ link_id` |
| Device snapshot | Account Key | `plaintext/v1/vault-snapshot ‖ account_id ‖ vault_id` |

Signatures are Ed25519 over `plaintext/v1/<domain> ‖ body` with domains `identity`, `roster`, `manifest`, `message`, `leave`, so a signature for one purpose is never valid for another. Signed documents travel as `{body, signer, sig}` with the exact signed bytes.

## Items

An item is one JSON object: `kind` (login, password, note, card, identity, document, bank, database, server, ssh_key, api_credential, wifi, passport, driver_license, membership, crypto_wallet, …), `title`, the login designations (`username`, `password`, `urls`, `totp`), `notes`, free sections of typed fields (text, concealed, url, email, phone, date, month_year, otp, address, menu, card_number, card_type, ssh_key, boolean), `tags`, `favorite`, `archived`, `files`, `passkeys`, `password_history`, and up to 10 earlier versions in `history`. This mirrors 1Password's model so imports are lossless.

### Attachments

A file is uploaded on its own (`PUT /v1/vaults/{id}/files/{fid}`) before the item that lists it is pushed, so the server can hold files no item refers to: an upload whose push never happened, a writer's junk, and the files of deleted items and of edits that dropped them. They count against the quota like any other file. Nobody deletes a file the moment its item goes, because another device may still bring the item back with an edit it hadn't pushed (local edits win the merge), and the file has to be there then.

Instead every writer's device collects them as it syncs. Right after it pulls a vault, it lists the vault's files (`GET /v1/vaults/{id}/files`, writers only), and the listing carries the server's clock, which times everything below, so a device's own clock doesn't matter. The device notes the files that no item refers to: not the items it holds, in their current fields or in any of the earlier versions in `history`, and not the server's copy of an item it has changed or deleted but not pushed yet. It keeps the time it first saw each one so in its sealed snapshot. Once a file has stayed unreferenced on that device for a week, the device deletes it. A file that an item lists again in one of its syncs is dropped from the notes. So is everything, if the device hasn't looked for more than two weeks (a laptop left closed), since a file may have been referenced again in between. Readers never collect. Neither do one-off agent runs (`PLAINTEXT_AGENT_KEY`), which keep no snapshot, but `plaintext mcp` keeps its session and syncs on every tool call, so one that runs for more than a week collects too. Collecting costs one more request per vault the device can write to, on every sync.

Freeing room therefore relies on some writer's device that syncs the vault at least every two weeks; if none does, unreferenced files stay and count against the quota.

The week is the limit, and it's timed from when a device first saw a file unreferenced, not from when it last was referenced. An item that comes back with a change made after a device has collected its attachments comes back without them, and they return 404. That happens when a device offline for more than a week pushes an edit to a deleted item, when a change the server refused stays unpushed that long while another writer collects its upload, and when an app holds an upload that long before saving its item. It also happens sooner in two cases. An item deleted, brought back and deleted again between two of a device's syncs looks unreferenced to that device the whole time, so its files can go a week after the first deletion, however recent the second. And an edit that brings an item back after a device's pull but before its delete request loses the file. Only an item's `files`, current or in `history`, count as references, so a later client that refers to files from anywhere else has to change what this one collects.

## Sync

Each vault has a counter and a **manifest chain**. A manifest is a signed envelope `{vault_id, counter, epoch, roster (version), prev = SHA256(previous manifest's signed body), sealed_hash}` and its sealed part, which holds the vault name and `{item_id → SHA256(item blob)}` and travels beside the envelope; `sealed_hash` is its SHA-256. The server keeps the sealed part only for the latest manifest, so the chain it keeps for good comes to about 400 bytes a push, and it refuses an envelope over 512 bytes. Manifests written before this carry the sealed part inside the envelope (`sealed`); clients still verify them and the server keeps them, but it refuses new ones. So apps from before can't read a vault once a newer app pushes to it, nor push to an updated server, and newer apps can't push to an older server: update the server and the apps together.

- **Pull** `GET /v1/vaults/{id}?since=N&roster=V` returns every roster after V, every manifest after N (with the latest one's sealed part), the caller's wrapped key for the current epoch, every item written after N, and the members who left or whose accounts were deleted (`gone`). It comes in pages of about 16 MiB, at least one entry each: rosters, then manifests, then items by id, each in order, with the latest manifest's sealed part in the page that carries it. A page that isn't the last says `more`, and the client asks for the next with `roster`, `from` (a manifest counter) and `after` (an item id) set to the last of each it has, and `at` set to the first page's counter. The server answers 409 once the counter has moved, since every change to the items or the key moves it, and the client starts the pull over (up to five times; then it reports the vault as not updated, without suggesting to leave it, and the next sync tries again). A page must move the pull on, so a query repeated within one pull is refused, though a server can still send made-up entries until the device runs out of memory, which is refusing service. The client joins the pages and checks them as one response: the roster chain; the key against `key_check`; that the manifests are consecutive, each links to the one before (starting from the last one this device verified), and each is signed by someone who could write; that the latest is under the current epoch and its sealed part matches the hash it signs; and that every item blob matches the latest manifest's hash. (An expired writer's manifest is still accepted until an owner's device rotates the key, which it does on its next sync: refusing it would leave the vault unreadable for everyone until then.) Any failure rejects the whole response and changes nothing. A vault that fails is reported and keeps its last verified state (or isn't listed, if it never verified); the other vaults still sync, so nobody can jam a sync by sharing a bad vault.
- **Push** `PUT /v1/vaults/{id}` carries `expected_counter`, a new signed manifest, upserts and deletes. The server applies it only if the counter matches and the manifest extends its chain; otherwise 409, and the client pulls, merges and retries.
- **Large pushes.** When a push's items and sealed manifest (or a key rotation's) come to more than 16 MiB, the client sends the items ahead with `POST /v1/vaults/{id}/stage` in parts of up to 16 MiB under a random stage id, then pushes with no upserts and `staged: {id, count}`. The server moves the staged items in with the manifest, in one transaction, so other devices see all of the push or none of it. It keeps one stage per member and vault (a new stage id drops the previous one; a refused part or push drops the whole stage, and so does the member's next push or a roster change that leaves them no longer a writer) and deletes it a day after its first part, writing an audit entry when a stage gets its first items, and refuses a push whose stage doesn't hold exactly `count` items (409; the client stages again). Two devices of one account staging into the same vault at once undo each other's stage, so one of them retries. Staged items count against the vault's creator, so a big push needs room for all its items while it's staged, even where it replaces items of the same size. Over the quota only an owner may stage, and only while everything its owners have staged comes to no more than its items, which is what a new key needs. A stage started anew has a new day, so an owner who keeps restaging keeps that much stored; the audit log shows it. Pulls come in pages, so no push is too big for the other devices to pull, and a vault of any size can change its key.
- **Merge.** Local unpushed edits win. If the server's copy of an item also changed since the local edit began, it is kept as a conflict copy ("… (conflict)") so nothing is lost; the server must send that copy's blob, or the pull is rejected. A blob that was only re-sealed (a key rotation) with unchanged content doesn't count as a change, so it can't undo a pending delete.
- **Rollback guard.** Each device persists its last verified counter and manifest hash (in its sealed snapshot). The server can't serve an older state, or a different branch, to a device that has seen a newer one: the hash chain won't link. A vault the server stops listing keeps its verified state on the device, so it can't come back older; the device the user left a vault on starts it afresh if they're added again, while their other devices keep its state, unsent changes included. A device with no state starts from the latest manifest (`latest=true`) instead of replaying the whole chain.
- **Default vault.** New items go to the vault the account made at signup (recorded in the keyring), never a vault someone shared with it, so nobody can collect your logins by sharing you a vault called "Personal". If the server stops listing that vault, the client asks which vault to use instead of picking another one it created, which might be shared.

## Inbox, requests and links

- **Sharing one item with a user:** the item's current fields (as for links, below) are sealed to their pinned key, signed, and placed in their inbox with an optional expiry. They save it into a vault or delete it. The sealed part's AD names both sender and recipient, so whoever holds the envelope can't re-sign it as someone else or redirect it, and it's padded like items.
- **Access requests:** an agent sends its owner a sealed, signed request ("need the prod DB password for the migration"). The owner grants vault access or sends the item.
- **Share links** for people without an account: the item's current fields (no password history, earlier versions, passkeys or attachments) are sealed with a random key that exists only in the link's `#fragment`; the server stores the blob with an expiry (≤ 30 days) and optional view limit, and serves it without authentication. The link opens a static viewer page, `getplaintext.org/s/` by default, so the vault server never serves the code that decrypts. Self-hosters can put a copy of `docs/s/` on any domain of their own and point their apps at it (the CLI reads `PLAINTEXT_LINK_PAGE`). It must not be served by the vault server itself, because whoever serves that page's script can read the key. Whoever controls the viewer's hosting could, in principle, serve a malicious viewer; that page is static, open source and small.

## Agents

Agents are first-class accounts owned by a human, built for automation and AI tools:

- `plaintext agent create ci-bot --vault CI --role reader --expires 30d` makes the account, pins and verifies it for the owner, grants access, and prints the `ptk_…` key once.
- **An agent trusts its owner only.** The owner's client creates the agent's keyring with the owner already pinned and verified, and records who the owner is. An agent accepts a vault only if its owner signed some version of that vault's roster. Agents keep no state between runs, so without this a server could show one a vault of its own (posing as the owner, or as anyone) and feed it secrets, or collect the passwords it generates.
- Access is per vault, with a role and an expiry, enforced by keys (an agent only ever receives the keys of vaults it's in). Agents can't create vaults, invite people or create agents. The owner (or an admin) can disable an agent instantly.
- Every agent read (at most one entry a minute per agent, so a pull in pages shows once) and every write is in the vault's audit log, visible to its owners.
- **Use without seeing:** `plaintext run -- cmd` and `plaintext inject` resolve `pt://Vault/Item/field` references into environment variables or files. The MCP server (`plaintext mcp`) gives AI agents search, non-secret fields, `run_with_secrets` (secrets go into the command's environment and are scrubbed from its output), `create_item` with a generated password the model never sees, and `request_access`. Returning secret values to the model needs `PLAINTEXT_MCP_REVEAL=1`. This keeps secrets out of model context and transcripts by accident; it is not a boundary against a model determined to read them (a command can transform a secret before printing it, and `run_with_secrets` scrubs only the plain, base64 and percent-encoded forms). The boundary is which vaults the agent account can read.
- **An agent never borrows a person's session.** `plaintext mcp` runs only with an agent key. A person's unlocked CLI session works only in the terminal it was unlocked in (terminal device and login session, like sudo's tickets), so commands an AI tool runs, which have no terminal, can't reach that person's vaults through it. A model given a shell on the same machine as the same user can still read that user's keychain and files; run agents under their own OS user or in a container.

## Wire API

| | |
|---|---|
| `POST /v1/signup` | `SignupRequest`; first account free, then an invite proof |
| `POST /v1/agents` | `SignupRequest` for an agent, by its owner's session |
| `POST /v1/login`, `/v1/logout` | signed for the server's host; optional `ttl` (seconds, at most 30 days) |
| `GET /v1/account` | username, admin, sealed Account Key and keyring, vault ids, storage quota and usage, the vaults that count against it (`paid`) |
| `PUT /v1/account/keyring` | compare-and-swap on the keyring counter |
| `POST /v1/account/password` | signed by the current login key |
| `DELETE /v1/account` | signed by the current login key (see "Deleting an account") |
| `GET /v1/sessions`, `DELETE /v1/sessions/{id}` | |
| `GET /v1/info` | public: version, open signup, setup code needed |
| `GET /v1/users`, `GET /v1/users/{name}` | directory (limited on open servers, see "Servers and accounts"); exact lookup |
| `POST /v1/users/{name}/disable`, `POST /v1/invites` | admin actions (owners may disable their agents; anyone invites on open servers) |
| `POST /v1/vaults` | new vault (roster v0, keys, first manifest) |
| `GET`/`PUT /v1/vaults/{id}` | pull (in pages) / push |
| `POST /v1/vaults/{id}/roster` | grant, change or revoke (with rotation) |
| `POST /v1/vaults/{id}/stage` | items of a push or rotation too big for one request (see "Sync") |
| `POST /v1/vaults/{id}/leave` | the caller and their agents leave the vault |
| `GET /v1/vaults/{id}/audit` | owners |
| `PUT`/`GET`/`DELETE /v1/vaults/{id}/files/{fid}` | sealed attachments, up to 64 MB |
| `GET /v1/vaults/{id}/files` | every uploaded file's id and sealed size, whether or not an item lists it, and the server's clock (writers and up) |
| `GET`/`POST /v1/messages`, `DELETE /v1/messages/{id}` | inbox |
| `POST /v1/links`, `GET`/`DELETE /v1/links/{id}` | share links (GET is public, CORS open) |

Types are in `core/src/api.rs`; ids are hex, blobs base64.

Signed documents are limited as a whole, before anything in them is parsed: identities 2 KiB, rosters 512 KiB and 1000 members (each listed once), messages their sealed part in base64 plus 4 KiB, manifest envelopes 512 bytes (the sealed part beside one, up to 16 MiB). `GET /v1/messages` returns the oldest messages up to 32 MiB (at least one); the rest come once those are deleted. `HEAD` on a share link gets 405, so checking a link doesn't use up a view, and every response carries `Cache-Control: no-store`, plus `Strict-Transport-Security: max-age=31536000` when a `PLAINTEXT_URL` address is `https://`. Expired links, messages and sessions are never served, and are deleted every ten minutes.

Request bodies are limited to 64 KiB, except: the keyring, inbox messages and share links take 2 MiB; vault create, push, stage and roster changes take 32 MiB; files take 64 MB. Those larger requests need a valid session, which the server checks before it reads the body. A push or key rotation with more items than that stages them first (see "Sync"). A body over its limit gets 413, which clients tell apart from a full account (507).

## Code layout

| Crate | What |
|---|---|
| `core/` | crypto, keys, rosters, sync rules, items, generator, TOTP, Watchtower. Sans-IO. Known-answer vectors cross-checked by `tools/kat.py` (Python + libsodium). |
| `client/` | sync orchestration over a `Transport` (ureq by default), importers. Used by the CLI, the app bindings and the extension. End-to-end test over real HTTP. |
| `wasm/` | core and client for browsers: the share-link viewer (`docs/s/`) and, with the `extension` feature, the browser extension's bridge. |
| `extension/` | the Chrome and Firefox extension (MV3, plain JavaScript); see "The browser extension". |
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

### The browser extension

The extension runs `plaintext-client` itself, compiled to WebAssembly, so it verifies, merges and guards against rollback exactly as the CLI does. JavaScript only moves bytes and draws the UI.

**Sync without blocking.** `Session`'s logic (sign-in, sync, the 409 retries, expired-member removal, the keyring's compare-and-swap merge, `problems`, hidden vaults) is written once, as `async` methods over `AsyncTransport`. Every blocking `Transport` is an `AsyncTransport` whose requests finish inside the call, and the blocking methods the CLI and app bindings use (`sync`, `login`, `put_item`, …) poll that future once. In the browser, `wasm/` implements `AsyncTransport` with one JavaScript function around `fetch` (redirects refused, no cookies, a timeout and a 128 MiB cap). Three alternatives were rejected:
- A thin async layer in `wasm/` over `plaintext-core` would copy the orchestration above, which lives in `client`, and the copies would drift.
- Blocking requests from the browser (synchronous XHR in a worker) can't run in Chrome's MV3 service worker, which has neither, and XHR can't refuse redirects.
- A step API that returns "pending" and reruns the operation once JavaScript has the response is unsound: each run re-seals with fresh nonces (a removal even makes a new vault key), so local state would record a push the server never received.

**What it keeps.**
- **`storage.local`:** each account's server, username and Secret Key, sealed under the password (`crypto::seal_secret_key`: Argon2id with a random salt). It also holds the account's vault snapshots and keyring, sealed with the Account Key, as the CLI keeps them, so rollback guards and pins survive restarts.
- **`storage.session`:** the session token and Account Key while unlocked. This storage lives in memory only and is gone when the browser quits.
- **The trade-off.** A browser profile has no OS keychain, so someone who copies the profile can guess the password offline at Argon2 speed. That's the same position as holding the server's database together with the Secret Key.
- **Reopening.** When the browser suspends the extension, it picks the session up again from these two with no network. The next sync checks the token.
- **Locking** happens after the chosen idle time (10 minutes by default) and when the browser closes. Locking from the extension ends the server session too. Closing the browser can't, so that token lapses on the server's schedule, but no copy of it survives on the device.

**Filling.**
- **Matching.** Logins are offered by `site::matches`: the same registrable domain (eTLD+1, from a bundled Public Suffix List), or the exact host when the item asks for it. An https login is never offered to a plain http page.
- **Where fills happen.** A fill goes only into the tab's top frame. The extension takes the page's address from the browser, never from the page, and a form that posts to another site gets nothing unless the login is saved for that site too.
- **When fills happen.** Secrets reach a page only when the user picks a login in the extension's popup or presses the fill shortcut. The small mark in login fields just opens the popup, so a page can't restyle or cover the thing that fills.
- **Saving.** After a login form is submitted, the toolbar button shows a badge and the popup asks whether to save the login or update its password. The page sees nothing either way, so it can't learn what's saved or trick a click. New logins go to the account's default vault.
- **Form destinations.** The form's destination is checked as the browser resolves it: the form's action and every submit button's `formaction`, with `<base>` applied.

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
- **A new device trusts its first sync,** and a user who hasn't verified anyone trusts the directory on first use. Invites and fingerprints close the second gap. Roster checkpoints in the keyring stop a server from showing a new device a vault from before a removal, unless it also serves that device an old keyring, which nothing on a brand-new device can detect. Agents keep no state, so they are always in this position.
- **Metadata** (usernames, memberships, sizes, timing) is visible to the server. Items, messages and the keyring are padded to 256-byte steps, and attachments to Padmé steps (above), so the server sees a file's size only to within about 6%.
- **History** is kept in full: every manifest envelope, so any device can verify the chain from where it left off, and every roster version, so a new device can verify the roster from version 0. Both count toward the storage quota, so a vault used for years carries its history there: about 400 bytes a push, and each roster version's size (about 200 bytes a member). Signed checkpoints could trim it, at the cost of devices that were away longer than the checkpoint starting afresh. A writer who keeps pushing fills the paying account with history nobody can delete (up to about 800 bytes a push); an owner can remove them, but what they pushed stays counted, and only giving the vault up frees it.
- **A busy vault can outrun a slow pull.** A pull of more than one page starts over whenever the vault changes midway, up to five times a sync, so a device on a slow link can't finish pulling a big vault while someone pushes faster than that.
