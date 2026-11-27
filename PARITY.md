# 1Password feature parity

This file compares Plaintext with 1Password 8 as of 2026-11-27. The 1Password column summarises the feature inventory (support.1password.com, www.1password.dev and release notes, all fetched on 2026-11-27). The Plaintext column describes the code in this repository, not DESIGN.md, which is being rewritten.

**Status**

- **Done (core/server/CLI)**: works end to end today through the `plaintext` CLI (or the MCP server) on top of `core`, `client` and `server`. Every native app still has to build its own screens for it.
- **Protocol ready, needs app UI**: the item model, wire types and server already support it, so only app or extension work remains.
- **Planned**: needs new work first, in `core`, the item schema, the server, or new client tooling (a CLI subsystem, a third-party integration, bindings). The "Gaps in the protocol" list at the end collects the protocol and server parts.
- **Won't do**: deliberately out of scope. The note gives the reason.

**Tier**: v1 is needed for the first native app release, v2 comes later, and "won't" means never.

Plaintext's ground rules shape many rows. The server is untrusted and holds only ciphertext. Nobody, including admins, family members or the server, can recover an account, because that would be key escrow. The Secret Key and Emergency Kit are the only recovery story. Bitwarden compatibility means import and export only. Agents are first-class accounts.

## 1. Item categories

The item `kind` is a free string (`core/src/item.rs`). The 1PUX importer maps all 22 category ids (`category()` in `client/src/import.rs`). `plaintext add --kind K --field label=value --concealed label=value` can create any kind today. Apps need per-kind templates.

| Feature | 1Password | Plaintext status | Tier | Notes |
|---|---|---|---|---|
| Login | Username, password, websites, OTP | Done (core/server/CLI) | v1 | `Item` has built-in `username`, `password`, `urls` and `totp`. The CLI adds, edits, gets and deletes them. |
| Credit Card | Number, CVV, expiry; browser fill | Done (core/server/CLI) | v1 | Stored as kind `card` with `card_number`, `card_type`, `concealed` and `month_year` fields, and imported from 1PUX. Filling cards in forms is in section 6. |
| Secure Note | One Markdown text field | Done (core/server/CLI) | v1 | Kind `note` with `notes`. Markdown rendering is app work (section 3). |
| Identity | Name, address, phone, email | Done (core/server/CLI) | v1 | Kind `identity` with `address`, `phone`, `email` and `date` fields. Address filling is v2 (section 6). |
| Password | A single password | Done (core/server/CLI) | v1 | It is stored as kind `password` with only the built-in `password` field. |
| Document | An uploaded file | Done (core/server/CLI) | v1 | Kind `document`, with the file as a `FileRef` attachment (`plaintext attach` and `plaintext download`). |
| Software License | Version, key, registered email | Done (core/server/CLI) | v2 | Imported as `software_license`. The creation template is v2; v1 apps show it through the generic section and field view. |
| Bank Account | Routing number, account number, PIN | Done (core/server/CLI) | v2 | The importer maps it to kind `bank`, and v1 apps show it through the generic field view. A creation template is v2. |
| Database | Type, server, port, username, password | Done (core/server/CLI) | v2 | Imported as `database`. The template is v2. Agents read these fields through `pt://` references. |
| Driver License | Number, name, expiry | Done (core/server/CLI) | v2 | The importer maps it to kind `driver_license`, and v1 apps show it through the generic field view. A creation template is v2. |
| Outdoor License | Wildlife, quota, state | Done (core/server/CLI) | v2 | The importer maps it to kind `outdoor_license`, and v1 apps show it through the generic field view. A creation template is v2. |
| Membership | Group, member ID, PIN | Done (core/server/CLI) | v2 | The importer maps it to kind `membership`, and v1 apps show it through the generic field view. A creation template is v2. |
| Passport | Country, number, name | Done (core/server/CLI) | v2 | The importer maps it to kind `passport`, and v1 apps show it through the generic field view. A creation template is v2. |
| Reward Program | Company, member ID, PIN | Done (core/server/CLI) | v2 | The importer maps it to kind `reward_program`, and v1 apps show it through the generic field view. A creation template is v2. |
| Social Security Number | Name, SSN | Done (core/server/CLI) | v2 | The importer maps it to kind `ssn`, and v1 apps show it through the generic field view. A creation template is v2. |
| Wireless Router | Network name and password; Wi-Fi QR | Done (core/server/CLI) | v2 | Imported as `wifi`. The QR code is app work (section 3). |
| Server | URL, username, password | Done (core/server/CLI) | v2 | The importer maps it to kind `server`, and v1 apps show it through the generic field view. A creation template is v2. |
| Email Account | Server, port, auth method | Done (core/server/CLI) | v2 | The importer maps it to kind `email`, and v1 apps show it through the generic field view. A creation template is v2. |
| API Credential | Key, hostname; JWT decoding | Done (core/server/CLI) | v2 | Imported as `api_credential`. JWT decoding and the browser offer to save keys are not built. |
| Medical Record | Date, location, professional | Done (core/server/CLI) | v2 | The importer maps it to kind `medical_record`, and v1 apps show it through the generic field view. A creation template is v2. |
| SSH Key | Generate or import; used by the SSH agent | Done (core/server/CLI) | v2 | Storage only: kind `ssh_key` with an `ssh_key` field type. Generation and the SSH agent are Planned (section 8). |
| Crypto Wallet | Recovery phrase, password, address | Done (core/server/CLI) | v2 | Imported as `crypto_wallet` with whatever fields the export carries. The template is v2. |
| CLI category list | `op item template list` shows the same 22 categories | Done (core/server/CLI) | v1 | The importer covers all 22. There is no `plaintext template list` yet, and `--kind` accepts any string. |
| "Person" category | Only in the SDK enum, not user-facing | Won't do | won't | 1Password doesn't ship it. An unknown kind would round-trip anyway. |
| Custom item templates | Business: new categories, edited built-ins | Planned | v2 | No protocol change is needed: a template could be stored as an item of kind `template` in a vault. Core still needs to define that convention. |
| Sidebar category view | Categories in the sidebar | Protocol ready, needs app UI | v2 | Grouping by `kind` happens on the device, so it needs no protocol work. |

## 2. Built-in fields per category

| Feature | 1Password | Plaintext status | Tier | Notes |
|---|---|---|---|---|
| Login fields (CLI template) | username, password, notesPlain, websites | Done (core/server/CLI) | v1 | `username`, `password`, `notes` and `urls` are top-level fields of `Item`. |
| Database fields (CLI JSON example) | Type, hostname, port, database, SID, options | Done (core/server/CLI) | v2 | They are imported as typed fields in sections. The creation template is v2. |
| Item JSON shape | title, category, sections, fields with id and purpose, version, last_edited_by | Done (core/server/CLI) | v1 | `Item` mirrors this shape: `kind`, `title`, `sections[{title, fields[{label, type, value}]}]`, `created` and `updated`. Fields have no stable `id` or `purpose`, so references resolve by label. `extra` keeps unknown keys. The editor isn't stored per item; the manifest signer shows only who wrote each vault version. |
| Crypto Wallet field ids | recoveryPhrase, password, walletAddress (third-party source) | Done (core/server/CLI) | v2 | Whatever a 1PUX export carries comes in as labelled fields. Nothing depends on the unverified ids. |
| Crypto Wallet autocomplete tokens | crypto-address and crypto-recovery-seed for the Save button | Won't do | won't | These only serve 1Password's website Save button (section 6). |
| Login recovery codes | recovery-code autocomplete on Logins | Protocol ready, needs app UI | v2 | Store them as `concealed` fields. Filling them needs the extension. |
| Password strength metadata | password_details.strength on concealed fields | Done (core/server/CLI) | v1 | `tools::strength_bits` computes strength on the device and doesn't store it. It has no dictionary (see the `ponytail:` note), so it overrates passwords like "Password1!". |
| Per-category fields from real 1PUX exports | Typed fields in named sections for each category | Done (core/server/CLI) | v1 | The 1PUX value parser maps concealed, email, phone, url, address, date, monthYear, menu, card number and type, sshKey and totp values to Plaintext field types, keeping section titles and field labels. Addresses are flattened to one comma-separated string, the first one-time code becomes the item's `totp`, and the "guarded" and "multiline" flags are dropped. |

## 3. Custom fields, sections, links

| Feature | 1Password | Plaintext status | Tier | Notes |
|---|---|---|---|---|
| Field types (app UI) | Text, URL, email, address, date, month/year, OTP, password, phone, "Sign in with", security questions | Protocol ready, needs app UI | v1 | `Field.type` covers `text`, `concealed`, `url`, `email`, `phone`, `date`, `month_year`, `otp`, `address`, `menu`, `card_number`, `card_type`, `ssh_key` and `boolean`. "Sign in with" isn't modelled (section 6). |
| Field types (CLI) | password, text, email, url, date, monthYear, phone, otp, file | Done (core/server/CLI) | v1 | The CLI creates only `text` (`--field`) and `concealed` (`--concealed`) fields, plus `--totp` (asked for, never an argument; an empty answer removes it) and files through `attach`. Other types arrive only through import. |
| Field types (SDK enum) | Includes Reference (a link to another item) | Planned | v2 | All types exist except Reference. That needs an item-schema field type holding an item id (see Related items). |
| SDK-supported field kinds | API keys, SSH keys, OTP, files, passkeys, references | Done (core/server/CLI) | v1 | `Item` holds every kind except item references. Files are `FileRef`s and passkeys are `Passkey` entries. |
| Sections | Named sections, reordered by drag | Protocol ready, needs app UI | v1 | `sections` is an ordered list, so reordering is a list edit. The CLI puts every field it adds in one section. |
| Security questions | A section; answers generated | Protocol ready, needs app UI | v2 | Store questions as a section of `concealed` fields and generate answers with the existing generator. |
| File attachments | Any item; 1 to 5 GB per person; 2 GB per file | Done (core/server/CLI) | v1 | Each file is sealed with its own random key, kept in the item's `FileRef`, so changing a vault key needs no re-upload. The server takes up to 64 MiB per file as one request body stored in SQLite, and `PLAINTEXT_QUOTA_MB` sets a per-account storage quota. Larger files need protocol work (see Gaps). |
| Markdown notes | Headings, lists, code, links | Protocol ready, needs app UI | v1 | `notes` is a plain string. Rendering is client-side. |
| Related items | One-way links within one vault | Planned | v2 | This needs a reference field holding an item id. Item ids are stable within a vault. A move to another vault creates a new id, so links have to be dropped there, as 1Password does. |
| Private item links | A deep link for people who already have access | Protocol ready, needs app UI | v2 | A `plaintext://vault/<id>/item/<id>` URL scheme needs no server work, since access already depends on holding the vault key. |
| Item locations | Map location; the mobile Nearby list | Planned | v2 | This needs an item-schema field. The Nearby lookup runs on the device, so the server never sees locations. |
| Wi-Fi QR code | Generated from network name and password | Protocol ready, needs app UI | v2 | The app renders the QR code from the `wifi` item's fields. |
| Expiry alerts | One alert per item on a date field; category defaults | Planned | v2 | `date` fields exist. An alert flag on a field and a Watchtower "expiring" check in core are needed. |
| Rich icons / custom icons | Downloaded site icons; encrypted custom icons | Won't do | won't | Apps never fetch anything by an item's URL, because doing so leaks which sites you have accounts on (Bitwarden's BW06). Shipping a bundled icon set or encrypted custom icons stored as attachments is possible later without protocol work. |

## 4. Password generator, usernames, masked email

| Feature | 1Password | Plaintext status | Tier | Notes |
|---|---|---|---|---|
| Generator types | Random, Memorable, PIN | Done (core/server/CLI) | v1 | `tools::Recipe::{Random, Memorable, Pin}` uses rejection sampling, so there is no modulo bias. It is exposed by `plaintext generate`, `add --generate` and the MCP `generate_password` tool. |
| Memorable options | Seven separator types, three word lists, capitalize one chunk | Done (core/server/CLI) | v1 | Words come only from the EFF large list (12.9 bits each). The separator is any string. "Capitalize" capitalizes every word, not one random chunk. There are no syllable or three-letter lists. |
| Generator ranges | Random 8 to 100, Memorable 3 to 15, PIN 3 to 12 | Done (core/server/CLI) | v1 | Random allows up to 128 characters (minimum one per chosen class), Memorable 3 to 20 words, and PIN 4 to 32 digits. Look-alike characters (0/O, 1/l/I) are excluded. |
| CLI recipe | `--generate-password='letters,digits,symbols,32'` | Done (core/server/CLI) | v1 | `plaintext add --generate` makes a 20-character random password. `plaintext generate --length/--words/--pin/--no-symbols` covers the rest. |
| Suggested password in the browser | "Use Suggested Password" on sign-up forms | Protocol ready, needs app UI | v1 | The core generator is exposed to the extensions through WASM. |
| Generator history | Every generated password kept per site | Protocol ready, needs app UI | v2 | Generated passwords could be stored as items in the Personal vault, or in the keyring's `extra` map. Neither needs server work. |
| Localized memorable generator | Localized word lists | Planned | v2 | Only the English EFF list is embedded in core. |
| iOS AutoFill generation | Generate through AutoFill without unlocking | Protocol ready, needs app UI | v1 | The credential provider extension calls the generator. Saving the result still needs an unlocked Account Key. |
| Username generator | Random or memorable usernames | Planned | v2 | A small addition to `tools.rs`, with no protocol impact. |
| Username suggestions | From Identity items at sign-up | Protocol ready, needs app UI | v2 | The extension can read `identity` items on the device and suggest their usernames and emails. |
| Fastmail Masked Email | Create, regenerate and block aliases at sign-up | Planned | v2 | This is a client-side integration: the user's Fastmail API token is stored as an item and the extension calls Fastmail's API directly, so it needs no protocol work. It is v2 because it depends on the browser extension and serves only users of one paid provider. A provider-neutral version (Fastmail, SimpleLogin, addy.io) would be worth more to self-hosters. |

## 5. Watchtower

All checks run on the device (`tools::watchtower`). Archived items are skipped.

| Feature | 1Password | Plaintext status | Tier | Notes |
|---|---|---|---|---|
| Compromised websites | Breached sites whose password is older than the breach | Planned | v2 | This needs a breach-site feed. The client can download HIBP's public breach list and compare it locally against `urls` and `updated`. No server change is needed. |
| Vulnerable passwords | HIBP Pwned Passwords with k-anonymity | Done (core/server/CLI) | v1 | `plaintext watchtower --breaches` sends only the first 5 hex characters of a SHA-1 hash (`breach_prefix` and `breach_count`). |
| Reused passwords | Grouped by shared password | Done (core/server/CLI) | v1 | `Finding::Reused`. The check covers all vaults on the device, but only the `password` field, not concealed custom fields. |
| Weak passwords | Easy-to-guess passwords | Done (core/server/CLI) | v1 | `Finding::Weak` flags passwords under 50 bits by `strength_bits`, which has no dictionary. |
| Unsecured websites | http:// URLs of sites that support HTTPS; "Use HTTPS" fix | Done (core/server/CLI) | v1 | `Finding::Unsecured` flags every `http://` URL; there is no list of sites known to support HTTPS. The one-click fix is app work. |
| 2FA available | Sites that support 2FA but have no OTP saved | Done (core/server/CLI) | v1 | `Finding::NoTwoFactor` flags every login with URLs and no TOTP. Checking against a 2FA directory feed, fetched by the client, is v2. |
| Passkeys available | Sites that support passkeys but have none saved | Planned | v2 | This needs a passkey directory feed and passkey support itself (section 7). |
| Expiring items | Expired or soon-to-expire items | Planned | v2 | This needs the expiry-alert flag (section 3) and a core check. |
| Items with duplicates | Exact duplicates in one vault | Planned | v2 | A local core check with no protocol change. |
| Items in another account | A login's email belongs to another account | Won't do | won't | Plaintext accounts have no email address, so there is nothing to compare. |
| Imported from LastPass | Logins exposed in the 2022 LastPass breach | Won't do | won't | There is no LastPass importer, and the general breach checks cover it. |
| Developer secrets on disk | Plaintext SSH keys and .env files on disk | Planned | v2 | This fits agent-first use: `plaintext` could scan `~/.ssh` and `.env` files and offer to import them. It is client-only work. |
| Recovery code card | Prompts to set up a recovery code | Won't do | won't | There are no recovery codes. An app card reminding users to save the Emergency Kit replaces it (v1 scope). |
| Watchtower score / Share My Score | A shareable security score | Won't do | won't | This is a marketing feature, and per-item findings say more. |
| Per-item alert banners | A banner on each affected item | Protocol ready, needs app UI | v1 | `tools::watchtower` already returns findings keyed by item id, so the app only has to show them. |
| Breach alerts in browser | Warn on breached sites and weak passwords | Protocol ready, needs app UI | v2 | The extension can run the same core checks through WASM. |
| Ignore / exclude | Ignore on the 2FA banner | Planned | v2 | This needs an item-schema field (see the next row). |
| Per-item Watchtower exclusions (data model) | Seven per-item booleans in `overview.watchtowerExclusions` | Planned | v2 | This needs `watchtower_exclusions` on `Item`. The 1PUX importer doesn't carry the flags over yet. |
| Local checks | Breach and 2FA data downloaded and compared on the device | Done (core/server/CLI) | v1 | Every check is local. The only network request is the HIBP range query, which the client makes directly, not through the Plaintext server. |
| Business Watchtower report | An admin report across shared and employee vaults | Won't do | won't | Admins can't read vaults, so an organisation-wide report could only be built from members' clients reporting on themselves. Each member's own dashboard is the replacement. |

## 6. Autofill

None of this needs server work. It is app and extension work on top of the core (UniFFI for the apps, WASM for the extensions).

| Feature | 1Password | Plaintext status | Tier | Notes |
|---|---|---|---|---|
| Browser extension | Chrome, Firefox, Edge, Brave, Safari; inline menu; pop-up | Protocol ready, needs app UI | v1 | The plan is MV3 extensions using core through WASM, with Safari as a Web Extension inside the Apple apps. |
| Sign-in prompt | A "Sign in" prompt at the top of the page | Protocol ready, needs app UI | v1 | This is extension work on top of the existing item model. |
| Automatic sign-in | Submit after fill, toggled per login | Planned | v2 | The per-item "don't submit" flag needs an item-schema field. |
| Save prompts | Save or update logins, cards, addresses, OTP, passkeys | Protocol ready, needs app UI | v1 | v1 covers new and updated logins. Cards, addresses and the other types follow in v2. Saves go through `Item::edit`, which keeps password history. |
| Multi-page logins | Username on one page, password on the next | Protocol ready, needs app UI | v2 | The extension saves the username first and then updates the same item with the password. |
| Credit cards and addresses | Fill checkout and registration forms | Protocol ready, needs app UI | v2 | The data exists in `card` and `identity` items. Form filling is extension work. |
| TOTP autofill | Fill the OTP after the login; optional auto-copy | Protocol ready, needs app UI | v1 | `tools::totp` supports SHA-1, SHA-256 and SHA-512 with 6 to 10 digits. |
| Autofill behavior per website field | Fill anywhere on the site, exact host only, or never | Planned | v1 | Default eTLD+1 matching needs a public suffix list in core (v1). Per-URL modes need `urls` to become objects carrying a match mode, which is an item-schema change (v2). Bitwarden imports carry a `match` value that the importer currently drops. |
| Suggestion ordering | Favorites first; full URLs rank higher | Protocol ready, needs app UI | v1 | `favorite` is in `Item`, but the CLI has no flag to set it. |
| Autofill confirmation | Ask before filling, against clickjacking | Protocol ready, needs app UI | v2 | This is extension work on top of the existing item model. |
| Sign in with (SSO provider) | Remembers and clicks "Sign in with Google" and others | Planned | v2 | This needs an item-schema field naming the provider. |
| Phishing protection | Warn on pasting into an unsaved site | Protocol ready, needs app UI | v2 | This is extension work on top of the existing item model. |
| Universal Autofill (Mac) | Cmd-\ fills in apps, sudo and the admin password | Protocol ready, needs app UI | v2 | This is macOS app work with no protocol dependency. |
| macOS AutoFill provider | The system AutoFill provider in Safari and apps | Protocol ready, needs app UI | v1 | It shares the AuthenticationServices credential provider extension with iOS. |
| Auto-Type (Windows) | Types the username and password into the active window | Protocol ready, needs app UI | v2 | This is Windows tray app work with no protocol dependency. |
| Quick Access (desktop) | A search-anywhere overlay | Protocol ready, needs app UI | v2 | This is desktop app work, and `Item::matches` already provides the search. |
| iOS/iPadOS AutoFill | Passwords, passkeys, OTP; QuickType bar | Protocol ready, needs app UI | v1 | A credential provider extension that unlocks the Account Key from a shared Keychain group. |
| Android Autofill | Autofill service, app identifier matching | Protocol ready, needs app UI | v1 | An Autofill service, plus a Credential Manager provider for passkeys (section 7). App identifiers need a URL form such as `androidapp://`, which fits in `urls` today. |
| Safari on iPhone/iPad | In-page filling through a Safari web extension | Protocol ready, needs app UI | v2 | The system AutoFill provider covers iOS in v1, so the Safari web extension can wait. |
| Apple Watch | Selected items, OTP complications | Planned | v2 | This needs a per-item "show on Watch" flag (item schema) or a local list on the phone. |
| Copy fallbacks | Copy password or OTP shortcuts; pin fields | Protocol ready, needs app UI | v1 | `plaintext get ITEM --field F` and `pt://…/totp` already cover the CLI. |
| Clipboard clearing | Clears copied data after 90 seconds | Protocol ready, needs app UI | v1 | App work. The CLI prints to stdout and doesn't use the clipboard. |
| Large Type | Show a password in large type | Protocol ready, needs app UI | v2 | This is app work with no protocol dependency. |
| Additional browsers | Trust custom browsers for the extension | Protocol ready, needs app UI | v2 | The native-messaging host would keep an allowlist of trusted browsers. |
| Secure snippets (Labs) | Text snippets filled by shortcut | Won't do | won't | It is a Labs experiment outside password management. |
| Save in 1Password button (for websites) | An npm package sites embed for one-click saving | Won't do | won't | It depends on websites adopting a vendor-specific package. Save prompts cover the need. |

## 7. Passkeys

`Item.passkeys` stores `rp_id`, `credential_id`, `user_handle`, `user_name`, a PKCS#8 `private_key`, `counter`, `created`, and anything else in `extra` (such as `rp_name`, `user_display_name` and `discoverable`). The Bitwarden JSON importer brings passkeys over; one it can't read is kept as it was in the item's `extra.bitwarden_passkeys`. Core has no WebAuthn code yet: no key generation, no authenticatorData or attestation building, and no assertion signing.

| Feature | 1Password | Plaintext status | Tier | Notes |
|---|---|---|---|---|
| Save and sign in with passkeys | Extension, iOS, Android 14+, Windows; passkeys are shareable items | Planned | v1 | Storage exists, and passkeys sync and share like any other item field. Core needs WebAuthn create and get (ES256 key generation, authenticatorData, counter handling) exposed through UniFFI and WASM. The apps need the iOS/macOS credential provider, the Android Credential Manager provider and extension interception of `navigator.credentials`. |
| Fallback to another authenticator | Switch to a security key or the browser's own manager | Planned | v2 | The extension can offer this once it intercepts WebAuthn calls, which needs the core passkey work first. |
| Windows passkey provider | Third-party passkey provider on Windows 11 | Planned | v2 | Needs the core WebAuthn work and the Windows plugin API. |
| Cross-device sign-in | Phone scans a QR code shown on another device | Planned | v2 | The OS hybrid transport calls the phone's credential provider, so this comes with the mobile passkey providers and the core WebAuthn work. |
| Related-origin passkeys | A passkey for one domain works on a related one | Planned | v2 | Core has to fetch and check the RP's `.well-known/webauthn` file. |
| Post-quantum passkeys | Save and use PQ passkeys | Planned | v2 | Needs ML-DSA in core and a `Passkey` algorithm field (item schema). |
| Search and filter | `=passkey` filter | Protocol ready, needs app UI | v2 | The app can filter on items with a non-empty `passkeys` list once passkeys exist. |
| Business policy (passkey saving) | Turn passkey saving on or off | Won't do | won't | Plaintext has no organisation policies (see section 10). |
| Passkey export / Credential Exchange | Import and export through CXP on iOS 26+ and Android | Planned | v2 | This needs a Credential Exchange Format reader and writer in `client`. The Bitwarden JSON exporter drops passkeys today. |
| Unlock 1Password with a passkey (passwordless) | Beta: passkey instead of password plus Secret Key | Won't do | won't | Every key derives from the password plus the Secret Key, and a new device must always need the Secret Key. On known devices, biometric unlock with the Account Key in the OS keychain already gives passwordless unlock. |

## 8. TOTP, SSH, CLI and developer tools

1Password's Service Accounts, Connect, SDKs and secret references map onto Plaintext's agent model. An agent account (`Kind::Agent`, with its controlling human in `owner`) signs in with a 256-bit `ptk_` key and gets no personal vault. Owners give it per-vault reader or writer roles that can expire. The server logs its reads, and the agent asks its owner for more access through the inbox.

| Feature | 1Password | Plaintext status | Tier | Notes |
|---|---|---|---|---|
| One-time passwords | TOTP in Logins or custom fields; QR scan; autofill | Done (core/server/CLI) | v1 | `plaintext totp ITEM` and `pt://Vault/Item/totp` work today, following RFC 6238 with SHA-1, SHA-256 and SHA-512. Only the built-in `totp` field is used; `otp`-typed custom fields aren't read. Scanning a QR code is app work. |
| OTP notifications (iOS) | Notify when an OTP is auto-copied | Protocol ready, needs app UI | v2 | This is app work with no protocol dependency. |
| SSH key management | Generate Ed25519 or RSA, import, export; public key autofill | Planned | v2 | Only storage exists (kind `ssh_key`). Core needs key generation and OpenSSH key parsing and formatting. |
| SSH agent | Serves vault keys to ssh; keys never leave the app | Planned | v2 | A `plaintext ssh-agent` (CLI or desktop app) signing with keys from the vault. No server change is needed. |
| agent.toml | Choose which keys and vaults the agent offers | Planned | v2 | This would be built together with the SSH agent. |
| SSH approval prompts | Approve per app, per session or per request | Planned | v2 | Comes with the SSH agent and needs desktop app UI. |
| SSH agent forwarding / WSL | Forwarding with local approval; WSL integration | Planned | v2 | This would be built together with the SSH agent. |
| SSH Bookmarks (beta) | Connect to hosts from 1Password | Planned | v2 | Low priority. `ssh://` URLs fit in `urls` today. |
| Git commit signing | Configure SSH commit signing | Planned | v2 | This would be built together with the SSH agent. |
| 1Password CLI (`op`) | Items, vaults, users, groups, documents, Connect, service accounts, events | Done (core/server/CLI) | v1 | `plaintext` covers signup/signin/lock, items (ls, get, add, edit, rm), attach and download, vaults (create, rename, members, share, revoke, audit), users (ls, invite, verify, disable), agents, send, link, open, inbox, request, run, inject, import, export, passwd, sessions and mcp. There are no groups or events commands, because the server has neither. |
| Secret references | `op://vault/item/[section/]field`; "Copy Secret Reference" | Done (core/server/CLI) | v1 | `pt://Vault/Item/field` resolves the item by title or id and the field by label, or a built-in (`password`, `username`, `url`, `notes`, `totp`). It has no section segment, and the first matching label wins, so two fields with the same label in different sections are ambiguous. Copying a reference in the app is v1 app work. |
| `op run` | Subprocess with secrets as env vars; `--env-file`; output masked | Done (core/server/CLI) | v1 | `plaintext run [--env-file F] -- cmd` replaces any `pt://` value in the environment and removes `PLAINTEXT_AGENT_KEY` from the child. It doesn't mask output: only the MCP `run_with_secrets` tool replaces secret values in output with `[secret]`. Masking in `run` is planned for v1. |
| `op inject` | Renders `{{ op://... }}` templates; output file mode 0600 | Done (core/server/CLI) | v1 | `plaintext inject [-i F] [-o F]` renders `{{ pt://... }}`. It writes the output file with the default umask rather than 0600, which should be fixed. |
| CLI biometric unlock (app integration) | The CLI unlocks through the desktop app with Touch ID or Windows Hello | Planned | v2 | Today the CLI keeps the Secret Key in the OS keychain and the unlocked session for 12 hours. Biometric unlock needs a local channel to the desktop app. |
| Shell plugins | Authenticate around 100 third-party CLIs with biometrics | Won't do | won't | `plaintext run` with an env file of `pt://` references covers this without maintaining plugins for each tool. |
| Developer Watchtower | Finds unencrypted SSH keys and plaintext .env files | Planned | v2 | Same as "Developer secrets on disk" in section 5. |
| Environments | Per-project secret sets, version history, delivered to apps | Done (core/server/CLI) | v1 | This maps onto existing pieces without a new object: a vault (or items) per project or stage, an env file of `KEY=pt://…` lines checked into the repo, and `plaintext run --env-file`. Version history comes from item history. A dedicated "environment" item kind for .env import and export is v2. |
| Local mounted .env files | A .env file served from memory, never written to disk | Planned | v2 | Needs a FIFO or FUSE mount in the CLI or desktop app. No server work. |
| Environments MCP server | Local stdio MCP that never returns secret values | Done (core/server/CLI) | v1 | `plaintext mcp` offers list_vaults, search_items, get_item (concealed values replaced by `pt://` references), run_with_secrets (output scrubbed), generate_password, create_item (`generate=true` stores a password the model never sees) and request_access. `read_secret` appears only when `PLAINTEXT_MCP_REVEAL=1` is set. This keeps secrets out of the model's context by accident; it is not a boundary against a model that wants a secret (it could run `sh -c 'echo $PW | rev'`, and notes come back in clear). The boundary is the agent account's vault access, enforced by keys. |
| Local MCP server in Developer tab | The desktop app gives AI assistants access to developer tools | Done (core/server/CLI) | v2 | Shipped through the CLI. A settings toggle in the desktop app is v2. |
| Service accounts | Token-scoped access for CI; rate limits | Done (core/server/CLI) | v1 | `plaintext agent create NAME [--vault V --role reader --expires 30d]`. The server logs the agent's vault reads. The owner or an admin can `user disable` it, and `vault revoke` rotates the vault key. There are no rate limits per agent (see Gaps). |
| Connect server | A self-hosted REST server that caches decrypted vault data | Won't do | won't | A Connect server holds decrypted data on a server, which is the trusted server Plaintext's model removes. Run the agent key where the workload runs (CLI, MCP or the `plaintext-client` crate). A Kubernetes injector that wraps `plaintext run` could come later with no protocol work. |
| Credential Broker (public preview) | CI identity checked by OIDC; no token | Won't do | won't | Decryption needs a key that the server never holds. An OIDC-only flow would require the server to keep agent keys, which is escrow. |
| SDKs (Go, JS, Python) | Item, vault, user and sharing operations | Planned | v1 | The `plaintext-client` Rust crate already works as a Rust SDK. UniFFI bindings (Swift, Kotlin) don't exist yet and are v1, because the apps need them. Python, Go and JS bindings, through UniFFI or WASM, are v2. |
| VS Code extension | Insert references; detect plaintext secrets | Planned | v2 | It can be built on the CLI. No protocol work. |
| Secrets Automation | The umbrella for service accounts and Connect | Done (core/server/CLI) | v1 | Agents plus `run`, `inject`, `read` and MCP, as above. |
| Events API / Users API | SIEM feeds; suspend and reactivate users | Done (core/server/CLI) | v2 | `GET /v1/vaults/{id}/audit` serves the last 1,000 entries to owners, `GET /v1/users` lists the whole user directory to any signed-in account, and `POST /v1/users/{name}/disable` lets admins disable anyone and humans disable their own agents. There is no streaming feed, no reactivate endpoint and no account-level events (see Gaps). |

## 9. Sharing and permissions

| Feature | 1Password | Plaintext status | Tier | Notes |
|---|---|---|---|---|
| Item sharing via link | A copy anyone can open; expiry 1 hour to 30 days; email or domain audience; view once | Protocol ready, needs app UI | v1 | Creating links works today with `plaintext link ITEM --expires 7d --views N`, and `plaintext open LINK` opens one; the static viewer page at getplaintext.org isn't built yet (ticket #956). The item is sealed with a random key carried only in the URL `#fragment`. The server enforces a maximum of 30 days and counts views down, and the creator can delete a link. The viewer page is part of v1. Limiting a link to email addresses or a domain isn't possible, because the server has no email (see Gaps). |
| Shared item limits | No files over 250 MB; no update propagation; save to own vault | Done (core/server/CLI) | v1 | A link carries a copy capped at 1 MiB, without attachments or passkeys, so files can't be shared through links. Neither links nor inbox shares propagate later edits. Recipients save inbox items with `plaintext inbox --save ID`. |
| Sharing history | List active and expired links; delete one | Planned | v2 | `DELETE /v1/links/{id}` exists, but there is no endpoint listing a user's links. Clients could keep their own list in the keyring's `extra` map. |
| Sharing policy | Who may share, maximum lifespan, view-once, files | Won't do | won't | There are no organisation policies. The 30-day maximum is enforced by the server for everyone. |
| Vault sharing | Create, name and share vaults; delete | Done (core/server/CLI) | v1 | `plaintext vault create, rename, share USER --role reader/writer/owner --expires 30d, revoke, members`. Each roster version is signed by an owner and hash-linked to the previous one. Members' keys are pinned, with fingerprints to compare. Revoking someone rotates the vault key and re-seals every item. Vaults can't be deleted, because there is no endpoint (see Gaps), and they have no icon (`VaultMeta.extra` can hold one). |
| Per-item sharing to a user (Plaintext) | Not in 1Password, which offers links or vaults | Done (core/server/CLI) | v1 | `plaintext send ITEM --to USER --expires 7d` seals a copy to the recipient's pinned key, signs it, and drops it in their inbox. |
| Vault permissions — Families | Organizers set view, edit and manage permissions per person | Done (core/server/CLI) | v1 | Every vault has its own owners, so no account-wide organizer is needed. |
| Vault permissions — Teams | Allow Viewing, Allow Editing, Allow Managing | Done (core/server/CLI) | v1 | These map to `Role::Reader`, `Writer` and `Owner`, each with an optional `expires`. |
| Vault permissions — Business (12 total) | Separate create, edit, archive, delete, export, print, copy and history permissions | Won't do | won't | Most of these are client-enforced in 1Password, so a modified client ignores them. A reader holds the vault key and can do anything with the data it can read. Writers can't be split into create, edit and delete, because any writer signs whole manifests. |
| Permission enforcement tiers | Cryptographic, server-enforced or client-enforced | Done (core/server/CLI) | v1 | Reading is cryptographic, because you need the vault key. Writing is checked by the server and by every client: a manifest has to be signed by a writer listed in a verified roster. Managing is a signed roster chain that clients verify themselves. None of this relies on clients alone. |
| Default vault permissions policy | Pre-selected permissions when sharing | Won't do | won't | Plaintext has no organisation policies. |
| App access per vault | Limit which apps reach a vault; travel-safe flag; service-account access | Done (core/server/CLI) | v1 | Each agent is its own account, so per-app access means per-agent vault roles. Hiding vaults on a device is Travel Mode (section 11). |
| Collections | Custom groups of vaults across accounts | Protocol ready, needs app UI | v2 | A local grouping that could sync through the keyring's `extra` map. |
| Move / copy (duplicate) items | Between vaults and accounts; shows who gains access | Protocol ready, needs app UI | v1 | A client can put an item in the target vault and delete it from the source, but these are two pushes, not one atomic step. Attachments must be downloaded and uploaded again, because the server stores files per vault. The CLI has no `mv` command yet. |
| Item ownership / credential governance | Admins take over work logins from employee vaults | Won't do | won't | An admin taking over someone's items is key escrow. |

## 10. Accounts, plans, admin

| Feature | 1Password | Plaintext status | Tier | Notes |
|---|---|---|---|---|
| Plans & seats | Families, Teams and Business seat limits and billing | Won't do | won't | Plaintext is self-hosted: no plans, no billing, and as many users as the admin invites. |
| Regions | US, CA and EU data regions | Won't do | won't | Each operator decides where their own server runs. |
| Family organizer | Invites, manages vaults, recovers, bills | Done (core/server/CLI) | v1 | The first account on a server is its admin. It can make invite codes (`user invite`) and disable accounts (`user disable`), and it can't read or recover anyone's data. An invite also proves the invitee's keys, so the inviter marks them verified without a fingerprint check. |
| Guests | Access to a single vault, no private vault | Done (core/server/CLI) | v1 | Any user given a role in just one shared vault is effectively a guest. Every human still gets a Personal vault at signup. |
| Built-in groups | Owners, Administrators, Team Members, Security, Provision Managers | Planned | v2 | Only a per-account `admin` flag exists today, and groups need new protocol (see Custom groups). |
| Custom groups | Groups with vault access and admin permissions | Planned | v2 | A group needs its own key pair, rosters that list a group as a member, wrapped vault keys for the group, and key rotation when a member leaves. This is new protocol (see Gaps). |
| Account recovery | Organizers or admins reset a user's Secret Key and password | Won't do | won't | Recovery by a family organizer or admin is key escrow, which conflicts with the untrusted-server model. The Secret Key and Emergency Kit are the recovery story. |
| Recovery codes | A self-service, reusable recovery code | Won't do | won't | A code that restores access without the password is another unlock path, and a weaker one. The Secret Key and Emergency Kit are the recovery story. |
| Unlock with SSO | OIDC unlock with no Secret Key or Emergency Kit | Won't do | won't | Unlocking through an identity provider means the IdP or the server holds key material, which is escrow. |
| Automated provisioning (SCIM) | Create, suspend and deprovision users from an IdP | Planned | v2 | Suspend and invite map onto existing endpoints. Creating accounts can't be automated, because each user has to generate their own Secret Key. |
| Policies | Password length, 2FA, lockout, Emergency Kit, auto-lock | Planned | v2 | Only server-side settings make sense, such as invite-only signup (already the case) and the per-address signup and failed-login limits open servers already have. The server never sees the password, so a password-length rule can only be enforced by clients. |
| Sharing & permissions policies | Sharing, disk scanning, autofill types, file storage, agentic permissions and more | Won't do | won't | There are no organisation policies. Agent access is controlled per vault by owners. |
| Unlock/auto-lock policy | Presets enforced per platform | Won't do | won't | Each device has its own auto-lock setting (v1 app scope). Admins don't enforce one. |
| Firewall rules | Allow or deny by country, IP or anonymiser | Won't do | won't | That is the reverse proxy's job on a self-hosted server. |
| Managed Travel Mode | Admins turn Travel Mode on per member | Won't do | won't | Travel Mode itself is v2 (section 11). An admin forcing it on a member's devices adds no protection, because admins can't read vaults anyway. |
| Duo | Organisation-wide Duo MFA | Won't do | won't | The Secret Key already acts as the second factor (section 11). |
| Audit log | Events for accounts, devices, items, sharing, groups and more | Done (core/server/CLI) | v1 | `plaintext vault audit V` (owners only, the last 1,000 entries) shows each write (item and delete counts), each roster change, and every vault pull or file download by an agent. Reads are logged per vault, not per item, because a sync pulls the whole vault. The server writes the log itself, so a compromised server could falsify it. Logins, sessions and password changes aren't logged (see Gaps). |
| Reports | Breach, usage, sign-in, device and adoption reports | Won't do | won't | Admins can't see vault contents, so most reports are impossible. Each user sees their own devices (`plaintext sessions`). |
| Insights | Breach checks, password health, usage for owners | Won't do | won't | It is out of scope for the same reason as Reports. |
| Events Reporting | SIEM integrations (Splunk, Datadog and others) | Planned | v2 | An audit export as JSON lines would cover most uses. |
| Employee vault & free Families | Admin-recoverable employee vault plus a linked Families plan | Won't do | won't | An employee vault that admins can recover is escrow, and there is no billing. |
| Device Trust / Extended Device Compliance | osquery-based device checks | Won't do | won't | Device posture checking is out of scope for a password manager. |
| Brex virtual cards | Create and fill Brex vendor cards | Won't do | won't | It is a third-party commercial integration that doesn't fit a self-hosted product. |
| Unified Access / SaaS Manager / Enterprise Password Manager | The enterprise bundle | Won't do | won't | The enterprise bundle is out of scope for a self-hosted password manager. |

## 11. Security model, unlock, app features

| Feature | 1Password | Plaintext status | Tier | Notes |
|---|---|---|---|---|
| Secret Key | Device-held 128-bit key mixed with the password | Done (core/server/CLI) | v1 | `A1-XXXXXXX-…` (128 bits with 2 check characters), generated on the device and never sent. It also determines the account id, so the server stores no email. The CLI keeps it in the OS keychain. |
| Emergency Kit (PDF) | Sign-in address, Secret Key, password blank, Setup Code QR | Protocol ready, needs app UI | v1 | `plaintext signup` prints the Secret Key and server address once. Apps must produce a printable kit with a QR code and say plainly that nothing can be recovered without it. |
| SRP | The password never leaves the device; mutual authentication | Done (core/server/CLI) | v1 | Login signs `account_id ‖ ts` with an Ed25519 key derived from the password and Secret Key. The timestamp must be within ±120 s and newer than the last login, so a captured login can't be replayed. The server stores only the public key and token hashes, and holds nothing equivalent to the password. |
| PBKDF2 | Slows brute-forcing of the account password | Done (core/server/CLI) | v1 | Argon2id with m=64 MiB, t=3, p=1, salted from the Secret Key. The parameters are fixed in the client, so the server can't downgrade them. |
| Two-factor for 1Password account | TOTP, security keys or Duo for sign-in | Won't do | won't | Account 2FA protects only the login, while the Secret Key protects the data itself and can't be bypassed by the server. Device sessions can be listed and ended (`plaintext sessions`). |
| New device setup | Set Up Another Device by QR code or Setup Code | Protocol ready, needs app UI | v1 | An existing device shows a QR code with the server address and Secret Key, and the new device scans it and asks for the password. No server work is needed. |
| Biometric / system unlock | Touch ID, Face ID, Windows Hello, Android biometrics, Linux PolKit | Protocol ready, needs app UI | v1 | The apps keep the session token and Account Key in the OS keychain behind biometrics. `Session::resume` restores a session from them without the password. The password is never stored. |
| Device password/passcode unlock | Mac login password or phone passcode | Protocol ready, needs app UI | v1 | Same mechanism, with the keychain set to accept the device passcode. |
| Unlock with device | 1Password unlocks when the computer unlocks | Protocol ready, needs app UI | v2 | This is desktop app work with no protocol dependency. |
| Auto-lock settings | Idle timeout, lock on sleep, password re-entry interval | Protocol ready, needs app UI | v1 | The CLI stays unlocked for 12 hours or until `plaintext lock`. Apps need their own local settings. |
| Travel Mode | Remove vaults not marked safe for travel from every device | Planned | v2 | Plausible as v2. Hiding vaults on one device and deleting their local snapshots is client-only. Making it hold against a border search needs a server-visible list of hidden vault ids per account, so the server stops serving them until Travel Mode is turned off, plus a check that devices purged their local copies. Vault names live inside encrypted manifests, so the server only ever sees ids. |
| Offline access & sync | Cached data offline; an Offline Items view | Done (core/server/CLI) | v1 | Each device keeps encrypted vault snapshots (`Vault::snapshot`) including the rollback counter, queues local edits, and pushes them on the next sync. When the same item was also changed on the server, the server's copy is saved as a "(conflict)" item. The Offline Items view is app work. |
| Item history | Restore earlier versions; password history | Done (core/server/CLI) | v1 | `Item::edit` keeps the last 10 versions inside the item blob, plus every earlier password, both sealed with the item. There is no restore command in the CLI yet. |
| Archive & Recently Deleted | Archive hides items; deleted items kept for 30 days | Planned | v1 | `archived` exists in `Item` and is imported from 1PUX, but the CLI can't set it. Deletion is immediate and permanent. A `trashed` timestamp in the item schema would give a Recently Deleted list with no server change: any writer purges items older than 30 days. |
| Favorites & tags | Favorites; nested tags | Done (core/server/CLI) | v1 | `tags` (`--tag`) are searchable. `favorite` is in the model but has no CLI flag. Nesting with `/` is a display convention for the apps. |
| Search | Titles, fields and notes; filters by vault, tag, category | Done (core/server/CLI) | v1 | `Item::matches` searches title, username, URLs, tags, notes and non-secret fields, but never concealed values. `plaintext ls QUERY [--vault V]`. Filter syntax is app work. |
| Multiple accounts | Several accounts in one app | CLI done, apps in v1 | v1 | Accounts on any mix of servers (family, work, Plaintext Cloud). CLI: `plaintext account ls/use/remove`, `--account`. Vaults are shared within one server. |
| Import | Browsers, Bitwarden, Dashlane, KeePass, Keeper, LastPass, CSV, 1PUX, Credential Exchange | Done (core/server/CLI) | v1 | `plaintext import`: 1PUX (all categories, files, password history, archived and favorite flags), Bitwarden or Vaultwarden unencrypted JSON (folders become tags, passkeys come along), and CSV from 1Password, Bitwarden, Chrome, Firefox, Safari or anything with recognisable headers. Dashlane, KeePass, Keeper and LastPass have to go through CSV. Credential Exchange is v2. |
| Export | 1PUX or CSV; Credential Exchange with passkeys on iOS | Done (core/server/CLI) | v2 | `plaintext export` writes unencrypted Bitwarden JSON only. It drops files, passkeys, tags, password history, item history and kinds other than login and note. A lossless native export (JSON plus files, optionally sealed) is v2. Bitwarden compatibility stays import and export only. |
| Print | Print items and Wi-Fi QR codes | Protocol ready, needs app UI | v2 | Printing the Emergency Kit is v1. Printing items is v2. |
| Privacy.com cards | Single-use virtual cards at checkout | Won't do | won't | It is a US-only commercial integration that doesn't fit a self-hosted product. |
| Keyboard shortcuts | Global fill, Quick Access, copy | Protocol ready, needs app UI | v2 | This is desktop app work with no protocol dependency. |
| Labs & betas | Labs toggles; beta and nightly channels | Won't do | won't | Release channels belong to the app stores (TestFlight, Play beta). There is no in-app Labs. |
| Guided Setup | Onboarding: autofill, import, practice | Protocol ready, needs app UI | v1 | v1 onboarding covers the Emergency Kit, turning on AutoFill or the extension, and import. |
| Default start screen | Choose the section shown at launch | Protocol ready, needs app UI | v2 | It is a local app setting with no protocol dependency. |
| Browser extension hardening | Sandboxed background, iframe menus, strict CSP, native-messaging link to the app | Protocol ready, needs app UI | v1 | The plan is MV3 with no remote code, plus a native-messaging host so the extension unlocks through the desktop app's keychain. The server never serves code that touches keys. |
| Daily server backups | Vaults and items backed up daily | Planned | v1 | The server is one SQLite file of ciphertext, so an operator can store backups anywhere. v1 only needs documentation (`sqlite3 .backup` or the host's snapshots), not code. |

## 12. Notable 2025–2026 additions

| Feature | 1Password | Plaintext status | Tier | Notes |
|---|---|---|---|---|
| 1Password for Agents | Approve each request; fills Login items into an agent's browser | Done (core/server/CLI) | v1 | Plaintext takes a different approach: an agent has its own account and can reach only the vaults it was given, and `run_with_secrets` uses credentials without the model seeing them. When it needs more, it asks with `request_access`, and the request lands in the owner's inbox. Filling a browser driven by an agent is v2 extension work. |
| 1Password for Claude | Claude asks 1Password to fill logins; Agentic Mode | Protocol ready, needs app UI | v2 | Today the same need is met through `plaintext mcp`. A browser "agentic mode" restricted to approved items depends on the extension. |
| Secure Agentic Autofill policy | A Business policy that turns agentic autofill on | Done (core/server/CLI) | v1 | Each agent's reach is set by vault roles with expiry, rather than by an account-wide policy. |
| Environments + MCP + Credential Broker | See section 8 | Done (core/server/CLI) | v1 | Environments and MCP are covered (section 8). The Credential Broker is Won't do (section 8). |
| Item Usage report from the item | Admins open an item's usage report | Won't do | won't | A sync pulls the whole vault, so the server can't tell which item was read. The CLI and MCP could report their own item reads, but an agent could just skip that, so it isn't evidence. Vault-level agent reads are logged. |
| Default and custom expiry alerts | Category defaults and custom date alerts | Planned | v2 | It is the same work as Expiry alerts in section 3. |
| Bitwarden in-app import / LastPass encrypted-URL import | Import from Bitwarden; decrypt LastPass URLs | Done (core/server/CLI) | v1 | Bitwarden JSON and CSV are done. LastPass is CSV only. |
| Windows ADMX group policy / MDM settings | Managed settings | Won't do | won't | Plaintext has no organisation policies. |
| Touch ID unlock of the Safari extension / extension unlock from a pop-up | Biometric unlock of the extension | Protocol ready, needs app UI | v1 | The Safari extension shares the app's Keychain group. Chrome and Firefox unlock through the native-messaging host. |
| SSH: approve every request; warning for 6+ keys | Per-request SSH approval | Planned | v2 | This would be built together with the SSH agent. |
| Release-channel policy | Limit members to production, beta or nightly | Won't do | won't | Plaintext has no organisation policies. |
| 1Password 7 retirement | 1Password 7 stops syncing in early 2027 | Won't do | won't | It doesn't apply, because Plaintext has no legacy client. |

## Plaintext features 1Password lacks

| Feature | 1Password | Plaintext status | Tier | Notes |
|---|---|---|---|---|
| Key pinning and fingerprints | The server distributes public keys | Done (core/server/CLI) | v1 | Contacts' keys are pinned on first use, and the pins sync in the encrypted keyring. A changed key raises `KeyChanged`. `plaintext user verify USER --yes` marks a fingerprint as compared. Apps should compare fingerprints by QR. |
| Signed, hash-linked rosters and manifests | Membership is server-enforced | Done (core/server/CLI) | v1 | A server can't add a member, swap a key, drop or alter an item, or roll a device back without the device detecting it. |
| Access requests | none | Done (core/server/CLI) | v1 | `plaintext request` and MCP `request_access` send a signed, sealed message that expires after 7 days to the owner's inbox. The owner then grants a role with `vault share`. |
| Agent read audit | Service account usage reports | Done (core/server/CLI) | v1 | The server logs every vault pull and file download by an agent (see Audit log in section 10). |
| Invite proofs | Invites by email | Done (core/server/CLI) | v1 | The invite code carries a secret, and the new account sends an HMAC of its identity made with it, so the inviter can verify the invitee's keys without trusting the server. |

## v1 app scope

Every native app (iOS, Android, macOS with Safari, and the Chrome and Firefox extensions) needs these for launch:

- Sign up and sign in with password and Secret Key, an Emergency Kit (printable, with a QR code) and a clear "no recovery" warning at signup.
- Adding a device by scanning a QR code from an existing one, or by typing the Secret Key.
- Biometric or device-passcode unlock with the Account Key in the OS keychain, plus local auto-lock settings.
- Offline sync through the `plaintext-client` crate over UniFFI or WASM, with conflict copies and clear errors for `KeyChanged`, `Rollback` and `ManifestMismatch`.
- Viewing and editing every item kind through the generic section and field editor, with templates for Login, Password, Secure Note, Credit Card, Identity and Document, Markdown notes, favorites, tags and archive.
- A Recently Deleted list (the `trashed` item field) so that deleting an item isn't instantly permanent.
- The password generator (random, memorable, PIN) with a strength meter.
- One-time codes: showing, copying, filling, and adding by QR scan.
- Autofill for logins and OTP: the iOS and macOS credential provider, the Android Autofill service, and the Safari, Chrome and Firefox extensions with eTLD+1 matching.
- Passkeys: saving and signing in through the same providers and extensions (needs the core WebAuthn work).
- Copying with clipboard clearing, and showing password and item history.
- Uploading and downloading attachments.
- Watchtower: weak, reused, unsecured, missing 2FA and HIBP breach checks, shown as per-item banners.
- Sharing: vault members with roles and expiry, revoking, comparing fingerprints by QR, sending items to a user's inbox, share links with expiry and view limits (plus the getplaintext.org viewer page), and approving agents' access requests.
- Import from 1PUX, Bitwarden JSON and CSV, a device list with sign-out, and creating agents.

## Gaps in the protocol

The following would need new protocol, schema or server work to match 1Password.

**Item schema additions.** These need no server change, because unknown fields survive older clients, but core should define them before the apps freeze their models.

- A `trashed` timestamp for Recently Deleted.
- URL objects with a match mode (domain, exact host, never), a per-item "don't auto-submit" flag, and a "Sign in with" provider.
- A reference field type holding an item id, for related items.
- Stable field ids, so `pt://` references survive renamed labels, and a section segment in `pt://`.
- Watchtower exclusions per item, and an expiry-alert flag on `date` fields.
- An item location, an Apple Watch flag, and a passkey algorithm field for post-quantum keys.
- A convention for custom templates stored as items.

**Core work.** None of this changes the wire protocol.

- WebAuthn registration and assertion for stored passkeys, and related-origin checks.
- A public suffix list for autofill matching.
- SSH key generation, OpenSSH formats and an ssh-agent.
- A username generator, localized word lists, and memorable options matching 1Password's.
- A lossless native export, and Credential Exchange import and export.
- Watchtower checks for duplicates and expiring items, plus client-fetched breached-site, 2FA and passkey directory feeds.

**Wire and server changes.**

- **Groups.** A group key pair, rosters that can list groups, vault keys wrapped to groups, and rotation when a group member leaves.
- **Per-item permissions.** Today permissions are per vault only. Per-item access would need per-item keys and per-item rosters. The cheaper answer is a separate vault or `send`.
- **Vault deletion.** There is no endpoint.
- **Atomic cross-vault move.** Today a move is two pushes, and files are stored per vault, so attachments are uploaded again.
- **Larger attachments.** Chunked or streaming uploads instead of one 64 MiB body held in memory, and storage outside SQLite.
- **Share links.** An endpoint listing a user's links (sharing history), links that carry files (blobs are capped at 1 MiB), and any recipient restriction. Email-verified recipients conflict with the no-email design, but a passphrase-protected link would not.
- **Travel Mode.** A server-visible list of hidden vault ids per account, enforced on pull, and confirmation that devices purged their local copies.
- **Audit.** Account-level events (logins, sessions, password changes, invites), a reactivate endpoint for disabled users, and a streaming or exportable feed. Item-level read auditing isn't possible while a sync pulls the whole vault.
- **Agent limits.** Rate limits per agent, and optional IP allowlists for agent sessions.
- **Server policies.** Lockout and limits on invite-only servers (open servers already limit signups and failed logins per address), and SCIM endpoints for invite and suspend.
- **Fork detection.** Devices can be split onto different branches by the server. Detecting this needs devices to compare their manifest heads, for example through gossip inside the vault (a known limit in DESIGN.md).
