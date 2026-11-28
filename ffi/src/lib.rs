//! The native apps' bridge to Rust (UniFFI, for Swift and Kotlin). One
//! `PlaintextApp` object signs in, syncs through `plaintext-client`, keeps this
//! device's sealed state in a folder, and hands the app plain records. Crypto,
//! sync and sharing rules stay in Rust; the apps only draw screens.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

use plaintext_client::plaintext_core::api::{Hex, Identity, Kind, Role as CoreRole};
use plaintext_client::plaintext_core::crypto::{SecretKey, derive};
use plaintext_client::plaintext_core::item::{Field, Item, Section};
use plaintext_client::plaintext_core::{self as core, Account, Content, tools};
use plaintext_client::{Error as ClientError, Http, Session, Transport, import, now, now_ms};
use zeroize::Zeroizing;

uniffi::setup_scaffolding!();

type S = Session<Http>;

// ---------- Errors ----------

#[derive(Debug, uniffi::Error)]
#[uniffi(flat_error)]
pub enum PlaintextError {
    /// The server couldn't be reached.
    Network { message: String },
    /// The server ended this device's session (signed out elsewhere, password
    /// changed, account disabled): sign in with the password again.
    SignedOut,
    /// The password and Secret Key don't open this account.
    WrongPassword,
    BadSecretKey,
    BadInvite,
    BadUsername,
    /// Someone's keys differ from the ones pinned for them.
    KeyChanged { username: String },
    /// The server served an older or different copy than this device has seen.
    Rollback,
    /// The server's vault doesn't match its signed manifest.
    ManifestMismatch,
    ReadOnly,
    Server { code: u16, message: String },
    NotFound { message: String },
    Invalid { message: String },
    /// Nobody is signed in on this device right now.
    Locked,
}

impl std::fmt::Display for PlaintextError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use PlaintextError::*;
        match self {
            Network { .. } => f.write_str("Couldn't reach your server. Your items are still here, and changes sync when it's back."),
            SignedOut => f.write_str("This device was signed out. Enter your password to sign in again."),
            WrongPassword => f.write_str("That password didn't match. Check it and your Secret Key, then try again."),
            BadSecretKey => f.write_str("That Secret Key is mistyped. It starts with A1 and is on your Emergency Kit."),
            BadInvite => f.write_str("That invite code is mistyped. Ask for a new one."),
            BadUsername => f.write_str("Usernames are 2–32 lowercase letters, digits, dots, dashes or underscores."),
            KeyChanged { username } => write!(f, "{username}'s keys changed since you last saw them. Compare fingerprints with them before trusting them again."),
            Rollback => f.write_str("Your server sent an older copy of a vault than this device has seen, so nothing was changed. Contact whoever runs your server."),
            ManifestMismatch => f.write_str("Your server's copy of a vault doesn't match what its members signed, so nothing was changed. Contact whoever runs your server."),
            ReadOnly => f.write_str("You can only view this vault."),
            Server { message, .. } => write!(f, "The server said: {message}"),
            NotFound { message } => write!(f, "Couldn't find {message}."),
            Invalid { message } => f.write_str(&capitalize(message)),
            Locked => f.write_str("Plaintext is locked."),
        }
    }
}

impl std::error::Error for PlaintextError {}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    let mut out: String = c.next().map(|f| f.to_uppercase().chain(c).collect()).unwrap_or_default();
    if !out.ends_with('.') {
        out.push('.');
    }
    out
}

impl From<core::Error> for PlaintextError {
    fn from(e: core::Error) -> Self {
        use core::Error as E;
        match e {
            E::KeyChanged(username) => PlaintextError::KeyChanged { username },
            E::Rollback => PlaintextError::Rollback,
            E::ManifestMismatch => PlaintextError::ManifestMismatch,
            // Wrong-password paths map it themselves (`password_error`).
            E::Tampered => PlaintextError::Invalid { message: "this data didn't check out: it was damaged or changed on its way".into() },
            E::BadSecretKey => PlaintextError::BadSecretKey,
            E::BadInvite => PlaintextError::BadInvite,
            E::BadUsername => PlaintextError::BadUsername,
            E::ReadOnly => PlaintextError::ReadOnly,
            e => PlaintextError::Invalid { message: e.to_string() },
        }
    }
}

impl From<ClientError> for PlaintextError {
    fn from(e: ClientError) -> Self {
        match e {
            ClientError::Core(e) => e.into(),
            ClientError::Server(401, _) => PlaintextError::SignedOut,
            ClientError::Server(code, message) => PlaintextError::Server { code, message: server_message(&message) },
            ClientError::Network(message) => PlaintextError::Network { message },
            ClientError::NotFound(message) => PlaintextError::NotFound { message },
            ClientError::Refused(message) => PlaintextError::Invalid { message },
        }
    }
}

/// Signing in or changing the password: a refusal or a key that doesn't open
/// means the password (or Secret Key) is wrong.
fn password_error(e: ClientError) -> PlaintextError {
    match e {
        ClientError::Server(401 | 403, _) | ClientError::Core(core::Error::Tampered) => PlaintextError::WrongPassword,
        e => e.into(),
    }
}

/// A damaged copy on this device (`Session::load_local`) is replaced on the next
/// save, as the CLI does: say so, but don't keep the account locked. Call after
/// the first sync, which clears `problems`.
fn local_warning(s: &mut S, loaded: Result<(), ClientError>) {
    // Only a copy that doesn't open: a failed upload of the merged keyring is retried by the next sync.
    if let Err(ClientError::Core(_)) = loaded {
        s.problems.push("this device's saved copy couldn't be read, so it was replaced with the server's".into());
    }
}

/// The server's error text, without JSON wrapping.
fn server_message(raw: &str) -> String {
    serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(String::from))
        .unwrap_or_else(|| raw.trim().to_string())
}

impl From<import::ImportError> for PlaintextError {
    fn from(e: import::ImportError) -> Self {
        PlaintextError::Invalid { message: e.to_string() }
    }
}

impl From<std::io::Error> for PlaintextError {
    fn from(e: std::io::Error) -> Self {
        PlaintextError::Invalid { message: format!("couldn't save on this device: {e}") }
    }
}

type Res<T> = Result<T, PlaintextError>;

fn hex_id(s: &str) -> Res<Hex> {
    s.parse().map_err(|_| PlaintextError::NotFound { message: "that item".into() })
}

// ---------- Records ----------

/// What the keychain keeps to unlock without the password (behind biometrics).
#[derive(uniffi::Record, Clone)]
pub struct UnlockData {
    pub token: String,
    pub account_id: Vec<u8>,
    pub account_key: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct SignupResult {
    pub account: AccountInfo,
    /// Show once, on the Emergency Kit.
    pub secret_key: String,
    pub unlock: UnlockData,
    /// The server showed keys for whoever sent the invite that don't match the
    /// invite: show it next to the Emergency Kit.
    pub warning: Option<String>,
}

#[derive(uniffi::Record)]
pub struct LoginResult {
    pub account: AccountInfo,
    pub unlock: UnlockData,
}

/// What a server allows before anyone signs in (`GET /v1/info`).
#[derive(uniffi::Record, Debug, PartialEq)]
pub struct ServerInfo {
    pub version: String,
    /// Anyone may sign up; otherwise an invite is needed.
    pub open: bool,
    /// The server has no accounts yet: the first one needs the setup code.
    pub setup: bool,
}

/// One signed-in account. `id` names it in every call that acts as someone.
#[derive(uniffi::Record, Clone, Debug)]
pub struct AccountInfo {
    pub id: String,
    pub server: String,
    pub username: String,
    pub admin: bool,
    pub fingerprint: String,
    /// Edits made offline that haven't reached the server yet.
    pub pending: bool,
    /// What the last sync couldn't do: vaults that didn't verify (kept as last
    /// verified) and invite conflicts. Show them; the other vaults synced.
    pub problems: Vec<String>,
    /// For each problem, the vault whose unsent changes it says can't be sent
    /// (you may only read it now): `unsent_changes` shows them, `discard_changes`
    /// drops them.
    pub problem_unsent: Vec<Option<String>>,
}

/// This device's changes to a vault that haven't reached the server, to show
/// before `discard_changes` drops them.
#[derive(uniffi::Record, Debug, PartialEq)]
pub struct UnsentChanges {
    pub name: String,
    /// Titles of the items added or edited here.
    pub changed: Vec<String>,
    /// How many items were deleted here.
    pub deleted: u32,
    /// The vault's name or description changed here.
    pub renamed: bool,
}

#[derive(uniffi::Enum, Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    Reader,
    Writer,
    Owner,
}

impl From<CoreRole> for Role {
    fn from(r: CoreRole) -> Self {
        match r {
            CoreRole::Reader => Role::Reader,
            CoreRole::Writer => Role::Writer,
            CoreRole::Owner => Role::Owner,
        }
    }
}

impl From<Role> for CoreRole {
    fn from(r: Role) -> Self {
        match r {
            Role::Reader => CoreRole::Reader,
            Role::Writer => CoreRole::Writer,
            Role::Owner => CoreRole::Owner,
        }
    }
}

#[derive(uniffi::Record, Clone)]
pub struct VaultInfo {
    pub account_id: String,
    pub id: String,
    pub name: String,
    pub item_count: u32,
    /// None when access expired.
    pub role: Option<Role>,
    pub members: Vec<String>,
    /// Made by this account (the only kind new items go to by default).
    pub own: bool,
    pub is_default: bool,
}

#[derive(uniffi::Record)]
pub struct MemberInfo {
    pub username: String,
    pub role: Role,
    pub expires: Option<u64>,
    pub verified: bool,
    pub fingerprint: String,
    pub is_me: bool,
}

#[derive(uniffi::Record, Clone)]
pub struct ItemSummary {
    pub account_id: String,
    pub vault_id: String,
    pub vault_name: String,
    pub id: String,
    pub kind: String,
    pub title: String,
    /// Username, a card's last four, or the start of a note.
    pub subtitle: String,
    pub favorite: bool,
    pub archived: bool,
    pub has_username: bool,
    pub has_password: bool,
    pub has_totp: bool,
    pub tags: Vec<String>,
    /// Unix milliseconds.
    pub updated: u64,
}

#[derive(uniffi::Record, Clone, Debug, PartialEq)]
pub struct FieldData {
    pub label: String,
    /// `text`, `concealed`, `url`, `email`, `phone`, `date`, `month_year`, `otp`,
    /// `address`, `menu`, `card_number`, `card_type`, `ssh_key`, `boolean`.
    pub kind: String,
    pub value: String,
    /// Unknown properties from newer apps, kept as they were. Pass back unchanged.
    pub extra_json: String,
}

#[derive(uniffi::Record, Clone, Debug, PartialEq)]
pub struct SectionData {
    pub title: String,
    pub fields: Vec<FieldData>,
}

#[derive(uniffi::Record, Clone, Debug, PartialEq)]
pub struct FileData {
    pub id: String,
    pub name: String,
    pub size: u64,
}

#[derive(uniffi::Record, Clone, Debug, PartialEq)]
pub struct OldPasswordData {
    pub password: String,
    pub changed: u64,
}

#[derive(uniffi::Record, Clone, Debug, PartialEq)]
pub struct VersionData {
    pub title: String,
    /// When this version was saved (Unix ms).
    pub updated: u64,
}

/// An item as the app edits it. Saving goes through `put_item`, which applies
/// these fields onto the stored item, so anything the app doesn't know about
/// (passkeys, newer fields, attachment keys) survives.
#[derive(uniffi::Record, Clone, Debug, PartialEq)]
pub struct ItemData {
    pub kind: String,
    pub title: String,
    pub username: String,
    pub password: String,
    pub urls: Vec<String>,
    pub totp: String,
    pub notes: String,
    pub sections: Vec<SectionData>,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub archived: bool,
    /// Attachments to keep; add new ones with `attach_file`.
    pub files: Vec<FileData>,
    pub password_history: Vec<OldPasswordData>,
    /// Earlier versions, newest first (restore with `restore_version`).
    pub history: Vec<VersionData>,
    pub created: u64,
    pub updated: u64,
}

fn item_data(i: &Item) -> ItemData {
    ItemData {
        kind: i.kind.clone(),
        title: i.title.clone(),
        username: i.username.clone(),
        password: i.password.clone(),
        urls: i.urls.clone(),
        totp: i.totp.clone(),
        notes: i.notes.clone(),
        sections: i
            .sections
            .iter()
            .map(|s| SectionData {
                title: s.title.clone(),
                fields: s
                    .fields
                    .iter()
                    .map(|f| FieldData {
                        label: f.label.clone(),
                        kind: f.kind.clone(),
                        value: f.value.clone(),
                        extra_json: if f.extra.is_empty() { String::new() } else { serde_json::to_string(&f.extra).unwrap_or_default() },
                    })
                    .collect(),
            })
            .collect(),
        tags: i.tags.clone(),
        favorite: i.favorite,
        archived: i.archived,
        files: i.files.iter().map(|f| FileData { id: f.id.to_string(), name: core::item::safe_file_name(&f.name), size: f.size }).collect(),
        password_history: i.password_history.iter().map(|p| OldPasswordData { password: p.password.clone(), changed: p.changed }).collect(),
        history: i
            .history
            .iter()
            .map(|v| VersionData {
                title: v.get("title").and_then(|t| t.as_str()).unwrap_or_default().to_string(),
                updated: v.get("updated").and_then(|t| t.as_u64()).unwrap_or_default(),
            })
            .collect(),
        created: i.created,
        updated: i.updated,
    }
}

/// `d` applied onto `base` (the stored item, or a new one): everything the
/// record doesn't carry is kept from `base`.
fn apply(base: &Item, d: ItemData) -> Item {
    let mut next = base.clone();
    next.history.clear();
    next.kind = d.kind;
    next.title = d.title;
    next.username = d.username;
    next.password = d.password;
    next.urls = d.urls.into_iter().map(|u| u.trim().to_string()).filter(|u| !u.is_empty()).collect();
    next.totp = d.totp.trim().to_string();
    next.notes = d.notes;
    next.sections = d
        .sections
        .into_iter()
        .map(|s| Section {
            title: s.title,
            fields: s
                .fields
                .into_iter()
                .map(|f| Field { label: f.label, kind: f.kind, value: f.value, extra: serde_json::from_str(&f.extra_json).unwrap_or_default() })
                .collect(),
        })
        .filter(|s| !s.fields.is_empty() || !s.title.is_empty())
        .collect();
    next.tags = d.tags.into_iter().map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect();
    next.favorite = d.favorite;
    next.archived = d.archived;
    // Attachments change only through `attach_file` and `remove_file`: an editor
    // open meanwhile mustn't drop a file another device just attached.
    next
}

fn subtitle(i: &Item) -> String {
    let field = |name: &str| i.field(name).filter(|v| !v.is_empty()).map(String::from);
    match i.kind.as_str() {
        "card" => field("number").map(|n| {
            let digits: String = n.chars().filter(char::is_ascii_digit).collect();
            format!("•••• {}", &digits[digits.len().saturating_sub(4)..])
        }),
        "note" => i.notes.lines().find(|l| !l.trim().is_empty()).map(|l| l.chars().take(80).collect()),
        "identity" => {
            let name = [field("first name"), field("last name")].into_iter().flatten().collect::<Vec<_>>().join(" ");
            (!name.is_empty()).then_some(name).or(field("email"))
        }
        _ => None,
    }
    .or_else(|| (!i.username.is_empty()).then(|| i.username.clone()))
    .or_else(|| i.urls.first().map(|u| host(u)))
    .or_else(|| {
        let concealed = |k: &str| matches!(k, "concealed" | "ssh_key" | "otp");
        i.sections.iter().flat_map(|s| &s.fields).find(|f| !concealed(&f.kind) && !f.value.is_empty()).map(|f| f.value.chars().take(80).collect())
    })
    .unwrap_or_default()
}

/// `https://www.example.com/login` → `www.example.com`.
fn host(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    rest.split(['/', '?', '#']).next().unwrap_or(rest).to_string()
}

#[derive(uniffi::Record)]
pub struct KindInfo {
    pub id: String,
    pub name: String,
}

#[derive(uniffi::Enum, Clone, Copy, PartialEq, Eq, Debug)]
pub enum Finding {
    Weak,
    Reused,
    Unsecured,
    NoTwoFactor,
}

#[derive(uniffi::Record)]
pub struct WatchItem {
    pub account_id: String,
    pub vault_id: String,
    pub id: String,
    pub title: String,
    pub subtitle: String,
    pub findings: Vec<Finding>,
    /// For reused passwords: how many other items share it.
    pub reused_with: u32,
}

#[derive(uniffi::Record)]
pub struct TotpCode {
    pub code: String,
    /// Seconds until it changes.
    pub remaining: u64,
    pub period: u64,
    /// The code after this one (show it in the last seconds).
    pub next: String,
}

#[derive(uniffi::Enum, Clone, PartialEq, Debug)]
pub enum Recipe {
    Random { length: u32, digits: bool, symbols: bool },
    Memorable { words: u32, separator: String, capitalize: bool },
    Pin { length: u32 },
}

#[derive(uniffi::Record)]
pub struct Strength {
    pub bits: f64,
    /// 0 weak, 1 fair, 2 good, 3 strong.
    pub level: u8,
}

#[derive(uniffi::Record)]
pub struct UserData {
    pub username: String,
    pub is_agent: bool,
    pub owner: Option<String>,
    pub admin: bool,
    pub disabled: bool,
    pub verified: bool,
}

#[derive(uniffi::Record)]
pub struct AgentAccess {
    pub vault_id: String,
    pub vault_name: String,
    pub role: Role,
    pub expires: Option<u64>,
}

/// A new agent's key (show it once) and, when giving it the vault failed, why.
#[derive(uniffi::Record)]
pub struct NewAgentKey {
    pub key: String,
    pub warning: Option<String>,
}

#[derive(uniffi::Record)]
pub struct AgentInfo {
    pub name: String,
    pub disabled: bool,
    pub access: Vec<AgentAccess>,
    /// Latest audit entry by the agent in a vault you own (Unix seconds).
    pub last_active: Option<u64>,
}

#[derive(uniffi::Record)]
pub struct AuditData {
    pub ts: u64,
    pub username: String,
    pub action: String,
}

#[derive(uniffi::Record)]
pub struct SessionData {
    pub id: String,
    pub device: String,
    pub created: u64,
    pub current: bool,
}

// Records cross the FFI by value, so boxing the big variant buys nothing.
#[allow(clippy::large_enum_variant)]
#[derive(uniffi::Enum, Clone, PartialEq, Debug)]
pub enum InboxContent {
    Item { item: ItemData },
    Request { text: String },
    /// It failed verification or expired; show why.
    Unreadable { reason: String },
}

#[derive(uniffi::Record)]
pub struct InboxEntry {
    /// Empty for unreadable messages.
    pub id: String,
    pub from: String,
    pub verified: bool,
    pub from_agent_of_mine: bool,
    pub content: InboxContent,
    pub expires: Option<u64>,
}

#[derive(uniffi::Enum, Clone, Copy)]
pub enum ImportFormat {
    OnePux,
    Bitwarden,
    Csv,
}

#[derive(uniffi::Record, Debug, PartialEq)]
pub struct DeviceCode {
    pub server: String,
    pub username: String,
    pub secret_key: String,
}

#[derive(uniffi::Record, Debug, PartialEq)]
pub struct InviteLink {
    pub server: Option<String>,
    pub code: String,
}

// ---------- Shared formats (QR codes and links; Android must match) ----------

const DEVICE: &str = "plaintext:device:";
const VERIFY: &str = "plaintext:verify:";
const INVITE: &str = "plaintext:invite:";

/// The "add a device" QR: server, username and Secret Key.
#[uniffi::export]
pub fn device_code(server: String, username: String, secret_key: String) -> String {
    format!("{DEVICE}{username}:{secret_key}:{server}")
}

#[uniffi::export]
pub fn parse_device_code(code: String) -> Option<DeviceCode> {
    let mut parts = code.trim().strip_prefix(DEVICE)?.splitn(3, ':');
    let (username, sk, server) = (parts.next()?, parts.next()?, parts.next()?);
    let sk = SecretKey::parse(sk).ok()?;
    // The same address rules as typing it: no plain http:// to public hosts.
    let server = server_address(server.into()).ok()?.url;
    core::identity::valid_username(username).then(|| DeviceCode { server, username: username.into(), secret_key: sk.encode() })
}

/// An invite as a link or QR: `plaintext:invite:<code>:<server>`. A bare code
/// (or a server setup code) parses too, without a server.
#[uniffi::export]
pub fn invite_link(server: String, code: String) -> String {
    format!("{INVITE}{code}:{server}")
}

#[uniffi::export]
pub fn parse_invite_link(link: String) -> Option<InviteLink> {
    let link = link.trim();
    if let Some(rest) = link.strip_prefix(INVITE) {
        let (code, server) = rest.split_once(':')?;
        return Some(InviteLink { server: Some(server.into()), code: code.into() });
    }
    (!link.is_empty() && !link.contains(char::is_whitespace)).then(|| InviteLink { server: None, code: link.into() })
}

fn verify_code(username: &str, fingerprint: &str) -> String {
    format!("{VERIFY}{username}:{}", fingerprint.replace(' ', ""))
}

// ---------- Tools (no account needed) ----------

#[uniffi::export]
pub fn generate_password(recipe: Recipe) -> String {
    tools::generate(&match recipe {
        Recipe::Random { length, digits, symbols } => tools::Recipe::Random { length, digits, symbols },
        Recipe::Memorable { words, separator, capitalize } => tools::Recipe::Memorable { words, separator, capitalize },
        Recipe::Pin { length } => tools::Recipe::Pin { length },
    })
}

/// Below 50 bits is what Watchtower calls weak.
#[uniffi::export]
pub fn password_strength(password: String) -> Strength {
    let bits = tools::strength_bits(&password);
    let level = match bits {
        b if b < 50.0 => 0,
        b if b < 70.0 => 1,
        b if b < 100.0 => 2,
        _ => 3,
    };
    Strength { bits, level }
}

/// The current one-time code for an `otpauth://` URI or base32 secret.
#[uniffi::export]
pub fn totp_code(spec: String) -> Option<TotpCode> {
    let t = now();
    let (code, remaining) = tools::totp(&spec, t)?;
    let (next, _) = tools::totp(&spec, t + remaining)?;
    let period = spec.split(['?', '&']).find_map(|kv| kv.strip_prefix("period=")).and_then(|v| v.parse().ok()).unwrap_or(30);
    Some(TotpCode { code, remaining, period, next })
}

/// The Secret Key in its canonical form, or why it's wrong.
#[uniffi::export]
pub fn normalize_secret_key(secret_key: String) -> Res<String> {
    Ok(SecretKey::parse(&secret_key)?.encode())
}

#[uniffi::export]
pub fn valid_username(username: String) -> bool {
    core::identity::valid_username(&username)
}

/// The item kinds the app offers, in picker order.
#[uniffi::export]
pub fn item_kinds() -> Vec<KindInfo> {
    KINDS.iter().map(|(id, name, _)| KindInfo { id: (*id).into(), name: (*name).into() }).collect()
}

/// A new item of `kind` with its built-in fields (1Password's lists).
#[uniffi::export]
pub fn item_template(kind: String) -> ItemData {
    let fields = KINDS.iter().find(|(id, _, _)| *id == kind).map(|(_, _, f)| *f).unwrap_or(&[]);
    let mut sections: Vec<SectionData> = Vec::new();
    for (section, label, ty) in fields {
        if sections.last().is_none_or(|s| s.title != *section) {
            sections.push(SectionData { title: (*section).into(), fields: vec![] });
        }
        let f = FieldData { label: (*label).into(), kind: (*ty).into(), value: String::new(), extra_json: String::new() };
        sections.last_mut().expect("pushed above").fields.push(f);
    }
    let mut i = item_data(&Item { kind: kind.clone(), ..Default::default() });
    i.sections = sections;
    i
}

type Template = &'static [(&'static str, &'static str, &'static str)];

/// (id, name, [(section, label, type)]). Logins and passwords use the built-in
/// username/password/URL/one-time code fields instead of sections.
const KINDS: &[(&str, &str, Template)] = &[
    ("login", "Login", &[]),
    ("password", "Password", &[]),
    ("note", "Secure Note", &[]),
    (
        "card",
        "Credit Card",
        &[
            ("", "Cardholder name", "text"),
            ("", "Type", "card_type"),
            ("", "Number", "card_number"),
            ("", "Verification number", "concealed"),
            ("", "Expiry date", "month_year"),
            ("", "Valid from", "month_year"),
            ("", "PIN", "concealed"),
        ],
    ),
    (
        "identity",
        "Identity",
        &[
            ("Identification", "First name", "text"),
            ("Identification", "Last name", "text"),
            ("Identification", "Birth date", "date"),
            ("Identification", "Occupation", "text"),
            ("Address", "Address", "address"),
            ("Contact", "Email", "email"),
            ("Contact", "Phone", "phone"),
        ],
    ),
    ("document", "Document", &[]),
    ("ssh_key", "SSH Key", &[("", "Private key", "ssh_key"), ("", "Public key", "text"), ("", "Fingerprint", "text")]),
    (
        "api_credential",
        "API Credential",
        &[("", "Username", "text"), ("", "Credential", "concealed"), ("", "Type", "menu"), ("", "Hostname", "text"), ("", "Expires", "date")],
    ),
    (
        "bank",
        "Bank Account",
        &[
            ("", "Bank name", "text"),
            ("", "Name on account", "text"),
            ("", "Type", "menu"),
            ("", "Routing number", "text"),
            ("", "Account number", "concealed"),
            ("", "SWIFT", "text"),
            ("", "IBAN", "concealed"),
            ("", "PIN", "concealed"),
        ],
    ),
    (
        "database",
        "Database",
        &[
            ("", "Type", "menu"),
            ("", "Server", "text"),
            ("", "Port", "text"),
            ("", "Database", "text"),
            ("", "Username", "text"),
            ("", "Password", "concealed"),
        ],
    ),
    ("server", "Server", &[("", "URL", "url"), ("", "Username", "text"), ("", "Password", "concealed")]),
    ("wifi", "Wi-Fi", &[("", "Network name", "text"), ("", "Wireless password", "concealed"), ("", "Security", "menu")]),
    (
        "passport",
        "Passport",
        &[
            ("", "Full name", "text"),
            ("", "Number", "text"),
            ("", "Issuing country", "text"),
            ("", "Nationality", "text"),
            ("", "Date of birth", "date"),
            ("", "Issued on", "date"),
            ("", "Expiry date", "date"),
        ],
    ),
    (
        "driver_license",
        "Driver License",
        &[
            ("", "Full name", "text"),
            ("", "Number", "text"),
            ("", "License class", "text"),
            ("", "State", "text"),
            ("", "Country", "text"),
            ("", "Date of birth", "date"),
            ("", "Expiry date", "date"),
        ],
    ),
    (
        "membership",
        "Membership",
        &[("", "Group", "text"), ("", "Member name", "text"), ("", "Member ID", "text"), ("", "Member since", "month_year"), ("", "PIN", "concealed")],
    ),
    (
        "crypto_wallet",
        "Crypto Wallet",
        &[("", "Recovery phrase", "concealed"), ("", "Password", "concealed"), ("", "Wallet address", "text")],
    ),
    (
        "software_license",
        "Software License",
        &[("", "License key", "concealed"), ("", "Licensed to", "text"), ("", "Registered email", "email"), ("", "Version", "text")],
    ),
];

// ---------- Servers ----------

/// The hosted server's address. One constant until the final one is decided.
pub const CLOUD: &str = "https://vault.getplaintext.org";

#[uniffi::export]
pub fn cloud_server() -> String {
    CLOUD.into()
}

/// The default share-link page (a setting: self-hosters can host their own copy).
#[uniffi::export]
pub fn default_link_page() -> String {
    plaintext_client::LINK_PAGE.into()
}

#[derive(uniffi::Record, Debug, PartialEq)]
pub struct ServerAddress {
    /// What to connect to and sign logins for: `https://host[:port]`.
    pub url: String,
    /// Plain `http://`, allowed on local and private networks only: warn that
    /// anyone on the network can see which server is used.
    pub insecure: bool,
}

/// Check and normalize an address the user typed (a domain, an IP or a
/// Tailscale name, with an optional port). No scheme means `https://`.
#[uniffi::export]
pub fn server_address(address: String) -> Res<ServerAddress> {
    let a = address.trim().trim_end_matches('/');
    let (scheme, rest) = match a.split_once("://") {
        Some((s, r)) => (s.to_lowercase(), r),
        None => ("https".into(), a),
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let bad = || PlaintextError::Invalid { message: "that isn't a server address. Type a domain, an IP address or a Tailscale name".into() };
    if host.is_empty() || host.contains(char::is_whitespace) || host.contains('@') || !matches!(scheme.as_str(), "http" | "https") {
        return Err(bad());
    }
    let name = match host.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or_default(),
        None => host.rsplit_once(':').filter(|(_, p)| p.parse::<u16>().is_ok()).map_or(host, |(h, _)| h),
    }
    .to_lowercase();
    if name.is_empty() {
        return Err(bad());
    }
    let insecure = scheme == "http";
    if insecure && !local_host(&name) {
        return Err(PlaintextError::Invalid {
            message: "use https:// for this server. Plain http:// only works for localhost, private networks and .local or .ts.net names".into(),
        });
    }
    Ok(ServerAddress { url: format!("{scheme}://{}", host.to_lowercase()), insecure })
}

/// Localhost, private and Tailscale ranges, `.local` and `.ts.net`.
fn local_host(name: &str) -> bool {
    use std::net::IpAddr;
    match name.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            let [a, b, ..] = ip.octets();
            ip.is_loopback() || ip.is_private() || ip.is_link_local() || (a == 100 && (64..128).contains(&b))
        }
        Ok(IpAddr::V6(ip)) => ip.is_loopback() || (ip.segments()[0] & 0xfe00) == 0xfc00 || (ip.segments()[0] & 0xffc0) == 0xfe80,
        Err(_) => name == "localhost" || name.ends_with(".localhost") || name.ends_with(".local") || name.ends_with(".ts.net"),
    }
}

/// What the server allows before signing up; doubles as the reachability check.
#[uniffi::export]
pub fn server_info(server: String) -> Res<ServerInfo> {
    match plaintext_client::server_info(&Http::new(&normalize_server(&server)?)) {
        Ok(i) => Ok(ServerInfo { version: i.version, open: i.open, setup: i.setup }),
        Err(ClientError::Network(message)) => Err(PlaintextError::Network { message }),
        Err(_) => Err(PlaintextError::NotFound { message: "a Plaintext server at that address".into() }),
    }
}

/// How many times a password appears in Have I Been Pwned. Only the first five
/// characters of its SHA-1 hash leave the device.
#[uniffi::export]
pub fn breach_count(password: String) -> Res<u64> {
    let (prefix, suffix) = tools::breach_prefix(&password);
    let (status, body) = Http::new("https://api.pwnedpasswords.com").send("GET", &format!("/range/{prefix}"), None, None)?;
    if status != 200 {
        return Err(PlaintextError::Server { code: status, message: "the breach check isn't available right now".into() });
    }
    Ok(tools::breach_count(&String::from_utf8_lossy(&body), &suffix))
}

fn normalize_server(server: &str) -> Res<String> {
    Ok(server_address(server.into())?.url)
}

fn account_of(u: &UnlockData) -> Res<Account> {
    let id: [u8; 16] = u.account_id.as_slice().try_into().map_err(|_| PlaintextError::SignedOut)?;
    let key: [u8; 32] = u.account_key.as_slice().try_into().map_err(|_| PlaintextError::SignedOut)?;
    Ok(Account { id, account_key: Zeroizing::new(key) })
}

fn unlock_of(s: &S) -> UnlockData {
    UnlockData { token: s.token.clone(), account_id: s.account.id.to_vec(), account_key: s.account.account_key.to_vec() }
}

// ---------- The app ----------

struct Row {
    account: String,
    vault: Hex,
    vault_name: String,
    id: Hex,
    item: Item,
}

/// One unlocked account. Each has its own lock, so a slow server only holds up
/// calls for that account.
struct Acct {
    id: String,
    server: String,
    session: Mutex<S>,
    info: RwLock<AccountInfo>,
}

#[derive(uniffi::Object)]
pub struct PlaintextApp {
    dir: PathBuf,
    device: String,
    accounts: RwLock<Vec<Arc<Acct>>>,
    /// Copies of every account's items and vaults, so lists and search never
    /// wait on a sync.
    rows: RwLock<Vec<Row>>,
    vaults: RwLock<Vec<VaultInfo>>,
}

fn not_found(what: &str) -> PlaintextError {
    PlaintextError::NotFound { message: what.into() }
}

fn writer_again() -> PlaintextError {
    PlaintextError::Invalid { message: "You can write to this vault again, so these changes go out with the next sync.".into() }
}

fn writable(s: &S, vid: &Hex) -> Res<()> {
    match s.vaults.get(vid).ok_or_else(|| not_found("that vault"))?.role(s.username(), now()) {
        Some(r) if r >= CoreRole::Writer => Ok(()),
        _ => Err(PlaintextError::ReadOnly),
    }
}

/// Add a new item and push it. If that fails, take it back out (its delete is
/// harmless if the put did arrive), so trying again doesn't leave a second copy.
fn put_new(s: &mut S, vid: &Hex, iid: Hex, it: Item) -> Res<()> {
    s.put_item(vid, iid, it).map_err(|e| {
        // A refused put changed nothing: a delete would queue a change of its own.
        if let Some(v) = s.vaults.get_mut(vid)
            && v.get(&iid).is_some()
        {
            v.delete(iid);
        }
        e.into()
    })
}

fn get_item(s: &S, vid: &Hex, iid: &Hex) -> Res<Item> {
    s.vaults.get(vid).and_then(|v| v.get(iid)).cloned().ok_or_else(|| not_found("that item"))
}

#[uniffi::export]
impl PlaintextApp {
    /// `dir` is the app's private folder for sealed vault snapshots; `device`
    /// names this device in the session list.
    #[uniffi::constructor]
    pub fn new(dir: String, device: String) -> Self {
        PlaintextApp { dir: dir.into(), device, accounts: RwLock::default(), rows: RwLock::default(), vaults: RwLock::default() }
    }

    // ----- Accounts -----

    /// Create an account. `invite` is an invite code or link, or the server's
    /// setup code for the first account. Show the Secret Key on the Emergency Kit.
    pub fn signup(&self, server: String, username: String, password: String, invite: Option<String>) -> Res<SignupResult> {
        let server = normalize_server(&server)?;
        let invite = invite.map(|c| parse_invite_link(c.clone()).map_or(c, |l| l.code)).filter(|c| !c.trim().is_empty());
        let password = Zeroizing::new(password);
        let (sk, s) = Session::signup(Http::new(&server), username.trim(), &password, invite.as_deref(), &self.device)?;
        // The account exists now: whatever fails from here, hand back the Secret
        // Key (the next sync retries what this one couldn't do).
        let mut s = match s {
            Ok(s) => s,
            Err(e) => match Session::login(Http::new(&server), &derive(&password, &sk), &self.device) {
                Ok(s) => s,
                Err(_) => {
                    return Err(PlaintextError::Invalid {
                        message: format!("your account was created, but signing in failed ({e}). Write down your Secret Key, {}, then sign in with it and your password", sk.encode()),
                    });
                }
            },
        };
        // Checked after the account exists, so a mismatch never costs the Secret Key.
        let warning = match invite.as_deref().filter(|c| c.contains('.')).map(|c| s.trust_inviter(c)) {
            Some(Err(e)) => Some(format!(
                "Plaintext couldn't confirm who invited you ({}). Someone may be listening in: compare fingerprints in person before you share anything with them.",
                PlaintextError::from(e)
            )),
            _ => None,
        };
        let _ = s.sync();
        let unlock = unlock_of(&s);
        let id = hex::encode(s.account.id);
        let account = self.start(s, server).or_else(|_| Ok::<_, PlaintextError>(self.acct(&id)?.info.read().expect("lock").clone()))?;
        Ok(SignupResult { account, secret_key: sk.encode(), unlock, warning })
    }

    /// Sign in with the password and Secret Key (a new device, another account,
    /// or after the server ended this device's session).
    pub fn login(&self, server: String, secret_key: String, password: String) -> Res<LoginResult> {
        let server = normalize_server(&server)?;
        let sk = SecretKey::parse(&secret_key)?;
        let password = Zeroizing::new(password);
        let mut s = Session::login(Http::new(&server), &derive(&password, &sk), &self.device).map_err(password_error)?;
        let loaded = s.load_local(&self.dir_for(&s.account));
        // Signed in either way: what this sync couldn't do (a full account, a
        // server error) shows on the next one instead of locking the device out.
        let _ = s.sync();
        local_warning(&mut s, loaded);
        let unlock = unlock_of(&s);
        let account = self.start(s, server)?;
        Ok(LoginResult { account, unlock })
    }

    /// Unlock an account with what the keychain released. Works offline from
    /// this device's sealed copies; `SignedOut` means the password is needed.
    pub fn resume(&self, server: String, unlock: UnlockData) -> Res<AccountInfo> {
        let server = normalize_server(&server)?;
        let account = account_of(&unlock)?;
        let s = match Session::resume(Http::new(&server), unlock.token.clone(), account) {
            Ok(mut s) => {
                let loaded = s.load_local(&self.dir_for(&s.account));
                let synced = s.sync();
                local_warning(&mut s, loaded);
                match synced {
                    Ok(()) | Err(ClientError::Network(_) | ClientError::Server(500.., _)) => s,
                    // Signed out: stays locked until the password signs in again.
                    Err(ClientError::Server(401, _)) => return Err(PlaintextError::SignedOut),
                    // Anything else (a rollback, a changed key) opens with a warning.
                    Err(e) => {
                        self.start(s, server)?;
                        return Err(e.into());
                    }
                }
            }
            // Down (also behind a proxy answering 502/503): open from this device's copies.
            Err(ClientError::Network(_) | ClientError::Server(500.., _)) => {
                let account = account_of(&unlock)?;
                let dir = self.dir_for(&account);
                Session::offline(Http::new(&server), unlock.token, account, &dir)?
            }
            Err(e) => return Err(e.into()),
        };
        self.start(s, server)
    }

    /// Forget every unlocked session. With `end_sessions` (nothing in the
    /// keychain can resume them), also end them on the server, in the background.
    pub fn lock(&self, end_sessions: bool) {
        let gone = std::mem::take(&mut *self.accounts.write().expect("lock"));
        self.rows.write().expect("lock").clear();
        self.vaults.write().expect("lock").clear();
        if end_sessions {
            std::thread::spawn(move || {
                for a in gone {
                    let _ = a.session.lock().unwrap_or_else(|e| e.into_inner()).logout();
                }
            });
        }
    }

    /// Drop one account from memory and keep this device's copies (they hold the
    /// rollback guard and pins): for when the server ended this device's session.
    pub fn forget(&self, account: String) {
        self.drop_account(&account);
    }

    /// What the keychain stores to resume an unlocked account.
    pub fn unlock_data(&self, account: String) -> Res<UnlockData> {
        let a = self.acct(&account)?;
        let s = a.session.lock().unwrap_or_else(|e| e.into_inner());
        Ok(unlock_of(&s))
    }

    /// Sign this device out of one account: end the session on the server (when
    /// reachable) and delete this device's copies. A locked account's session is
    /// ended with what the keychain kept for it (`stored`), when there is any.
    pub fn sign_out(&self, account: String, server: String, stored: Option<UnlockData>) {
        let Ok(a) = self.acct(&account) else {
            if let Some(u) = stored
                && let Ok(acct) = account_of(&u)
                && let Ok(s) = Session::resume(Http::new(&server), u.token, acct)
            {
                let _ = s.logout();
            }
            if account.len() == 32 && hex::decode(&account).is_ok() {
                let _ = std::fs::remove_dir_all(self.dir.join("vaults").join(&account[..16]));
            }
            return;
        };
        self.drop_account(&account);
        let s = a.session.lock().unwrap_or_else(|e| e.into_inner());
        let _ = s.logout();
        let _ = std::fs::remove_dir_all(self.dir_for(&s.account));
    }

    /// Every unlocked account, in the order they were unlocked.
    pub fn accounts(&self) -> Vec<AccountInfo> {
        self.accounts.read().expect("lock").iter().map(|a| a.info.read().expect("lock").clone()).collect()
    }

    pub fn is_unlocked(&self) -> bool {
        !self.accounts.read().expect("lock").is_empty()
    }

    /// Pull, verify, merge and push every vault of one account.
    pub fn sync(&self, account: String) -> Res<()> {
        self.with(&account, |s| Ok(s.sync()?))
    }

    pub fn change_password(&self, account: String, secret_key: String, old_password: String, new_password: String) -> Res<()> {
        let sk = SecretKey::parse(&secret_key)?;
        let old = Zeroizing::new(old_password);
        self.with(&account, |s| s.change_password(&derive(&old, &sk), &sk, &new_password).map_err(password_error))
    }

    /// The QR another device scans to sign in (needs this account's Secret Key).
    pub fn add_device_code(&self, account: String, secret_key: String) -> Res<String> {
        let sk = SecretKey::parse(&secret_key)?;
        let a = self.acct(&account)?;
        let username = a.info.read().expect("lock").username.clone();
        Ok(device_code(a.server.clone(), username, sk.encode()))
    }

    /// What `discard_changes` would drop from a vault.
    pub fn unsent_changes(&self, account: String, vault: String) -> Res<UnsentChanges> {
        let id = hex_id(&vault)?;
        self.peek(&account, |s| {
            let v = s.vaults.get(&id).ok_or_else(|| not_found("that vault"))?;
            if writable(s, &id).is_ok() {
                return Err(writer_again());
            }
            Ok(UnsentChanges { name: v.meta.name.clone(), changed: v.changed().map(|(_, i)| i.title.clone()).collect(), deleted: v.deleted() as u32, renamed: v.meta_changed() })
        })
    }

    /// Drop this device's changes to a vault that haven't reached the server (it
    /// is downloaded again), and the sync problem about them. Returns how many.
    pub fn discard_changes(&self, account: String, vault: String) -> Res<u32> {
        let id = hex_id(&vault)?;
        // The preview read the roster this device has: ask the server for today's.
        self.with(&account, |s| match s.writable(&id) {
            Ok(()) => Err(writer_again()),
            Err(ClientError::Core(core::Error::ReadOnly)) => Ok(s.discard_changes(&id)? as u32),
            Err(e) => Err(e.into()),
        })
    }

    // ----- Vaults and items -----

    /// Every account's vaults: each account's default vault first, then by name.
    pub fn vaults(&self) -> Vec<VaultInfo> {
        self.vaults.read().expect("lock").clone()
    }

    pub fn create_vault(&self, account: String, name: String) -> Res<String> {
        self.with(&account, |s| Ok(s.create_vault(name.trim())?.to_string()))
    }

    pub fn rename_vault(&self, account: String, vault: String, name: String) -> Res<()> {
        let id = hex_id(&vault)?;
        self.with(&account, |s| {
            let mut meta = s.vaults.get(&id).ok_or_else(|| not_found("that vault"))?.meta.clone();
            meta.name = name.trim().into();
            Ok(s.rename_vault(&id, meta)?)
        })
    }

    /// Items of one account and vault, or all of them, matching `query` (title,
    /// username, URLs, tags, notes and non-secret fields), favorites first, then
    /// by title.
    pub fn items(&self, account: Option<String>, vault: Option<String>, query: String, archived: bool) -> Vec<ItemSummary> {
        let rows = self.rows.read().expect("lock");
        let q = query.trim();
        let mut out: Vec<ItemSummary> = rows
            .iter()
            .filter(|r| account.as_ref().is_none_or(|a| *a == r.account))
            .filter(|r| vault.as_ref().is_none_or(|v| *v == r.vault.to_string()))
            .filter(|r| r.item.archived == archived)
            .filter(|r| q.is_empty() || r.item.matches(q))
            .map(summary)
            .collect();
        out.sort_by_key(|i| (!i.favorite, i.title.to_lowercase()));
        out
    }

    pub fn tags(&self) -> Vec<String> {
        let rows = self.rows.read().expect("lock");
        let mut t: Vec<String> = rows.iter().flat_map(|r| r.item.tags.iter().cloned()).collect();
        t.sort_by_key(|x| x.to_lowercase());
        t.dedup();
        t
    }

    pub fn item(&self, account: String, vault: String, id: String) -> Res<ItemData> {
        let rows = self.rows.read().expect("lock");
        rows.iter()
            .find(|r| r.account == account && r.vault.to_string() == vault && r.id.to_string() == id)
            .map(|r| item_data(&r.item))
            .ok_or_else(|| not_found("that item"))
    }

    /// Save an item (new when `id` is None) and push it. Editing keeps the
    /// previous version and password in the item's history. Offline, the edit
    /// is kept on this device and sent on the next sync. Returns the item id.
    pub fn put_item(&self, account: String, vault: String, id: Option<String>, item: ItemData) -> Res<String> {
        let vid = hex_id(&vault)?;
        let (iid, existing) = match &id {
            Some(i) => (hex_id(i)?, true),
            None => (core::new_item_id(), false),
        };
        self.local_first(&account, &vid, |s| {
            let next = if existing {
                let old = get_item(s, &vid, &iid)?;
                let mut it = old.clone();
                it.edit(apply(&old, item), now_ms());
                it
            } else {
                s.vaults.get(&vid).ok_or_else(|| not_found("that vault"))?;
                let mut it = apply(&Item::default(), item);
                (it.created, it.updated) = (now_ms(), now_ms());
                it
            };
            Ok(s.put_item(&vid, iid, next)?)
        })?;
        Ok(iid.to_string())
    }

    /// Favorite or archive without making a new version.
    pub fn set_flags(&self, account: String, vault: String, id: String, favorite: bool, archived: bool) -> Res<()> {
        let (vid, iid) = (hex_id(&vault)?, hex_id(&id)?);
        self.local_first(&account, &vid, |s| {
            let mut it = get_item(s, &vid, &iid)?;
            (it.favorite, it.archived) = (favorite, archived);
            Ok(s.put_item(&vid, iid, it)?)
        })
    }

    /// Put `password` at the top of an item's password history and leave the
    /// current password as it is, in one save: Watchtower's Change keeps a new
    /// password safe before the website has it.
    pub fn keep_password(&self, account: String, vault: String, id: String, password: String) -> Res<()> {
        let (vid, iid) = (hex_id(&vault)?, hex_id(&id)?);
        self.local_first(&account, &vid, |s| {
            let mut it = get_item(s, &vid, &iid)?;
            it.password_history.insert(0, core::item::OldPassword { password, changed: now_ms() });
            Ok(s.put_item(&vid, iid, it)?)
        })
    }

    /// Bring back an earlier version (index into `ItemData.history`); the
    /// current one goes into history in turn.
    pub fn restore_version(&self, account: String, vault: String, id: String, index: u32) -> Res<()> {
        let (vid, iid) = (hex_id(&vault)?, hex_id(&id)?);
        self.local_first(&account, &vid, |s| {
            let cur = get_item(s, &vid, &iid)?;
            let old = cur.history.get(index as usize).cloned().ok_or_else(|| not_found("that version"))?;
            let mut old: Item = serde_json::from_value(old).map_err(|_| PlaintextError::Invalid { message: "that version is unreadable".into() })?;
            // Attachments aren't versioned: keep today's.
            old.files = cur.files.clone();
            let mut it = cur;
            it.edit(old, now_ms());
            Ok(s.put_item(&vid, iid, it)?)
        })
    }

    pub fn delete_item(&self, account: String, vault: String, id: String) -> Res<()> {
        let (vid, iid) = (hex_id(&vault)?, hex_id(&id)?);
        self.local_first(&account, &vid, |s| Ok(s.delete_item(&vid, iid)?))
    }

    /// Move to another vault, also one of another account (attachments are
    /// re-encrypted for it). Returns the new id.
    pub fn move_item(&self, account: String, vault: String, id: String, to_account: String, to_vault: String) -> Res<String> {
        let (vid, iid, to) = (hex_id(&vault)?, hex_id(&id)?, hex_id(&to_vault)?);
        let (mut it, files) = self.with(&account, |s| {
            // The freshest roster, so a stale writer isn't left with a copy in each place.
            s.writable(&vid)?;
            let it = get_item(s, &vid, &iid)?;
            let mut files = Vec::new();
            for f in &it.files {
                files.push((f.name.clone(), Zeroizing::new(s.download_file(&vid, f)?)));
            }
            Ok((it, files))
        })?;
        it.files.clear();
        let nid = core::new_item_id();
        self.with(&to_account, |s| {
            writable(s, &to)?;
            for (name, data) in &files {
                it.files.push(s.upload_file(&to, name, data)?);
            }
            put_new(s, &to, nid, it)
        })?;
        self.with(&account, |s| Ok(s.delete_item(&vid, iid)?))?;
        Ok(nid.to_string())
    }

    pub fn attach_file(&self, account: String, vault: String, id: String, name: String, data: Vec<u8>) -> Res<()> {
        let (vid, iid) = (hex_id(&vault)?, hex_id(&id)?);
        self.with(&account, |s| {
            writable(s, &vid)?;
            let mut it = get_item(s, &vid, &iid)?;
            it.files.push(s.upload_file(&vid, &name, &data)?);
            Ok(s.put_item(&vid, iid, it)?)
        })
    }

    /// Take an attachment off an item. The file itself stays on the server until a
    /// later sync collects it (another device may still bring the item back with it).
    pub fn remove_file(&self, account: String, vault: String, id: String, file: String) -> Res<()> {
        let (vid, iid) = (hex_id(&vault)?, hex_id(&id)?);
        self.local_first(&account, &vid, |s| {
            let mut it = get_item(s, &vid, &iid)?;
            it.files.retain(|f| f.id.to_string() != file);
            Ok(s.put_item(&vid, iid, it)?)
        })
    }

    pub fn download_file(&self, account: String, vault: String, id: String, file: String) -> Res<Vec<u8>> {
        let (vid, iid) = (hex_id(&vault)?, hex_id(&id)?);
        let a = self.acct(&account)?;
        let s = a.session.lock().unwrap_or_else(|e| e.into_inner());
        let it = get_item(&s, &vid, &iid)?;
        let f = it.files.iter().find(|f| f.id.to_string() == file).ok_or_else(|| not_found("that attachment"))?;
        Ok(s.download_file(&vid, f)?)
    }

    /// Local Watchtower checks over every account's vaults (archived items skipped).
    pub fn watchtower(&self) -> Vec<WatchItem> {
        let all = self.rows.read().expect("lock");
        // A vault shared between two of your accounts counts once.
        let mut seen = std::collections::BTreeSet::new();
        let rows: Vec<&Row> = all.iter().filter(|r| seen.insert((r.vault, r.id))).collect();
        let found = tools::watchtower(rows.iter().map(|r| (r.id, &r.item)));
        let mut out: Vec<WatchItem> = rows
            .iter()
            .filter_map(|r| {
                let f = found.get(&r.id)?;
                let reused_with = rows
                    .iter()
                    .filter(|o| o.id != r.id && !o.item.archived && !r.item.password.is_empty() && o.item.password == r.item.password)
                    .map(|o| o.id)
                    .collect::<std::collections::BTreeSet<_>>()
                    .len() as u32;
                Some(WatchItem {
                    account_id: r.account.clone(),
                    vault_id: r.vault.to_string(),
                    id: r.id.to_string(),
                    title: r.item.title.clone(),
                    subtitle: subtitle(&r.item),
                    findings: f
                        .iter()
                        .map(|x| match x {
                            tools::Finding::Weak => Finding::Weak,
                            tools::Finding::Reused => Finding::Reused,
                            tools::Finding::Unsecured => Finding::Unsecured,
                            tools::Finding::NoTwoFactor => Finding::NoTwoFactor,
                        })
                        .collect(),
                    reused_with,
                })
            })
            .collect();
        out.sort_by_key(|w| w.title.to_lowercase());
        out
    }

    /// Parse and save imported data into one account. Source vaults land in its
    /// own vaults of the same name (made if needed) unless `vault` is given.
    /// Returns the count.
    pub fn import_items(&self, account: String, format: ImportFormat, data: Vec<u8>, vault: Option<String>) -> Res<u32> {
        let data = Zeroizing::new(data);
        let imported = match format {
            ImportFormat::OnePux => import::onepux(&data)?,
            ImportFormat::Bitwarden => import::bitwarden(&data)?,
            ImportFormat::Csv => import::csv(&String::from_utf8_lossy(&data))?,
        };
        let into = vault.as_deref().map(hex_id).transpose()?;
        self.with(&account, |s| Ok(s.import(imported, into)? as u32))
    }

    // ----- People and sharing (always within one account's server) -----

    pub fn members(&self, account: String, vault: String) -> Res<Vec<MemberInfo>> {
        let id = hex_id(&vault)?;
        self.peek(&account, |s| {
            let v = s.vaults.get(&id).ok_or_else(|| not_found("that vault"))?;
            let me = s.username();
            let mut out: Vec<MemberInfo> = v
                .roster
                .iter()
                .flat_map(|r| &r.members)
                .map(|m| MemberInfo {
                    username: m.username.clone(),
                    role: m.role.into(),
                    expires: m.expires,
                    verified: m.username == me || s.keyring.contacts.get(&m.username).is_some_and(|c| c.verified),
                    fingerprint: s.fingerprint(&m.username).unwrap_or_default(),
                    is_me: m.username == me,
                })
                .collect();
            out.sort_by_key(|m| (!m.is_me, std::cmp::Reverse(m.role as u8), m.username.clone()));
            Ok(out)
        })
    }

    /// Give someone access by exact username (pins their keys first if they're
    /// new to you). Lowering a role replaces the vault key, like removing them.
    pub fn share_vault(&self, account: String, vault: String, username: String, role: Role, expires: Option<u64>) -> Res<()> {
        let id = hex_id(&vault)?;
        let username = username.trim().to_lowercase();
        self.with(&account, |s| Ok(s.share_vault(&id, &username, role.into(), expires)?))
    }

    /// Remove someone and replace the vault key.
    pub fn revoke(&self, account: String, vault: String, username: String) -> Res<()> {
        let id = hex_id(&vault)?;
        self.with(&account, |s| Ok(s.revoke(&id, &username)?))
    }

    pub fn audit(&self, account: String, vault: String) -> Res<Vec<AuditData>> {
        let id = hex_id(&vault)?;
        self.peek(&account, |s| Ok(s.audit(&id)?.into_iter().rev().map(|e| AuditData { ts: e.ts, username: e.username, action: e.action }).collect()))
    }

    /// The people this account may browse: everyone for admins and on
    /// invite-only servers; on open servers, your invitees and agents.
    pub fn users(&self, account: String) -> Res<Vec<UserData>> {
        self.peek(&account, |s| {
            let mut out: Vec<UserData> = s
                .users()?
                .into_iter()
                .filter_map(|u| {
                    let id: Identity = serde_json::from_slice(&u.identity.body.0).ok()?;
                    Some(UserData {
                        verified: s.keyring.contacts.get(&id.username).is_some_and(|c| c.verified),
                        is_agent: id.kind == Kind::Agent,
                        username: id.username,
                        owner: id.owner,
                        admin: u.admin,
                        disabled: u.disabled,
                    })
                })
                .collect();
            out.sort_by(|a, b| a.username.cmp(&b.username));
            Ok(out)
        })
    }

    /// A user's fingerprint by exact username, pinning their keys on first sight.
    pub fn fingerprint(&self, account: String, username: String) -> Res<String> {
        let username = username.trim().to_lowercase();
        self.with(&account, |s| {
            if username != s.username() && !s.keyring.contacts.contains_key(&username) {
                s.pin_user(&username)?;
            }
            s.fingerprint(&username).ok_or_else(|| not_found(&format!("user {username}")))
        })
    }

    pub fn is_verified(&self, account: String, username: String) -> bool {
        self.peek(&account, |s| Ok(s.keyring.contacts.get(&username).is_some_and(|c| c.verified))).unwrap_or(false)
    }

    /// After comparing fingerprints in person.
    pub fn mark_verified(&self, account: String, username: String) -> Res<()> {
        self.with(&account, |s| Ok(s.mark_verified(&username)?))
    }

    /// The QR others scan to verify you.
    pub fn my_verify_code(&self, account: String) -> Res<String> {
        let info = self.acct(&account)?.info.read().expect("lock").clone();
        Ok(verify_code(&info.username, &info.fingerprint))
    }

    /// Scanned someone's verify QR: if it matches the keys pinned for them, they're
    /// verified. Returns their username.
    pub fn verify_scanned(&self, account: String, code: String) -> Res<String> {
        let bad = || PlaintextError::Invalid { message: "that isn't a Plaintext verification code".into() };
        let (username, fp) = code.trim().strip_prefix(VERIFY).and_then(|r| r.split_once(':')).ok_or_else(bad)?;
        // Pins and verifies only keys that match the scan; a mismatch changes nothing.
        self.with(&account, |s| {
            s.verify_fingerprint(username, fp)?;
            Ok(username.to_string())
        })
    }

    /// An invite link (admins; anyone on open servers) that carries the server
    /// and verifies both sides.
    pub fn invite(&self, account: String) -> Res<String> {
        let server = self.acct(&account)?.server.clone();
        self.with(&account, |s| Ok(invite_link(server, s.invite()?)))
    }

    /// Admins disable anyone; owners disable their agents.
    pub fn disable_user(&self, account: String, username: String) -> Res<()> {
        self.with(&account, |s| Ok(s.disable_user(&username)?))
    }

    /// Send one item to someone's inbox, sealed to their key.
    pub fn send_item(&self, account: String, vault: String, id: String, to: String, expires: Option<u64>) -> Res<()> {
        let (vid, iid) = (hex_id(&vault)?, hex_id(&id)?);
        let to = to.trim().to_lowercase();
        self.with(&account, |s| {
            let mut it = get_item(s, &vid, &iid)?;
            // Attachments stay in the vault: their keys alone would not open them.
            it.files.clear();
            it.history.clear();
            Ok(s.send(&to, &Content::Item(Box::new(it)), expires)?)
        })
    }

    /// A link anyone can open until it expires (`expires_in` seconds, up to 30
    /// days), optionally for one view only. `page` is the link page setting.
    pub fn create_link(&self, account: String, vault: String, id: String, page: String, expires_in: u64, one_view: bool) -> Res<String> {
        let (vid, iid) = (hex_id(&vault)?, hex_id(&id)?);
        let server = self.acct(&account)?.server.clone();
        let page = if page.trim().is_empty() { plaintext_client::LINK_PAGE.to_string() } else { page.trim().to_string() };
        self.with(&account, |s| {
            let mut it = get_item(s, &vid, &iid)?;
            it.files.clear();
            it.history.clear();
            it.password_history.clear();
            Ok(s.create_link(&page, &server, &it, now() + expires_in.min(30 * 86400), one_view.then_some(1))?)
        })
    }

    pub fn inbox(&self, account: String) -> Res<Vec<InboxEntry>> {
        self.with(&account, |s| {
            let me = s.username().to_string();
            let agents: Vec<String> = s
                .users()?
                .into_iter()
                .filter_map(|u| serde_json::from_slice::<Identity>(&u.identity.body.0).ok())
                .filter(|i| i.kind == Kind::Agent && i.owner.as_deref() == Some(&me))
                .map(|i| i.username)
                .collect();
            let mut out: Vec<InboxEntry> = s
                .inbox()?
                .into_iter()
                .map(|(from, r)| {
                    let verified = s.keyring.contacts.get(&from).is_some_and(|c| c.verified);
                    // An agent's owner claim is its own; the owner pinned and verified it when making it.
                    let from_agent_of_mine = verified && agents.contains(&from);
                    match r {
                        Ok((m, c)) => InboxEntry {
                            id: m.id.to_string(),
                            content: match c {
                                Content::Item(i) => InboxContent::Item { item: item_data(&i) },
                                Content::Request(text) => InboxContent::Request { text },
                            },
                            expires: m.expires,
                            from,
                            verified,
                            from_agent_of_mine,
                        },
                        Err(e) => InboxEntry { id: String::new(), from, verified, from_agent_of_mine, content: InboxContent::Unreadable { reason: capitalize(&e.to_string()) }, expires: None },
                    }
                })
                .collect();
            out.reverse();
            Ok(out)
        })
    }

    /// Save a shared item from the inbox into a vault (the account's default one
    /// when None), then remove the message.
    pub fn save_from_inbox(&self, account: String, message: String, vault: Option<String>) -> Res<String> {
        let mid = hex_id(&message)?;
        let into = vault.as_deref().map(hex_id).transpose()?;
        self.with(&account, |s| {
            let mut item = s
                .inbox()?
                .into_iter()
                .find_map(|(_, r)| match r {
                    Ok((m, Content::Item(i))) if m.id == mid => Some(*i),
                    _ => None,
                })
                .ok_or_else(|| not_found("that message"))?;
            let vid = match into {
                Some(v) => v,
                None => s.default_vault()?,
            };
            let iid = core::new_item_id();
            (item.created, item.updated) = (now_ms(), now_ms());
            put_new(s, &vid, iid, item)?;
            // Saved either way: a message left behind can still be dismissed.
            let _ = s.delete_message(&mid);
            Ok(iid.to_string())
        })
    }

    pub fn dismiss_message(&self, account: String, message: String) -> Res<()> {
        let mid = hex_id(&message)?;
        self.with(&account, |s| Ok(s.delete_message(&mid)?))
    }

    // ----- Agents -----

    /// Make an agent with access to one vault. Returns its `ptk_…` key: show it
    /// once. The agent exists once it's made, so its key comes back even when
    /// sharing the vault with it fails (the warning says so).
    pub fn create_agent(&self, account: String, name: String, vault: String, role: Role, expires: Option<u64>) -> Res<NewAgentKey> {
        let vid = hex_id(&vault)?;
        let name = name.trim().to_lowercase();
        self.with(&account, |s| {
            let key = s.create_agent(&name)?.encode();
            let warning = s.share_vault(&vid, &name, role.into(), expires).err().map(|e| {
                format!("{name} was made, but giving it the vault failed ({}). Share the vault with {name} to try again.", PlaintextError::from(e))
            });
            Ok(NewAgentKey { key, warning })
        })
    }

    /// This account's agents, their access and last activity.
    pub fn agents(&self, account: String) -> Res<Vec<AgentInfo>> {
        self.with(&account, |s| {
            let me = s.username().to_string();
            let mine: Vec<(String, bool)> = s
                .users()?
                .into_iter()
                .filter_map(|u| Some((serde_json::from_slice::<Identity>(&u.identity.body.0).ok()?, u.disabled)))
                .filter(|(i, _)| i.kind == Kind::Agent && i.owner.as_deref() == Some(&me))
                .map(|(i, d)| (i.username, d))
                .collect();
            let owned: Vec<Hex> = s.vaults.iter().filter(|(_, v)| v.role(&me, now()) == Some(CoreRole::Owner)).map(|(id, _)| *id).collect();
            let mut audits = Vec::new();
            for id in &owned {
                if s.vaults[id].roster.iter().flat_map(|r| &r.members).any(|m| mine.iter().any(|(n, _)| *n == m.username)) {
                    audits.extend(s.audit(id)?);
                }
            }
            Ok(mine
                .into_iter()
                .map(|(name, disabled)| AgentInfo {
                    access: s
                        .vaults
                        .iter()
                        .filter_map(|(id, v)| {
                            let m = v.roster.as_ref()?.members.iter().find(|m| m.username == name)?;
                            Some(AgentAccess { vault_id: id.to_string(), vault_name: v.meta.name.clone(), role: m.role.into(), expires: m.expires })
                        })
                        .collect(),
                    last_active: audits.iter().filter(|e| e.username == name).map(|e| e.ts).max(),
                    name,
                    disabled,
                })
                .collect())
        })
    }

    // ----- Devices -----

    pub fn sessions(&self, account: String) -> Res<Vec<SessionData>> {
        self.peek(&account, |s| Ok(s.sessions()?.into_iter().map(|d| SessionData { id: d.id, device: d.device, created: d.created, current: d.current }).collect()))
    }

    pub fn end_session(&self, account: String, id: String) -> Res<()> {
        self.with(&account, |s| Ok(s.end_session(&id)?))
    }
}

fn summary(r: &Row) -> ItemSummary {
    let i = &r.item;
    ItemSummary {
        account_id: r.account.clone(),
        vault_id: r.vault.to_string(),
        vault_name: r.vault_name.clone(),
        id: r.id.to_string(),
        kind: i.kind.clone(),
        title: i.title.clone(),
        subtitle: subtitle(i),
        favorite: i.favorite,
        archived: i.archived,
        has_username: !i.username.is_empty(),
        has_password: !i.password.is_empty(),
        has_totp: !i.totp.is_empty(),
        tags: i.tags.clone(),
        updated: i.updated,
    }
}

impl PlaintextApp {
    fn acct(&self, id: &str) -> Res<Arc<Acct>> {
        self.accounts.read().expect("lock").iter().find(|a| a.id == id).cloned().ok_or(PlaintextError::Locked)
    }

    fn dir_for(&self, a: &Account) -> PathBuf {
        self.dir.join("vaults").join(hex::encode(&a.id[..8]))
    }

    fn drop_account(&self, id: &str) {
        let mut accounts = self.accounts.write().expect("lock");
        accounts.retain(|a| a.id != id);
        self.rows.write().expect("lock").retain(|r| r.account != id);
        self.vaults.write().expect("lock").retain(|v| v.account_id != id);
    }

    fn start(&self, s: S, server: String) -> Res<AccountInfo> {
        let id = hex::encode(s.account.id);
        let info = AccountInfo { id: id.clone(), server: server.clone(), username: s.username().into(), admin: s.admin, fingerprint: s.me().fingerprint(), pending: false, problems: vec![], problem_unsent: vec![] };
        let a = Arc::new(Acct { id: id.clone(), server, info: RwLock::new(info), session: Mutex::new(s) });
        {
            let mut accounts = self.accounts.write().expect("lock");
            accounts.retain(|x| x.id != id);
            accounts.push(a.clone());
        }
        let s = a.session.lock().unwrap_or_else(|e| e.into_inner());
        match self.persist(&a, &s) {
            // Locked right away: still hand back what the caller needs (signup's
            // Secret Key); the app resumes it from the keychain data.
            Err(PlaintextError::Locked) => {}
            r => r?,
        }
        let info = a.info.read().expect("lock").clone();
        Ok(info)
    }

    /// Save the sealed snapshots and refresh the copies lists read from.
    fn persist(&self, a: &Arc<Acct>, s: &S) -> Res<()> {
        // A session that was locked or signed out meanwhile must not write over
        // newer snapshots (or bring back a folder `sign_out` removed).
        if !self.accounts.read().expect("lock").iter().any(|x| Arc::ptr_eq(x, a)) {
            return Err(PlaintextError::Locked);
        }
        let saved = s.save_local(&self.dir_for(&s.account));
        let me = s.username().to_string();
        {
            let mut info = a.info.write().expect("lock");
            info.admin = s.admin;
            info.pending = s.vaults.values().any(|v| v.has_changes());
            info.problems = s.problems.clone();
            info.problem_unsent = (0..s.problems.len()).map(|i| s.unsendable.iter().find(|(_, j)| *j == i).map(|(id, _)| id.to_string())).collect();
        }
        let rows = s.vaults.iter().flat_map(|(vid, v)| {
            v.items().map(move |(id, item)| Row { account: a.id.clone(), vault: *vid, vault_name: v.meta.name.clone(), id: *id, item: item.clone() })
        });
        let default = s.default_vault().ok();
        let vaults = s.vaults.iter().filter(|(_, v)| v.roster.is_some()).map(|(id, v)| VaultInfo {
            account_id: a.id.clone(),
            id: id.to_string(),
            name: v.meta.name.clone(),
            item_count: v.items().filter(|(_, i)| !i.archived).count() as u32,
            role: v.role(&me, now()).map(Role::from),
            members: v.roster.iter().flat_map(|r| &r.members).map(|m| m.username.clone()).collect(),
            own: v.creator == me,
            is_default: default == Some(*id),
        });
        // Holding the account list keeps a concurrent `lock` from being undone.
        let accounts = self.accounts.read().expect("lock");
        if let Some(pos) = accounts.iter().position(|x| Arc::ptr_eq(x, a)) {
            let mut r = self.rows.write().expect("lock");
            r.retain(|r| r.account != a.id);
            r.extend(rows);
            let mut vs = self.vaults.write().expect("lock");
            vs.retain(|v| v.account_id != a.id);
            vs.extend(vaults);
            let order = |id: &str| accounts.iter().position(|x| x.id == id).unwrap_or(pos);
            vs.sort_by_key(|v| (order(&v.account_id), !v.is_default, v.name.to_lowercase()));
        }
        Ok(saved?)
    }

    /// Run `f` on one account's session, then persist whatever it changed (also
    /// on errors: a failed push still leaves verified pulls and local edits worth
    /// keeping).
    fn with<R>(&self, account: &str, f: impl FnOnce(&mut S) -> Res<R>) -> Res<R> {
        let a = self.acct(account)?;
        let mut s = a.session.lock().unwrap_or_else(|e| e.into_inner());
        let r = f(&mut s);
        let saved = self.persist(&a, &s);
        // Locked meanwhile: nothing was kept, so this didn't happen (even offline).
        if let Err(PlaintextError::Locked) = saved {
            return Err(PlaintextError::Locked);
        }
        let r = r?;
        saved?;
        Ok(r)
    }

    /// Run `f` on one account's session without saving anything: for reads.
    fn peek<R>(&self, account: &str, f: impl FnOnce(&S) -> Res<R>) -> Res<R> {
        let a = self.acct(account)?;
        let s = a.session.lock().unwrap_or_else(|e| e.into_inner());
        f(&s)
    }

    /// Like `with`, but a network failure isn't one: the change is saved on this
    /// device and goes out with the next sync.
    /// Edits to a vault you can only view are refused: they'd never reach the server.
    fn local_first(&self, account: &str, vault: &Hex, f: impl FnOnce(&mut S) -> Res<()>) -> Res<()> {
        match self.with(account, |s| {
            writable(s, vault)?;
            f(s)
        }) {
            Err(PlaintextError::Network { .. }) => Ok(()),
            Err(PlaintextError::Server { code: 500.., .. }) => Ok(()),
            r => r,
        }
    }
}

#[cfg(test)]
mod tests;
