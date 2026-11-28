//! Everything a Plaintext app does over the network, on top of the sans-IO core:
//! signing in, syncing vaults (pull, verify, merge, push, retry on conflict),
//! keeping the keyring's pins in sync, sharing and agents. Every app (CLI, MCP,
//! the UniFFI bindings for iOS/Android/desktop) uses this, so sync rules exist once.

use std::collections::BTreeMap;
use std::future::Future;
use std::path::Path;

use plaintext_core::api::*;
use plaintext_core::crypto::{Derived, SecretKey, derive};
use plaintext_core::identity::{Keyring, Me};
use plaintext_core::item::{FileRef, Item};
use plaintext_core::{Account, Content, Vault, VaultMeta};
use serde::Serialize;
use serde::de::DeserializeOwned;

pub use plaintext_core;

#[cfg(not(target_arch = "wasm32"))]
pub mod import;

#[derive(Debug)]
pub enum Error {
    Core(plaintext_core::Error),
    /// The server answered with an error status.
    Server(u16, String),
    Network(String),
    NotFound(String),
    /// The client won't do it; the message says why.
    Refused(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::Core(e) => e.fmt(f),
            Error::Server(code, msg) => write!(f, "server said {code}: {}", msg.chars().take(300).collect::<String>()),
            Error::Network(e) => write!(f, "couldn't reach the server: {e}"),
            Error::NotFound(what) => write!(f, "{what} not found"),
            Error::Refused(why) => f.write_str(why),
        }
    }
}
impl std::error::Error for Error {}

impl Error {
    /// The server didn't take a vault's change this time: another device changed
    /// it first (409), it was too big (413: for one request, or for every member's
    /// next pull, `api::MAX_PUSH`) or the account is full (507).
    /// The change waits on the device for the next sync.
    pub fn held_back(&self) -> bool {
        matches!(self, Error::Server(409 | 413 | 507, _))
    }
}
impl From<plaintext_core::Error> for Error {
    fn from(e: plaintext_core::Error) -> Self {
        Error::Core(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// What `Session::import` saved. Its items are on this device even when an error is set.
#[derive(Debug, Default)]
pub struct ImportReport {
    pub items: usize,
    /// Attachments left out ("item title: file name") after `upload_error`.
    pub skipped: Vec<String>,
    pub upload_error: Option<Error>,
    /// The first push that failed; the items go out with the next sync.
    pub sync_error: Option<Error>,
}

/// Past this many bytes of items (and manifest), a push or key rotation stages its
/// items in parts of about this size, well under the server's 32 MiB request limit.
const STAGE_PAST: usize = 16 << 20;

/// An inbox message as opened, or why it couldn't be.
pub type Received = std::result::Result<(Message, Content), plaintext_core::Error>;

pub fn now() -> u64 {
    now_ms() / 1000
}

#[cfg(not(target_arch = "wasm32"))]
pub fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).expect("clock after 1970").as_millis() as u64
}

/// `SystemTime` panics in the browser; ask JavaScript.
#[cfg(target_arch = "wasm32")]
pub fn now_ms() -> u64 {
    js_sys::Date::now() as u64
}

/// How requests reach the server. `Http` for real use; tests and embedders may plug in others.
pub trait Transport {
    fn send(&self, method: &str, path: &str, token: Option<&str>, body: Option<Vec<u8>>) -> Result<(u16, Vec<u8>)>;
    /// The server's host as the user typed it (`crypto::server_host`); logins are signed for it.
    fn host(&self) -> String;
}

/// The same, for callers that can't block: the browser extension sends through
/// `fetch` (see `wasm/`). Every `Transport` is one, so `Session`'s logic is
/// written once, async, and the blocking methods drive it to completion.
pub trait AsyncTransport {
    fn fetch(&self, method: &str, path: &str, token: Option<&str>, body: Option<Vec<u8>>) -> impl Future<Output = Result<(u16, Vec<u8>)>>;
    /// As `Transport::host`.
    fn login_host(&self) -> String;
}

impl<T: Transport> AsyncTransport for T {
    fn fetch(&self, method: &str, path: &str, token: Option<&str>, body: Option<Vec<u8>>) -> impl Future<Output = Result<(u16, Vec<u8>)>> {
        std::future::ready(self.send(method, path, token, body))
    }
    fn login_host(&self) -> String {
        self.host()
    }
}

/// Runs a future that a blocking `Transport` has already finished: its requests
/// complete inside `fetch`, so the first poll is the last.
fn block_on<F: Future>(f: F) -> F::Output {
    let mut f = std::pin::pin!(f);
    match f.as_mut().poll(&mut std::task::Context::from_waker(std::task::Waker::noop())) {
        std::task::Poll::Ready(v) => v,
        std::task::Poll::Pending => unreachable!("a blocking Transport never leaves a request pending"),
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub struct Http {
    pub base: String,
    agent: ureq::Agent,
}

#[cfg(not(target_arch = "wasm32"))]
impl Http {
    pub fn new(base: &str) -> Http {
        use std::time::Duration;
        // No redirects: a server (or a share link's server) can't bounce a request
        // to another host. Timeouts: a server that stops answering can't hang us.
        let agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .timeout_connect(Some(Duration::from_secs(15)))
            .timeout_recv_response(Some(Duration::from_secs(60)))
            .timeout_global(Some(Duration::from_secs(600)))
            .build()
            .into();
        Http { base: base.trim_end_matches('/').into(), agent }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Transport for Http {
    fn send(&self, method: &str, path: &str, token: Option<&str>, body: Option<Vec<u8>>) -> Result<(u16, Vec<u8>)> {
        let url = format!("{}{}", self.base, path);
        let auth = token.map(|t| format!("Bearer {t}"));
        let req = ureq::http::Request::builder().method(method).uri(&url).header("content-type", "application/json");
        let req = match &auth {
            Some(a) => req.header("authorization", a),
            None => req,
        };
        let req = req.body(body.unwrap_or_default()).map_err(|e| Error::Network(e.to_string()))?;
        let mut resp = self.agent.run(req).map_err(|e| Error::Network(e.to_string()))?;
        let status = resp.status().as_u16();
        let bytes = resp.body_mut().with_config().limit(128 << 20).read_to_vec().map_err(|e| match e {
            // Like a vault too big to pull: that vault waits, the others still sync.
            ureq::Error::BodyExceedsLimit(_) => Error::Server(413, "the server's answer is bigger than this app takes in one go".into()),
            e => Error::Network(e.to_string()),
        })?;
        Ok((status, bytes))
    }

    fn host(&self) -> String {
        plaintext_core::crypto::server_host(&self.base)
    }
}

/// The share-link page. It's static and lives apart from every vault server: whoever
/// serves the page's script could read the key in the link. Self-hosters can host
/// `docs/s/` on their own domain and use that instead.
pub const LINK_PAGE: &str = "https://getplaintext.org/s/";

/// Whether talking to `url` would expose sign-ins and session tokens to the
/// network: anything but `https://`, except plain `http://` to this machine, a
/// private or Tailscale network, `.local` names, or a single-label name (a LAN or
/// Docker host). Someone on the path could replay a sign-in sent in the clear.
pub fn insecure_url(url: &str) -> bool {
    let Some(rest) = url.trim().strip_prefix("http://") else { return !url.trim().starts_with("https://") };
    let host = plaintext_core::crypto::server_host(rest);
    let host = match host.rsplit_once(':') {
        Some((h, port)) if port.chars().all(|c| c.is_ascii_digit()) && !h.ends_with(':') => h,
        _ => host.as_str(),
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let local = match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => ip.is_loopback() || ip.is_private() || ip.is_link_local() || (ip.octets()[0] == 100 && ip.octets()[1] & 0xc0 == 64),
        Ok(std::net::IpAddr::V6(ip)) => ip.is_loopback() || ip.is_unique_local() || ip.is_unicast_link_local(),
        Err(_) => !host.contains('.') || [".local", ".localhost", ".ts.net", ".internal", ".lan", ".home.arpa"].iter().any(|s| host.ends_with(s)),
    };
    !local
}

/// What the server allows before anyone signs in (open signup, setup code).
pub fn server_info<T: Transport>(t: &T) -> Result<ServerInfo> {
    call(t, "GET", "/v1/info", None, NONE)
}

fn call<T: Transport, R: DeserializeOwned>(t: &T, method: &str, path: &str, token: Option<&str>, body: Option<&impl Serialize>) -> Result<R> {
    block_on(call_async(t, method, path, token, body))
}

fn raw<T: Transport>(t: &T, method: &str, path: &str, token: Option<&str>, body: Option<Vec<u8>>) -> Result<(u16, Vec<u8>)> {
    block_on(raw_async(t, method, path, token, body))
}

async fn call_async<T: AsyncTransport, R: DeserializeOwned>(t: &T, method: &str, path: &str, token: Option<&str>, body: Option<&impl Serialize>) -> Result<R> {
    let (status, bytes) = raw_async(t, method, path, token, body.map(|b| serde_json::to_vec(b).expect("serializable"))).await?;
    let bytes = if status == 204 || bytes.is_empty() { b"null".to_vec() } else { bytes };
    serde_json::from_slice(&bytes).map_err(|e| Error::Server(status, format!("unexpected response: {e}")))
}

async fn raw_async<T: AsyncTransport>(t: &T, method: &str, path: &str, token: Option<&str>, body: Option<Vec<u8>>) -> Result<(u16, Vec<u8>)> {
    let (status, bytes) = t.fetch(method, path, token, body).await?;
    if !(200..300).contains(&status) {
        return Err(Error::Server(status, String::from_utf8_lossy(&bytes).into_owned()));
    }
    Ok((status, bytes))
}

pub const NONE: Option<&()> = None;

/// How long a file no item refers to stays on the server (`Session::collect_files`).
pub const FILE_GRACE: u64 = 7 * 24 * 3600;

/// A vault by id prefix or name (case-insensitive). A full id wins over a vault
/// someone named like it.
fn find<'a>(name: &str, vaults: impl Iterator<Item = (&'a Hex, &'a Vault)> + Clone) -> Result<Hex> {
    let n = name.to_lowercase();
    if let Some((id, _)) = vaults.clone().find(|(id, _)| id.to_string() == n) {
        return Ok(*id);
    }
    let hits: Vec<Hex> = vaults.filter(|(id, v)| v.meta.name.to_lowercase() == n || id.to_string().starts_with(&n)).map(|(id, _)| *id).collect();
    match hits.as_slice() {
        [one] => Ok(*one),
        [] => Err(Error::NotFound(format!("vault {name}"))),
        _ => Err(Error::NotFound(format!("one vault called {name} (several match)"))),
    }
}

/// The outcome of `Session::sign_in_async`.
#[allow(clippy::large_enum_variant)] // short-lived, and `Done` is the common case
pub enum SignIn<T: AsyncTransport> {
    Done(Session<T>),
    /// The account needs a security key (DESIGN "Signing in with a security key").
    Key(Pending<T>),
}

/// A signed login waiting a few minutes for the account's security key: its
/// answer, a recovery code, or the approval page (`page`) finishes it. It keeps
/// the Account Unlock Key, to open the Account Key once signed in, but not the
/// login key.
pub struct Pending<T: AsyncTransport> {
    t: Option<T>,
    account_id: plaintext_core::crypto::Id,
    unlock_key: plaintext_core::crypto::Key,
    pub needed: KeyNeeded,
    /// The session and trust token, once the server finished the sign-in, so
    /// opening the account can be retried without the key.
    done: Option<(String, String)>,
}

impl<T: AsyncTransport> Pending<T> {
    /// What to keep to pick this up in another process (the browser extension's
    /// background can be stopped while the approval page is open). As sensitive
    /// as the Account Key: keep it only in memory.
    pub fn state(&self) -> serde_json::Value {
        serde_json::json!({ "account_id": hex::encode(self.account_id), "unlock_key": hex::encode(&self.unlock_key[..]), "needed": self.needed })
    }

    pub fn restore(t: T, state: &serde_json::Value) -> Result<Self> {
        let bad = || Error::Refused("this sign-in's saved state is damaged; sign in again".into());
        let hex32 = |k: &str| -> Option<Vec<u8>> { hex::decode(state.get(k)?.as_str()?).ok() };
        let account_id = hex32("account_id").and_then(|v| v.try_into().ok()).ok_or_else(bad)?;
        let unlock_key: [u8; 32] = hex32("unlock_key").and_then(|v| v.try_into().ok()).ok_or_else(bad)?;
        let needed = serde_json::from_value(state.get("needed").cloned().ok_or_else(bad)?).map_err(|_| bad())?;
        Ok(Pending { t: Some(t), account_id, unlock_key: zeroize::Zeroizing::new(unlock_key), needed, done: None })
    }

    /// Where the approval page is, after the server's address, for apps that
    /// can't talk to the key themselves: it asks the key in the browser.
    pub fn page(&self) -> String {
        format!("/v1/login/key#{}", hex::encode(&self.needed.challenge.0))
    }

    /// The key's relying party: this server's host as the user typed it, never
    /// what the server says, so a look-alike can't ask for the real server's answer.
    pub fn rp_id(&self) -> String {
        self.t.as_ref().map(|t| plaintext_core::crypto::rp_id(&t.login_host())).unwrap_or_default()
    }

    /// Finish with the key's `assertion`, a `recovery` code, or neither once the
    /// approval page has the key's answer (until then this fails with 409, and
    /// can be tried again). Also returns the token that spares this device the
    /// key at later sign-ins (`Session::sign_in_async`'s `trust`): keep it.
    pub async fn finish_async(&mut self, assertion: Option<Assertion>, recovery: Option<&str>) -> Result<(Session<T>, String)> {
        let t = self.t.as_ref().ok_or_else(|| Error::Refused("this sign-in is finished already".into()))?;
        if self.done.is_none() {
            let req = LoginFinish { pending: self.needed.pending.clone(), assertion, recovery: recovery.map(String::from) };
            let resp: LoginResponse = call_async(t, "POST", "/v1/login/finish", None, Some(&req)).await?;
            self.done = Some((resp.token, resp.trust.unwrap_or_default()));
        }
        let (token, trust) = self.done.clone().expect("set above");
        let (account, keyring, acct) = Session::<T>::fetch_account(t, &self.account_id, &self.unlock_key, &token).await?;
        let t = self.t.take().expect("checked above");
        Ok((Session::opened(t, token, account, keyring, &acct), trust))
    }
}

impl<T: Transport> Pending<T> {
    pub fn finish(&mut self, assertion: Option<Assertion>, recovery: Option<&str>) -> Result<(Session<T>, String)> {
        block_on(self.finish_async(assertion, recovery))
    }
}

/// A signed-in, unlocked account.
pub struct Session<T: AsyncTransport> {
    pub t: T,
    pub token: String,
    pub account: Account,
    pub keyring: Keyring,
    /// The server keyring's counter this copy last matched; `None` after `restore`.
    keyring_counter: Option<u64>,
    keyring_dirty: bool,
    pub admin: bool,
    pub vaults: BTreeMap<Hex, Vault>,
    /// Vaults the server stopped listing. Their verified state is kept, so if
    /// they come back the server can't hand us an older copy as if new. Changes
    /// made here can't be sent: sync says so until `discard_changes` drops them,
    /// keeping only that guard (`Vault::forget`).
    pub hidden: BTreeMap<Hex, Vault>,
    /// Per vault, members whose accounts the server says were deleted.
    gone: BTreeMap<Hex, Vec<String>>,
    /// What the last `sync` couldn't do, for the user to see: vaults that didn't
    /// verify (kept as last verified, or left out if never verified) and invite
    /// conflicts. One bad vault doesn't stop the rest from syncing.
    pub problems: Vec<Problem>,
    /// Vaults whose changes the last `sync` couldn't send because we may only
    /// read them now, or the server stopped listing them (`hidden`);
    /// `discard_changes` drops them.
    pub unsendable: Vec<Hex>,
}

/// Something the last sync couldn't do, in words (which may end with a CLI hint).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Problem {
    pub text: String,
    /// The vault it suggests leaving: never one of your own, since leaving a
    /// vault nobody else uses deletes it.
    pub leave: Option<Hex>,
    /// The vault it's about, so leaving that vault drops it.
    pub vault: Option<Hex>,
}

impl From<String> for Problem {
    fn from(text: String) -> Self {
        Problem { text, leave: None, vault: None }
    }
}

impl From<&str> for Problem {
    fn from(text: &str) -> Self {
        text.to_string().into()
    }
}

impl std::ops::Deref for Problem {
    type Target = str;
    fn deref(&self) -> &str {
        &self.text
    }
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}

/// The logic, written once. Browsers call these through an `AsyncTransport`;
/// everything else uses the blocking methods below, which run the same code.
impl<T: AsyncTransport> Session<T> {
    /// Sign in with keys derived from (password, Secret Key) or an agent key.
    /// An account that needs a security key is refused: people's apps use `sign_in_async`.
    pub async fn login_async(t: T, d: &Derived, device: &str) -> Result<Self> {
        let req = plaintext_core::login_request(d, now_ms(), device, &t.login_host());
        let resp: LoginResponse = call_async(&t, "POST", "/v1/login", None, Some(&req)).await?;
        Self::open_async(t, &d.account_id, &d.unlock_key, resp.token).await
    }

    /// Sign in with (password, Secret Key). If the account needs a security key
    /// and `trust` (this device's token from an earlier such sign-in) doesn't
    /// spare it, a `Pending` sign-in comes back for the key to finish.
    pub async fn sign_in_async(t: T, d: &Derived, device: &str, trust: Option<&str>) -> Result<SignIn<T>> {
        let mut req = plaintext_core::login_request(d, now_ms(), device, &t.login_host());
        req.keys = true;
        req.trust = trust.map(String::from);
        let resp: LoginResponse = call_async(&t, "POST", "/v1/login", None, Some(&req)).await?;
        match resp.key {
            Some(needed) => Ok(SignIn::Key(Pending { t: Some(t), account_id: d.account_id, unlock_key: d.unlock_key.clone(), needed, done: None })),
            None => Ok(SignIn::Done(Self::open_async(t, &d.account_id, &d.unlock_key, resp.token).await?)),
        }
    }

    async fn open_async(t: T, account_id: &plaintext_core::crypto::Id, unlock_key: &plaintext_core::crypto::Key, token: String) -> Result<Self> {
        let (account, keyring, acct) = Self::fetch_account(&t, account_id, unlock_key, &token).await?;
        Ok(Self::opened(t, token, account, keyring, &acct))
    }

    async fn fetch_account(t: &T, account_id: &plaintext_core::crypto::Id, unlock_key: &plaintext_core::crypto::Key, token: &str) -> Result<(Account, Keyring, AccountResponse)> {
        let acct: AccountResponse = call_async(t, "GET", "/v1/account", Some(token), NONE).await?;
        let (account, keyring) = plaintext_core::unlock_with(account_id, unlock_key, &acct)?;
        Ok((account, keyring, acct))
    }

    fn opened(t: T, token: String, account: Account, keyring: Keyring, acct: &AccountResponse) -> Self {
        Session {
            t,
            token,
            account,
            keyring,
            keyring_counter: Some(acct.keyring_counter),
            keyring_dirty: false,
            admin: acct.admin,
            vaults: BTreeMap::new(),
            hidden: BTreeMap::new(),
            gone: BTreeMap::new(),
            problems: Vec::new(),
            unsendable: Vec::new(),
        }
    }

    /// Pick up a stored session (token + Account Key, e.g. from the OS keychain)
    /// without re-entering the password.
    pub async fn resume_async(t: T, token: String, account: Account) -> Result<Self> {
        let acct: AccountResponse = call_async(&t, "GET", "/v1/account", Some(&token), NONE).await?;
        let keyring = Keyring::open(&account, &acct.keyring.0)?;
        Ok(Session { t, token, account, keyring, keyring_counter: Some(acct.keyring_counter), keyring_dirty: false, admin: acct.admin, vaults: BTreeMap::new(), hidden: BTreeMap::new(), gone: BTreeMap::new(), problems: Vec::new(), unsendable: Vec::new() })
    }

    /// Pick up a stored session with no network: the token and Account Key plus
    /// this device's own keyring copy (`keyring_snapshot`). The next `sync`
    /// checks the token and folds in whatever the server's keyring gained.
    pub fn restore(t: T, token: String, account: Account, keyring_blob: &[u8]) -> Result<Self> {
        let keyring = Keyring::open(&account, keyring_blob)?;
        // No counter yet: the first sync or keyring save merges, so pins this copy never sent go up.
        Ok(Session { t, token, account, keyring, keyring_counter: None, keyring_dirty: false, admin: false, vaults: BTreeMap::new(), hidden: BTreeMap::new(), gone: BTreeMap::new(), problems: Vec::new(), unsendable: Vec::new() })
    }

    pub async fn call_async<R: DeserializeOwned>(&self, method: &str, path: &str, body: Option<&impl Serialize>) -> Result<R> {
        call_async(&self.t, method, path, Some(&self.token), body).await
    }

    pub fn me(&self) -> Me {
        self.keyring.me()
    }

    pub fn username(&self) -> &str {
        &self.keyring.username
    }

    /// Pull every vault, verify, merge, push local changes, and sync the keyring.
    pub async fn sync_async(&mut self) -> Result<()> {
        let acct: AccountResponse = self.call_async("GET", "/v1/account", NONE).await?;
        self.admin = acct.admin;
        // Another device (or this one, restored offline) changed the keyring: fold it in.
        if Some(acct.keyring_counter) != self.keyring_counter {
            self.merge_server_keyring(&acct)?;
        }
        let unlisted: Vec<Hex> = self.vaults.keys().filter(|id| !acct.vaults.contains(id)).copied().collect();
        for id in unlisted {
            let v = self.vaults.remove(&id).expect("listed above");
            self.hidden.insert(id, v);
        }
        self.problems.clear();
        self.unsendable.clear();
        // A vault whose account is out of storage (507) keeps its unpushed changes and
        // reports the error at the end, without holding up the other vaults. So does
        // a member removal another device raced, or one too big to send (413); the next sync retries.
        let mut full = None;
        let mut failed = vec![];
        for id in &acct.vaults {
            let v = self.hidden.remove(id).unwrap_or_else(|| Vault::new(*id));
            self.vaults.entry(*id).or_insert(v);
            match self.sync_and_tidy(id).await {
                // Best effort: an older server or a role that changed mid-run just means next time.
                Ok(()) => drop(self.collect_files_async(id, 0).await),
                // Every held-back change comes after a pull, so collecting is still safe, and
                // over quota it's what makes room for the refused change (though another
                // device may collect that change's own uploads meanwhile; DESIGN "Attachments").
                Err(e) if e.held_back() => {
                    drop(self.collect_files_async(id, 0).await);
                    // A 409 is worth retrying soon, so it's the one reported.
                    if !matches!(full, Some(Error::Server(409, _))) {
                        full = Some(e);
                    }
                }
                // Anyone can share a vault with you (or an agent); one that doesn't
                // check out mustn't stop the others. Network and session errors still do.
                Err(e @ (Error::Core(_) | Error::Server(403 | 404, _) | Error::NotFound(_) | Error::Refused(_))) => {
                    let own = self.is_own(id);
                    // Never offer to leave (delete) your own vault (`leavable`).
                    // Before `self.vaults.remove` below, which `leavable` looks at.
                    let leave = self.leavable(id).then_some(*id);
                    // A vault opened before keeps its name, though it may never open again.
                    let known = self.vaults.get(id).filter(|v| v.roster.is_some()).map(|v| v.meta.name.clone());
                    let read_only = matches!(e, Error::Core(plaintext_core::Error::ReadOnly));
                    // One reset while unlisted keeps its guard for the next try.
                    if known.is_none()
                        && let Some(v) = self.vaults.remove(id).filter(|v| v.counter > 0)
                    {
                        self.hidden.insert(*id, v);
                    }
                    let opened = known.is_some();
                    let name = known.unwrap_or_else(|| id.to_string());
                    match opened {
                        // A change you can't send (you only read the vault) doesn't need you to
                        // leave; the vault itself synced, so it's named below if you pay for it.
                        true if read_only => {
                            // Only pending changes make a reader's push fail.
                            self.unsendable.push(*id);
                            self.problems.push(Problem {
                                text: format!("vault {name} wasn't updated: {e}, so this device's changes to it can't be sent"),
                                leave: None,
                                vault: Some(*id),
                            })
                        }
                        // Your own vault: a server serving an old copy mustn't talk you into deleting it.
                        _ if own => self.problems.push(Problem { text: format!("vault {name} wasn't updated: {e}"), leave: None, vault: Some(*id) }),
                        _ => {
                            let paid = if acct.paid.contains(id) { "; it counts against your storage" } else { "" };
                            // The app drops a trailing " (plaintext …" hint.
                            self.problems.push(Problem {
                                text: format!("vault {name} wasn't updated: {e}{paid} (plaintext vault leave {id} if you don't want it)"),
                                leave,
                                vault: Some(*id),
                            });
                        }
                    }
                    if !read_only {
                        failed.push(*id);
                    }
                }
                Err(e) => return Err(e),
            }
        }
        for (id, v) in self.hidden.iter().filter(|(_, v)| v.has_changes()) {
            let name = if v.meta.name.is_empty() { id.to_string() } else { v.meta.name.clone() };
            self.problems.push(Problem {
                text: format!("vault {name} isn't listed for you any more, so this device's changes to it can't be sent unless it's shared with you again"),
                leave: None,
                vault: Some(*id),
            });
            self.unsendable.push(*id);
        }
        // Someone can make you an owner and leave, and the vault counts against you
        // from then on (DESIGN "Leaving"). Name every vault you pay for: one you aren't a
        // current member of always (your own without how to leave it), one you can open
        // but didn't create only while storage is limited (or a vault you took over on
        // purpose would be named on every sync for nothing). One that failed is named above.
        for id in acct.paid.iter().filter(|id| !failed.contains(id)) {
            let text = match self.vaults.get(id).filter(|v| v.roster.is_some()) {
                Some(v) if v.creator == self.keyring.username || acct.quota.is_none() => continue,
                Some(v) => format!("vault {} counts against your storage, though {} created it (plaintext vault leave {id} to stop that)", v.meta.name, v.creator),
                None if self.is_own(id) => {
                    // The full id too: `vault leave` can't find a vault it doesn't list by name.
                    let name = self.hidden.get(id).filter(|v| v.roster.is_some()).map_or_else(|| id.to_string(), |v| format!("{} ({id})", v.meta.name));
                    format!("vault {name} counts against your storage, but the server isn't listing it for you (unless you were taken out of it, don't leave it for that: a server can hide a vault on purpose)")
                }
                None => {
                    // The name this device last saw, if it kept the vault (`hidden`).
                    let name = self.hidden.get(id).map(|v| v.meta.name.clone()).filter(|n| !n.is_empty()).unwrap_or_else(|| id.to_string());
                    format!("vault {name} counts against your storage, but only an agent of yours is in it, or your access expired (plaintext vault leave {id} to stop that)")
                }
            };
            // Ahead of what else this sync says about the vault, so an app showing
            // one problem shows the one that can offer to leave it.
            let at = self.problems.iter().position(|p| p.vault == Some(*id)).unwrap_or(self.problems.len());
            self.problems.insert(at, Problem { text, leave: self.leavable(id).then_some(*id), vault: Some(*id) });
        }
        // Users who joined with our invites get verified through their proof.
        if !self.keyring.invites.is_empty() {
            let users = self.users_async().await?;
            let (done, conflicts) = self.keyring.verify_invitees(&users);
            self.keyring_dirty |= !done.is_empty();
            for n in conflicts {
                self.problems.push(format!(
                    "someone signed up with your invite as {n}, but you already had different keys for {n}; compare fingerprints in person (plaintext user verify {n} --fingerprint …)"
                ).into());
            }
        }
        self.save_keyring_async().await?;
        full.map_or(Ok(()), Err)
    }

    /// Whether a problem may offer to leave vault `id` (`Problem::leave`): never our
    /// own, and with no verified roster here, only a vault none of our devices ever
    /// verified (an agent's, say). A fresh device can't tell which of the others we
    /// created, and a server can hide one to get it offered.
    // ponytail: a server that also serves a fresh device an older keyring (without the
    // vault's checkpoint) gets past this; the CLI hint (#998) has the same ceiling.
    fn leavable(&self, id: &Hex) -> bool {
        let here = self.vaults.get(id).or_else(|| self.hidden.get(id)).is_some_and(|v| v.roster.is_some());
        !self.is_own(id) && (here || !self.keyring.rosters.contains_key(id))
    }

    /// Whether vault `id` is our own, as far as this device can tell: one we created
    /// whose roster, as last verified here, lists us as an owner, or with no verified
    /// roster, the one made at signup. Sync never suggests leaving (deleting) it.
    fn is_own(&self, id: &Hex) -> bool {
        let me = self.username();
        match self.vaults.get(id).or_else(|| self.hidden.get(id)) {
            Some(v) if v.roster.is_some() => v.creator == me && v.role(me, now()) == Some(Role::Owner),
            // A vault reset to its rollback guard (`discard_changes`) names a creator only if
            // it was ours; the signup vault counts only for a device that never had a copy.
            v => v.filter(|v| v.counter > 0).map_or(self.keyring.default_vault == Some(*id), |v| v.creator == me),
        }
    }

    async fn pull_async(&mut self, id: &Hex) -> Result<()> {
        let v = self.vaults.get(id).ok_or(Error::NotFound("vault".into()))?;
        let resp: VaultResponse = match self.call_async("GET", &format!("/v1/vaults/{id}?{}", v.pull_query()), NONE).await {
            // Waiting won't make it smaller: report this vault, sync the others.
            Err(Error::Server(413, m)) => return Err(Error::Refused(format!("too big to pull ({m})"))),
            r => r?,
        };
        let v = self.vaults.get_mut(id).expect("checked above");
        self.keyring_dirty |= v.apply(&resp, &mut self.keyring, now())?;
        self.gone.insert(*id, resp.gone);
        Ok(())
    }

    async fn sync_and_tidy(&mut self, id: &Hex) -> Result<()> {
        self.sync_vault_async(id).await?;
        self.remove_members_async(id, None).await
    }

    /// Pull, then push pending changes.
    pub async fn sync_vault_async(&mut self, id: &Hex) -> Result<()> {
        self.pull_async(id).await?;
        self.push_async(id).await
    }

    /// Pull a vault and refuse if we may only read it. A reader's sync never
    /// pushes, so a change made anyway would stay on this device without a word.
    /// Offline it passes, so the change waits for the next sync, unless the
    /// roster we already have says we only read. An offline pull's error comes
    /// back inside (Ok(Err)) for the caller.
    async fn check_async(&mut self, id: &Hex) -> Result<Result<()>> {
        let pulled = self.pull_async(id).await;
        if let Err(e) = &pulled
            && !matches!(e, Error::Network(_) | Error::Server(500..=599, _))
        {
            return pulled.map(Ok);
        }
        // A vault never pulled has no roster yet: the pull's error says more.
        if let Err(e) = self.may_write(id) {
            return if self.vaults[id].roster.is_none() { pulled.and(Err(e)) } else { Err(e) };
        }
        Ok(pulled)
    }

    fn may_write(&self, id: &Hex) -> Result<()> {
        let v = self.vaults.get(id).ok_or(Error::NotFound("vault".into()))?;
        match v.role(self.username(), now()) {
            Some(r) if r >= Role::Writer => Ok(()),
            _ => Err(plaintext_core::Error::ReadOnly.into()),
        }
    }

    /// Make a change and push it; if we may only read the vault (see
    /// `check_async`), undo it and refuse. The change goes in before the pull,
    /// as with `sync_vault`, so the pull still sees another device's newer copy
    /// of the item (an edit keeps it as a conflict, a delete gives way to it).
    async fn change_async(&mut self, id: &Hex, f: impl FnOnce(&mut Vault)) -> Result<()> {
        let v = self.vaults.get_mut(id).ok_or(Error::NotFound("vault".into()))?;
        let before = v.snapshot(&self.account);
        f(v);
        match self.check_async(id).await {
            Ok(pulled) => {
                pulled?;
                self.push_async(id).await
            }
            // Only the refusal is undone: after any other error the change waits
            // for the next sync, as it did before this check.
            Err(e @ Error::Core(plaintext_core::Error::ReadOnly)) => {
                // The undo also undid the pull; pull again so the roster that
                // refused us stays (best effort: offline the old one says so).
                self.vaults.insert(*id, Vault::restore(&self.account, *id, &before)?);
                drop(self.pull_async(id).await);
                Err(e)
            }
            Err(e) => Err(e),
        }
    }

    /// Drop this device's changes to a vault that haven't reached the server
    /// (say, made before we became a reader) by downloading it again. The new copy
    /// must be the version this device already verified; otherwise, or if the
    /// download fails, nothing changes. Returns how many changes were dropped.
    ///
    /// A vault the server no longer lists can't be downloaded: it keeps only its
    /// rollback guard (and whether it's ours), and is downloaded in full if
    /// it's listed again.
    pub async fn discard_changes_async(&mut self, id: &Hex) -> Result<usize> {
        if self.hidden.contains_key(id) {
            // Still ours after the reset, or the next sync would suggest leaving (deleting) it.
            let me = self.is_own(id).then(|| self.username().to_owned());
            let v = self.hidden.get_mut(id).expect("checked above");
            let n = v.changes();
            if n > 0 {
                v.forget();
                if let Some(me) = me {
                    v.creator = me;
                }
            }
            self.unsendable.retain(|v| v != id);
            return Ok(n);
        }
        self.pull_async(id).await?;
        let n = self.vaults[id].changes();
        if n == 0 {
            return Ok(0);
        }
        // Edits overwrote, and deletes removed, the server's copies: fetch every item.
        let mut fresh = Vault::new(*id);
        let resp: VaultResponse = self.call_async("GET", &format!("/v1/vaults/{id}?{}", fresh.pull_query()), NONE).await?;
        let mut keyring = self.keyring.clone();
        let changed = fresh.apply(&resp, &mut keyring, now())?;
        let old = &self.vaults[id];
        if !fresh.same_head(old) {
            // Newer: another device pushed in between. Older, or a different copy
            // of the same version: the server is lying.
            return Err(if fresh.counter > old.counter { Error::Refused("the vault changed meanwhile; try again".into()) } else { plaintext_core::Error::Rollback.into() });
        }
        // The next sync uploads the keyring, as after any pull.
        self.keyring = keyring;
        self.keyring_dirty |= changed;
        self.vaults.insert(*id, fresh);
        self.unsendable.retain(|v| v != id);
        Ok(n)
    }

    /// Push pending changes (a pull came just before); on a conflict pull again and retry.
    async fn push_async(&mut self, id: &Hex) -> Result<()> {
        for _ in 0..5 {
            let me = self.me();
            let v = self.vaults.get_mut(id).ok_or(Error::NotFound("vault".into()))?;
            // Changes made while we could still write (offline, or just before a
            // demotion) can't go to a reader's vault: `push` says ReadOnly, on every
            // sync, rather than keep them without a word.
            if !v.has_changes() {
                return Ok(());
            }
            let put = v.push(&me, now())?;
            let wire = self.staged_async(id, &put).await?;
            let body = serde_json::to_vec(wire.as_ref().unwrap_or(&put)).expect("serializable");
            match raw_async(&self.t, "PUT", &format!("/v1/vaults/{id}"), Some(&self.token), Some(body)).await {
                Ok(_) => {
                    self.vaults.get_mut(id).expect("exists").pushed(&put);
                    return Ok(());
                }
                Err(Error::Server(409, _)) => self.pull_async(id).await?,
                Err(e) => return Err(e),
            }
        }
        Err(Error::Server(409, "the vault kept changing; try again".into()))
    }

    /// `put` as it goes on the wire. Items too big for one request go to the
    /// server's staging area first, in parts, and the returned push commits them.
    async fn staged_async(&self, vault: &Hex, put: &VaultPut) -> Result<Option<VaultPut>> {
        let items: usize = put.upserts.iter().map(|u| u.blob.0.len()).sum();
        if items > MAX_PUSH {
            // The server would refuse it after every part was sent (as if it had said so).
            return Err(Error::Server(413, "not sent: more items than a device can pull in one go; push fewer at a time".into()));
        }
        if put.upserts.is_empty() || items + put.manifest.body.0.len() <= STAGE_PAST {
            return Ok(None);
        }
        let stage = plaintext_core::new_item_id();
        let (mut part, mut bytes) = (Vec::new(), 0);
        for (i, u) in put.upserts.iter().enumerate() {
            part.push(u.clone());
            bytes += u.blob.0.len();
            let next = put.upserts.get(i + 1).map_or(usize::MAX, |n| n.blob.0.len());
            if bytes.saturating_add(next) > STAGE_PAST {
                let req = StageRequest { stage, upserts: std::mem::take(&mut part) };
                self.call_async::<()>("POST", &format!("/v1/vaults/{vault}/stage"), Some(&req)).await?;
                bytes = 0;
            }
        }
        Ok(Some(VaultPut {
            expected_counter: put.expected_counter,
            manifest: put.manifest.clone(),
            upserts: vec![],
            deletes: put.deletes.clone(),
            staged: Some(Staged { id: stage, count: put.upserts.len() as u64 }),
        }))
    }

    /// Sends a roster change, staging a key rotation's items if they're too big.
    async fn post_roster_async(&self, id: &Hex, mut update: RosterUpdate) -> Result<()> {
        if let Some(r) = &update.rotation
            && let Some(wire) = self.staged_async(id, r).await?
        {
            update.rotation = Some(wire);
        }
        self.call_async("POST", &format!("/v1/vaults/{id}/roster"), Some(&update)).await
    }

    /// Removes `who` (if given) with a new vault key. Members whose access expired,
    /// or whose accounts were deleted, go in the same roster version (the server
    /// refuses a roster naming a deleted account); without `who` that happens only
    /// on an owner's device with nothing unpushed, whichever notices first.
    async fn remove_members_async(&mut self, id: &Hex, who: Option<&str>) -> Result<()> {
        let me = self.username().to_string();
        let Some(v) = self.vaults.get(id) else { return Ok(()) };
        if who.is_none() && (v.role(&me, now()) != Some(Role::Owner) || v.has_changes()) {
            return Ok(());
        }
        let gone = self.gone.get(id).map(Vec::as_slice).unwrap_or_default();
        let mut out: Vec<&str> = v
            .roster
            .iter()
            .flat_map(|r| &r.members)
            .filter(|m| m.username != me && (m.expires.is_some_and(|e| now() >= e) || gone.contains(&m.username)))
            .map(|m| m.username.as_str())
            .collect();
        out.extend(who.filter(|w| !out.contains(w)));
        if out.is_empty() {
            return Ok(());
        }
        let update = v.revoke(&self.me(), &out, now())?;
        self.post_roster_async(id, update).await?;
        self.pull_async(id).await
    }

    /// Delete the vault's files that no item refers to once this device has seen
    /// them so for `FILE_GRACE` (`Vault::collect_files`). They come from deleted
    /// items, edits that dropped them, and uploads whose item never got pushed;
    /// they count against the quota until then. Writers only, and only right
    /// after a pull (`sync` does that). The grace runs on the server's clock;
    /// tests move it forward by `skew` seconds.
    async fn collect_files_async(&mut self, vault: &Hex, skew: u64) -> Result<()> {
        let v = self.vaults.get(vault).ok_or(Error::NotFound("vault".into()))?;
        if v.role(self.username(), now()).is_none_or(|r| r < Role::Writer) {
            return Ok(());
        }
        let list: FileList = self.call_async("GET", &format!("/v1/vaults/{vault}/files"), NONE).await?;
        let listed: Vec<Hex> = list.files.into_iter().map(|f| f.id).collect();
        let due = self.vaults.get_mut(vault).expect("checked above").collect_files(&listed, list.now + skew, FILE_GRACE);
        for f in &due {
            self.call_async::<()>("DELETE", &format!("/v1/vaults/{vault}/files/{f}"), NONE).await?;
        }
        Ok(())
    }

    /// Fold in this device's own copy of the keyring (saved after the last run):
    /// pins it holds can't be erased by a server serving an older keyring.
    pub async fn merge_local_keyring_async(&mut self, local_blob: &[u8]) -> Result<()> {
        let mut local = Keyring::open(&self.account, local_blob)?;
        if local.username != self.keyring.username {
            return Err(plaintext_core::Error::Tampered.into());
        }
        self.keyring_dirty |= local.merge_from(&self.keyring);
        self.keyring = local;
        self.save_keyring_async().await
    }

    /// This device's copy of the keyring, sealed with the Account Key. Persist it
    /// and pass it to `merge_local_keyring` after signing in again.
    pub fn keyring_snapshot(&self) -> Vec<u8> {
        self.keyring.seal(&self.account)
    }

    /// Upload the keyring if pins changed. On a conflict, merge with the server's
    /// copy: pins are only ever added, and a pin this device made wins.
    pub async fn save_keyring_async(&mut self) -> Result<()> {
        for _ in 0..5 {
            if !self.keyring_dirty {
                return Ok(());
            }
            // Restored and not yet merged: there's no counter to send, so fetch it (and fold the server's pins in) first.
            let Some(counter) = self.keyring_counter else {
                let acct: AccountResponse = self.call_async("GET", "/v1/account", NONE).await?;
                self.merge_server_keyring(&acct)?;
                continue;
            };
            let put = KeyringPut { expected_counter: counter, keyring: B64(self.keyring.seal(&self.account)) };
            match raw_async(&self.t, "PUT", "/v1/account/keyring", Some(&self.token), Some(serde_json::to_vec(&put).expect("serializable"))).await {
                Ok(_) => {
                    self.keyring_counter = Some(counter + 1);
                    self.keyring_dirty = false;
                }
                Err(Error::Server(409, _)) => {
                    let acct: AccountResponse = self.call_async("GET", "/v1/account", NONE).await?;
                    self.merge_server_keyring(&acct)?;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Fold the server's keyring into ours and take its counter.
    fn merge_server_keyring(&mut self, acct: &AccountResponse) -> Result<()> {
        let server = Keyring::open(&self.account, &acct.keyring.0)?;
        self.keyring_dirty |= self.keyring.merge_from(&server);
        self.keyring_counter = Some(acct.keyring_counter);
        Ok(())
    }

    pub fn fingerprint(&self, username: &str) -> Option<String> {
        if username == self.username() {
            return Some(self.me().fingerprint());
        }
        let c = self.keyring.contacts.get(username)?;
        Some(plaintext_core::crypto::fingerprint(username, &c.sign_pk.0, &c.enc_pk.0))
    }

    /// Everyone on the server for admins and on invite-only servers; on open
    /// (hosted) servers, only the people who joined with your invites.
    async fn users_async(&self) -> Result<Vec<UserInfo>> {
        self.call_async("GET", "/v1/users", NONE).await
    }

    /// Find a vault by id prefix or name (case-insensitive).
    pub fn vault(&self, name: &str) -> Result<Hex> {
        find(name, self.vaults.iter())
    }

    /// Like `vault`, also among vaults the server stopped listing (`hidden`).
    pub fn vault_or_hidden(&self, name: &str) -> Result<Hex> {
        find(name, self.vaults.iter().chain(&self.hidden))
    }

    /// The vault new items go to by default: the one this account made at signup.
    /// Never a vault anyone else can read: if the server stops listing that one,
    /// this fails rather than pick another (it might be shared), so nobody can
    /// collect your new logins by hiding your vault or sharing you a "Personal".
    /// Accounts with no default recorded fall back to a vault only they are in.
    pub fn default_vault(&self) -> Result<Hex> {
        let me = self.username().to_string();
        let own = |v: &&Vault| v.creator == me && v.role(&me, now()).is_some_and(|r| r >= Role::Writer);
        let found = match self.keyring.default_vault {
            Some(id) => self.vaults.get(&id).filter(own),
            None => self.vaults.values().filter(own).find(|v| v.roster.as_ref().is_some_and(|r| r.members.len() == 1)),
        };
        found.map(|v| v.id).ok_or(Error::NotFound("your default vault (the server isn't listing it); name a vault".into()))
    }

    /// One of our own vaults by name (for imports), never one shared with us.
    pub fn own_vault(&self, name: &str) -> Option<Hex> {
        let me = self.username();
        self.vaults.values().find(|v| v.creator == me && v.meta.name.eq_ignore_ascii_case(name)).map(|v| v.id)
    }

    /// Items matching `query` (title, username, URL, tags, non-secret fields), or
    /// an exact id / id prefix. `vault` narrows the search.
    pub fn find(&self, query: &str, vault: Option<&Hex>) -> Vec<(Hex, Hex, &Item)> {
        let q = query.to_lowercase();
        let mut exact = Vec::new();
        let mut loose = Vec::new();
        for (vid, v) in self.vaults.iter().filter(|(id, _)| vault.is_none_or(|w| w == *id)) {
            for (iid, item) in v.items() {
                if iid.to_string().starts_with(&q) || item.title.to_lowercase() == q {
                    exact.push((*vid, *iid, item));
                } else if item.matches(query) {
                    loose.push((*vid, *iid, item));
                }
            }
        }
        if exact.is_empty() { loose } else { exact }
    }

    /// Exactly one item for `query`, or an error naming the problem.
    pub fn one(&self, query: &str, vault: Option<&Hex>) -> Result<(Hex, Hex, Item)> {
        let hits = self.find(query, vault);
        match hits.as_slice() {
            [(v, i, item)] => Ok((*v, *i, (*item).clone())),
            [] => Err(Error::NotFound(format!("item {query}"))),
            _ => Err(Error::NotFound(format!("one item for {query} ({} match; be more specific)", hits.len()))),
        }
    }

    /// Add or replace an item and push it.
    pub async fn put_item_async(&mut self, vault: &Hex, id: Hex, item: Item) -> Result<()> {
        self.change_async(vault, |v| v.put(id, item)).await
    }

    pub async fn logout_async(&self) -> Result<()> {
        self.call_async("POST", "/v1/logout", NONE).await
    }

    /// Whether we're the only owner of vault `id` and others would keep using it
    /// without us, as the server counts them: current members other than us, our
    /// agents, and disabled or deleted accounts.
    pub async fn leaves_ownerless_async(&self, id: &Hex) -> Result<bool> {
        let me = self.username().to_string();
        let Some(v) = self.vaults.get(id) else { return Ok(false) };
        let Some(r) = &v.roster else { return Ok(false) };
        if v.role(&me, now()) != Some(Role::Owner) {
            return Ok(false);
        }
        let gone = self.gone.get(id).map(Vec::as_slice).unwrap_or_default();
        let mut keepers = Vec::new();
        for m in r.members.iter().filter(|m| m.username != me && m.expires.is_none_or(|e| e > now()) && !gone.contains(&m.username)) {
            match self.call_async::<UserInfo>("GET", &format!("/v1/users/{}", m.username), NONE).await {
                Err(Error::Server(404, _)) => {}
                Ok(u) if u.disabled || serde_json::from_slice::<Identity>(&u.identity.body.0).is_ok_and(|i| i.owner.as_deref() == Some(&me)) => {}
                Ok(_) => keepers.push(m.role),
                Err(e) => return Err(e),
            }
        }
        Ok(!keepers.is_empty() && !keepers.contains(&Role::Owner))
    }

    /// Stop using a vault, along with your agents. Its owners' devices replace the
    /// key. The vault is deleted if nobody else uses it; as its only owner, you
    /// leave the others a vault whose members and key can't change any more.
    pub async fn leave_vault_async(&mut self, id: &Hex) -> Result<()> {
        let req = self.me().sign_doc("leave", &LeaveVault { vault_id: *id, ts: now_ms() });
        self.call_async::<()>("POST", &format!("/v1/vaults/{id}/leave"), Some(&req)).await?;
        // Kept as a vault this device knows nothing about: unsent changes are
        // gone (also those to one the server stopped listing), and if someone adds
        // us again it starts afresh.
        if self.vaults.remove(id).is_some() || self.hidden.contains_key(id) {
            self.hidden.insert(*id, Vault::new(*id));
        }
        self.unsendable.retain(|v| v != id);
        // What the last sync said about it no longer applies.
        self.problems.retain(|p| p.vault != Some(*id));
        Ok(())
    }
}

impl<T: Transport> Session<T> {
    /// Create an account. The first user of a server becomes its admin and needs
    /// no invite. Show the Secret Key to the user once, then, with an invite,
    /// call `trust_inviter`.
    ///
    /// The outer error means no account was made. Once it exists the Secret Key
    /// always comes back, even if signing in right after fails (the inner error).
    pub fn signup(t: T, username: &str, password: &str, invite: Option<&str>, device: &str) -> Result<(SecretKey, Result<Self>)> {
        // Invite codes are `id.secret`; anything else is the server's setup code.
        let setup = invite.filter(|c| !c.contains('.'));
        let (sk, mut s) = plaintext_core::signup(username, password, invite.filter(|c| c.contains('.')))?;
        s.request.setup = setup.map(String::from);
        call::<_, ()>(&t, "POST", "/v1/signup", None, Some(&s.request))?;
        let session = Self::login(t, &derive(password, &sk), device);
        Ok((sk, session))
    }

    /// The invite code names who sent it and their fingerprint: pin and verify
    /// them if the server's directory agrees. If it doesn't, nothing is pinned and
    /// this fails with `KeyChanged`: someone may be in the middle. Setup codes
    /// name nobody and are ignored.
    pub fn trust_inviter(&mut self, invite: &str) -> Result<()> {
        let Some((inviter, fp)) = plaintext_core::identity::invite_sender(invite) else { return Ok(()) };
        self.verify_fingerprint(&inviter, &fp).map(|_| ())
    }

    /// Confirm `username`'s keys against a fingerprint obtained out of band (read
    /// aloud, scanned from their screen, carried in an invite). On a match they're
    /// pinned and verified, replacing an earlier pin if the server had substituted
    /// one; otherwise nothing changes and this fails with `KeyChanged`. Returns
    /// true if an earlier, different pin was replaced.
    pub fn verify_fingerprint(&mut self, username: &str, fingerprint: &str) -> Result<bool> {
        let want = fingerprint.replace([' ', '-'], "").to_uppercase();
        if self.fingerprint(username).is_some_and(|f| f.replace(' ', "") == want) {
            self.mark_verified(username)?;
            return Ok(false);
        }
        let u = self.lookup(username)?;
        let id = plaintext_core::identity::check_identity(&u.identity)?;
        if plaintext_core::crypto::fingerprint(&id.username, &id.sign_pk.0, &id.enc_pk.0).replace(' ', "") != want {
            return Err(plaintext_core::Error::KeyChanged(username.into()).into());
        }
        let replaced = self.keyring.contacts.contains_key(username);
        self.keyring.repin_verified(&u.identity)?;
        self.keyring_dirty = true;
        self.save_keyring()?;
        Ok(replaced)
    }

    /// Sign in with keys derived from (password, Secret Key) or an agent key.
    pub fn login(t: T, d: &Derived, device: &str) -> Result<Self> {
        block_on(Self::login_async(t, d, device))
    }

    pub fn sign_in(t: T, d: &Derived, device: &str, trust: Option<&str>) -> Result<SignIn<T>> {
        block_on(Self::sign_in_async(t, d, device, trust))
    }

    /// The account's security keys for sign-in (any at all means signing in needs one).
    pub fn signin_keys(&self) -> Result<SigninKeys> {
        self.call("GET", "/v1/account/signin-keys", NONE)
    }

    /// Add or remove a security key for sign-in, or replace the recovery codes:
    /// signed by the login key, so the password is needed. Returns new recovery
    /// codes (adding the first key, or `Codes`) to show once, and after adding a
    /// key a token that spares this device the key at sign-in.
    pub fn change_signin_keys(&self, d: &Derived, ts: u64, action: &SigninKeyAction) -> Result<RecoveryCodes> {
        let req = plaintext_core::signin_keys_change(d, ts, &self.t.host(), action);
        self.call("POST", "/v1/account/signin-keys", Some(&req))
    }

    /// Pick up a stored session (token + Account Key, e.g. from the OS keychain)
    /// without re-entering the password.
    pub fn resume(t: T, token: String, account: Account) -> Result<Self> {
        block_on(Self::resume_async(t, token, account))
    }

    /// Open a stored session with no network: the token and Account Key from the
    /// keychain plus this device's own sealed copies in `dir` (see `save_local`).
    /// Items can be read and edited; `sync` sends the edits once the server is back.
    pub fn offline(t: T, token: String, account: Account, dir: &Path) -> Result<Self> {
        let blob = std::fs::read(dir.join("keyring.bin")).map_err(|_| Error::NotFound("this device's saved copy".into()))?;
        let keyring = Keyring::open(&account, &blob)?;
        let mut s = Session { t, token, account, keyring, keyring_counter: None, keyring_dirty: false, admin: false, vaults: BTreeMap::new(), hidden: BTreeMap::new(), gone: BTreeMap::new(), problems: Vec::new(), unsendable: Vec::new() };
        s.load_vaults(dir);
        Ok(s)
    }

    /// Load what this device saved in `dir`: its keyring copy (merged in, so pins
    /// it holds survive a server serving an older keyring) and every vault
    /// snapshot, which carries the rollback guard. Call after signing in.
    pub fn load_local(&mut self, dir: &Path) -> Result<()> {
        self.load_vaults(dir);
        match std::fs::read(dir.join("keyring.bin")) {
            Ok(blob) => self.merge_local_keyring(&blob),
            Err(_) => Ok(()),
        }
    }

    fn load_vaults(&mut self, dir: &Path) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for f in entries.flatten() {
            let Some(name) = f.file_name().to_str().and_then(|n| n.strip_suffix(".bin")).map(str::to_owned) else { continue };
            let (name, hidden) = name.strip_suffix(".hidden").map_or((name.as_str(), false), |n| (n, true));
            let Ok(id) = name.parse::<Hex>() else { continue };
            if let Ok(blob) = std::fs::read(f.path())
                && let Ok(v) = Vault::restore(&self.account, id, &blob)
            {
                if hidden { &mut self.hidden } else { &mut self.vaults }.insert(id, v);
            }
        }
    }

    /// Save this device's state to `dir`, sealed with the Account Key: every vault
    /// snapshot (hidden ones too, so they can't come back older, kept apart so
    /// they stay hidden when opened offline) and the keyring.
    pub fn save_local(&self, dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        let write = |name: String, data: Vec<u8>| -> std::io::Result<()> {
            let tmp = dir.join(format!("{name}.tmp"));
            std::fs::write(&tmp, data)?;
            std::fs::rename(tmp, dir.join(format!("{name}.bin")))
        };
        for (hidden, list) in [(false, &self.vaults), (true, &self.hidden)] {
            for (id, v) in list {
                let (name, other) = if hidden { (format!("{id}.hidden"), id.to_string()) } else { (id.to_string(), format!("{id}.hidden")) };
                write(name, v.snapshot(&self.account))?;
                let _ = std::fs::remove_file(dir.join(format!("{other}.bin")));
            }
        }
        write("keyring".into(), self.keyring_snapshot())
    }

    pub fn call<R: DeserializeOwned>(&self, method: &str, path: &str, body: Option<&impl Serialize>) -> Result<R> {
        call(&self.t, method, path, Some(&self.token), body)
    }

    /// Pull every vault, verify, merge, push local changes, and sync the keyring.
    pub fn sync(&mut self) -> Result<()> {
        block_on(self.sync_async())
    }

    /// Pull, then push pending changes.
    pub fn sync_vault(&mut self, id: &Hex) -> Result<()> {
        block_on(self.sync_vault_async(id))
    }

    /// Pull a vault and refuse if we may only read it (`check_async`).
    pub fn writable(&mut self, id: &Hex) -> Result<()> {
        block_on(self.check_async(id)).map(drop)
    }

    fn pull(&mut self, id: &Hex) -> Result<()> {
        block_on(self.pull_async(id))
    }

    /// Drop this device's unsent changes to a vault (`discard_changes_async`).
    pub fn discard_changes(&mut self, id: &Hex) -> Result<usize> {
        block_on(self.discard_changes_async(id))
    }

    fn remove_members(&mut self, id: &Hex, who: Option<&str>) -> Result<()> {
        block_on(self.remove_members_async(id, who))
    }

    fn post_roster(&self, id: &Hex, update: RosterUpdate) -> Result<()> {
        block_on(self.post_roster_async(id, update))
    }

    /// Fold in this device's own copy of the keyring (saved after the last run):
    /// pins it holds can't be erased by a server serving an older keyring.
    pub fn merge_local_keyring(&mut self, local_blob: &[u8]) -> Result<()> {
        block_on(self.merge_local_keyring_async(local_blob))
    }

    /// Upload the keyring if pins changed. On a conflict, merge with the server's
    /// copy: pins are only ever added, and a pin this device made wins.
    pub fn save_keyring(&mut self) -> Result<()> {
        block_on(self.save_keyring_async())
    }

    // ---------- Users ----------

    /// Everyone on the server for admins and on invite-only servers; on open
    /// (hosted) servers, only the people who joined with your invites.
    pub fn users(&self) -> Result<Vec<UserInfo>> {
        block_on(self.users_async())
    }

    /// Look a user up in the server directory and pin their keys (trust on first
    /// use; compare fingerprints to verify). Fails if they differ from a pin.
    pub fn pin_user(&mut self, username: &str) -> Result<Identity> {
        let u = self.lookup(username)?;
        let before = self.keyring.contacts.contains_key(username);
        let id = self.keyring.pin_identity(&u.identity)?;
        self.keyring_dirty |= !before;
        self.save_keyring()?;
        Ok(id)
    }

    /// A user's directory entry, by exact username.
    fn lookup(&self, username: &str) -> Result<UserInfo> {
        if !plaintext_core::identity::valid_username(username) {
            return Err(Error::NotFound(format!("user {username}")));
        }
        let u: UserInfo = match self.call("GET", &format!("/v1/users/{username}"), NONE) {
            Err(Error::Server(404, _)) => return Err(Error::NotFound(format!("user {username}"))),
            r => r?,
        };
        if u.identity.signer != username {
            return Err(plaintext_core::Error::KeyChanged(username.into()).into());
        }
        Ok(u)
    }

    pub fn mark_verified(&mut self, username: &str) -> Result<()> {
        self.keyring_dirty |= self.keyring.mark_verified(username);
        self.save_keyring()
    }

    /// An invite code for a new user (admins; anyone on open servers). Send it to them yourself.
    pub fn invite(&mut self) -> Result<String> {
        let (id, code) = self.keyring.new_invite();
        self.keyring_dirty = true;
        self.save_keyring()?;
        self.call::<()>("POST", "/v1/invites", Some(&NewInvite { id }))?;
        Ok(code)
    }

    pub fn disable_user(&self, username: &str) -> Result<()> {
        self.call("POST", &format!("/v1/users/{username}/disable"), NONE)
    }

    pub fn create_agent(&mut self, name: &str) -> Result<plaintext_core::crypto::AgentKey> {
        let (key, s) = plaintext_core::create_agent(&mut self.keyring, name)?;
        self.call::<()>("POST", "/v1/agents", Some(&s.request))?;
        self.keyring_dirty = true;
        self.save_keyring()?;
        Ok(key)
    }

    pub fn sessions(&self) -> Result<Vec<DeviceSession>> {
        self.call("GET", "/v1/sessions", NONE)
    }

    pub fn end_session(&self, id: &str) -> Result<()> {
        self.call("DELETE", &format!("/v1/sessions/{id}"), NONE)
    }

    pub fn change_password(&self, old: &Derived, sk: &SecretKey, new_password: &str) -> Result<()> {
        let pc = plaintext_core::change_password(old, &self.account, sk, new_password, now_ms());
        self.call("POST", "/v1/account/password", Some(&pc))
    }

    /// Delete this account for good, with its agents, inbox and share links.
    /// Vaults nobody else uses are deleted; shared ones stay with the others,
    /// whose owners' devices replace the key. Needs the password again (`d`):
    /// the session token alone can't delete an account. Refused while this
    /// account is the only owner of a vault others use.
    pub fn delete_account(&mut self, d: &Derived) -> Result<()> {
        // A full account (507) or a too-big change (413) can't be sent, so it goes
        // with the account; a 409 is worth a retry first.
        match self.sync() {
            Ok(()) | Err(Error::Server(413 | 507, _)) => {}
            Err(e) => return Err(e),
        }
        let mut blocking = Vec::new();
        for (id, v) in &self.vaults {
            if self.leaves_ownerless(id)? {
                blocking.push(v.meta.name.clone());
            }
        }
        if !blocking.is_empty() {
            return Err(Error::Refused(format!(
                "you're the only owner of {}, which others use: make one of them an owner, remove them, or leave it, first",
                blocking.join(", ")
            )));
        }
        self.call("DELETE", "/v1/account", Some(&plaintext_core::delete_account(d, now_ms(), &self.t.host())))
    }

    pub fn logout(&self) -> Result<()> {
        block_on(self.logout_async())
    }

    // ---------- Vaults ----------

    pub fn create_vault(&mut self, name: &str) -> Result<Hex> {
        let (v, nv) = Vault::create(&self.me(), name)?;
        self.call::<()>("POST", "/v1/vaults", Some(&nv))?;
        let id = v.id;
        self.vaults.insert(id, v);
        // Record it in the keyring now, so this account's new devices know it's a vault
        // of ours and never offer to leave (delete) it (`leavable`). Best effort: the
        // vault exists either way, and the next sync saves the keyring.
        drop(self.pull(&id).and_then(|()| self.save_keyring()));
        Ok(id)
    }

    pub fn rename_vault(&mut self, id: &Hex, meta: VaultMeta) -> Result<()> {
        block_on(self.change_async(id, |v| v.set_meta(meta)))
    }

    /// Give `username` access to a vault. Pins them first if they're new to us.
    pub fn share_vault(&mut self, id: &Hex, username: &str, role: Role, expires: Option<u64>) -> Result<()> {
        if !self.keyring.contacts.contains_key(username) {
            self.pin_user(username)?;
        }
        // A change the server holds back (the account is full) waits; promoting
        // someone doesn't need it sent first.
        match self.sync_vault(id) {
            Err(e) if !e.held_back() => return Err(e),
            _ => {}
        }
        self.remove_members(id, None)?;
        let v = self.vaults.get(id).ok_or(Error::NotFound("vault".into()))?;
        // Members who left have to go first, with a new key, which waits for the unsent changes.
        if let Some(who) = self.gone.get(id).and_then(|g| g.first()).filter(|_| v.has_changes()) {
            return Err(Error::Refused(format!(
                "{who} left {} (or was deleted); its key has to change first, which needs your unsent changes to it sent (make room) or deleted",
                v.meta.name
            )));
        }
        let update = v.grant(&self.me(), &self.keyring, username, role, expires, now())?;
        self.post_roster(id, update)?;
        self.pull(id)?;
        // Record the new roster in the keyring now, so this account's other
        // devices (and new ones) can't be shown the vault from before it.
        self.save_keyring()
    }

    /// Remove someone and replace the vault key.
    pub fn revoke(&mut self, id: &Hex, username: &str) -> Result<()> {
        self.sync_vault(id)?;
        self.vaults.get(id).ok_or(Error::NotFound("vault".into()))?;
        self.remove_members(id, Some(username))?;
        self.save_keyring()
    }

    /// See `leaves_ownerless_async`.
    pub fn leaves_ownerless(&self, id: &Hex) -> Result<bool> {
        block_on(self.leaves_ownerless_async(id))
    }

    /// See `leave_vault_async`.
    pub fn leave_vault(&mut self, id: &Hex) -> Result<()> {
        block_on(self.leave_vault_async(id))
    }

    pub fn audit(&self, id: &Hex) -> Result<Vec<AuditEntry>> {
        self.call("GET", &format!("/v1/vaults/{id}/audit"), NONE)
    }

    /// Add or replace an item and push it.
    pub fn put_item(&mut self, vault: &Hex, id: Hex, item: Item) -> Result<()> {
        block_on(self.put_item_async(vault, id, item))
    }

    /// Delete an item and push. Its attachments stay on the server until a later
    /// sync collects them (`collect_files`), so another device that brings the item
    /// back with an edit it hadn't pushed doesn't find its files gone.
    pub fn delete_item(&mut self, vault: &Hex, id: Hex) -> Result<()> {
        block_on(self.change_async(vault, |v| v.delete(id)))
    }

    /// Save imported items: each source vault goes to our own vault of that name
    /// (made if needed; "Personal" and unnamed ones to the default vault), or all
    /// to `into`. Refused before anything is saved if a vault would hold more than
    /// one pull brings (`api::MAX_PUSH`). Every item goes into this device's copy
    /// before anything is pushed, so a failed push loses nothing: the report
    /// carries that error, and the items go out with the next sync. Once an upload
    /// fails, the remaining attachments are left out and listed. Refused before
    /// anything changes if we may only read an existing target (see `writable`).
    #[cfg(not(target_arch = "wasm32"))]
    pub fn import(&mut self, imported: Vec<import::Imported>, into: Option<Hex>) -> Result<ImportReport> {
        // Where each part goes: a vault we have, or (Err) one to make. Kept, so a
        // pull here that renames a vault can't send items to an unchecked one.
        let mut targets = Vec::new();
        let mut checked = Vec::new();
        for v in imported {
            let to = match into {
                Some(id) => Ok(id),
                None if v.name.is_empty() || v.name.eq_ignore_ascii_case("personal") => Ok(self.default_vault()?),
                None => self.own_vault(&v.name).ok_or(v.name),
            };
            if let Ok(id) = to
                && !checked.contains(&id)
            {
                self.writable(&id)?;
                checked.push(id);
            }
            targets.push((to, v.items));
        }
        // Sealed, an item is padded to 256 bytes plus 41, and each attachment adds
        // a reference of less than its name plus 256.
        let sealed = |it: &Item, files: usize| serde_json::to_vec(it).map_or(0, |j| (j.len() + files).div_ceil(256) * 256 + 41);
        let mut size = BTreeMap::<_, usize>::new();
        for (to, items) in &targets {
            let have = || to.as_ref().ok().and_then(|id| self.vaults.get(id)).map_or(0, |v| v.items().map(|(_, i)| sealed(i, 0)).sum());
            let adds: usize = items.iter().map(|(it, files)| sealed(it, files.iter().map(|(name, _)| name.len() + 256).sum())).sum();
            *size.entry(to.clone().map_err(|n| n.to_ascii_lowercase())).or_insert_with(have) += adds;
        }
        if let Some((to, _)) = size.iter().find(|(_, n)| **n > MAX_PUSH) {
            let name = match to {
                Ok(id) => self.vaults.get(id).map_or(String::new(), |v| v.meta.name.clone()),
                Err(name) => name.clone(),
            };
            return Err(Error::Refused(format!(
                "that's more than one vault can hold (64 MiB of items, for {name}): split the file, make a vault for each part and import each part into its own vault"
            )));
        }
        // The vaults first: if one can't be made, nothing is imported yet.
        let mut made = Vec::new();
        for (to, items) in targets {
            let vid = match to {
                Ok(id) => id,
                Err(name) => match self.own_vault(&name) {
                    Some(id) => id,
                    None => self.create_vault(&name)?,
                },
            };
            made.push((vid, items));
        }
        let mut r = ImportReport::default();
        let mut vids = Vec::new();
        for (vid, items) in made {
            for (mut it, files) in items {
                for (name, bytes) in files {
                    if r.upload_error.is_none() {
                        match self.upload_file(&vid, &name, &bytes) {
                            Ok(f) => {
                                it.files.push(f);
                                continue;
                            }
                            Err(e) => r.upload_error = Some(e),
                        }
                    }
                    r.skipped.push(format!("{}: {name}", it.title));
                }
                self.vaults.get_mut(&vid).ok_or(Error::NotFound("vault".into()))?.put(plaintext_core::new_item_id(), it);
                r.items += 1;
            }
            if !vids.contains(&vid) {
                vids.push(vid);
            }
        }
        for vid in &vids {
            if let Err(e) = self.sync_vault(vid) {
                r.sync_error.get_or_insert(e);
            }
        }
        Ok(r)
    }

    // ---------- Files ----------

    pub fn upload_file(&self, vault: &Hex, name: &str, data: &[u8]) -> Result<FileRef> {
        let id = plaintext_core::new_item_id();
        let key = plaintext_core::crypto::random_key();
        let blob = plaintext_core::seal_file(&key, &vault.0, &id.0, data);
        raw(&self.t, "PUT", &format!("/v1/vaults/{vault}/files/{id}"), Some(&self.token), Some(blob.clone()))?;
        Ok(FileRef {
            id,
            name: plaintext_core::item::safe_file_name(name),
            size: data.len() as u64,
            key: B64(key.to_vec()),
            hash: B64(plaintext_core::crypto::sha256(&blob).to_vec()),
        })
    }

    /// The files uploaded to a vault, with their sealed sizes, whether or not an item lists them (writers).
    pub fn files(&self, vault: &Hex) -> Result<FileList> {
        self.call("GET", &format!("/v1/vaults/{vault}/files"), NONE)
    }

    /// `collect_files_async`, for tests that move the clock.
    #[cfg(test)]
    pub(crate) fn collect_files(&mut self, vault: &Hex, skew: u64) -> Result<()> {
        block_on(self.collect_files_async(vault, skew))
    }

    /// Delete an uploaded file from the server (items that list it can no longer fetch it).
    pub fn delete_file(&self, vault: &Hex, id: &Hex) -> Result<()> {
        self.call("DELETE", &format!("/v1/vaults/{vault}/files/{id}"), NONE)
    }

    pub fn download_file(&self, vault: &Hex, f: &FileRef) -> Result<Vec<u8>> {
        let (_, blob) = raw(&self.t, "GET", &format!("/v1/vaults/{vault}/files/{}", f.id), Some(&self.token), None)?;
        if plaintext_core::crypto::sha256(&blob)[..] != f.hash.0[..] {
            return Err(plaintext_core::Error::Tampered.into());
        }
        let key: plaintext_core::crypto::Key =
            zeroize_key(&f.key.0).ok_or(Error::Core(plaintext_core::Error::Tampered))?;
        Ok(plaintext_core::open_file(&key, &vault.0, &f.id.0, f.size, &blob)?.to_vec())
    }

    // ---------- Sharing one item ----------

    /// Send an item (or an access request) to one user's inbox, sealed to their pinned key.
    pub fn send(&mut self, to: &str, content: &Content, expires: Option<u64>) -> Result<()> {
        if !self.keyring.contacts.contains_key(to) {
            self.pin_user(to)?;
        }
        let msg = plaintext_core::send(&self.me(), &self.keyring, to, content, expires)?;
        self.call("POST", "/v1/messages", Some(&msg))
    }

    /// Messages for us. Ones that fail verification come back as errors rather than
    /// being dropped silently. Senders we haven't seen are pinned on first use.
    pub fn inbox(&mut self) -> Result<Vec<(String, Received)>> {
        let list: Vec<Signed> = self.call("GET", "/v1/messages", NONE)?;
        let mut out = Vec::new();
        for s in list {
            if !self.keyring.contacts.contains_key(&s.signer) && s.signer != self.username() {
                let _ = self.pin_user(&s.signer);
            }
            out.push((s.signer.clone(), plaintext_core::receive(&self.keyring, &s, now())));
        }
        Ok(out)
    }

    pub fn delete_message(&self, id: &Hex) -> Result<()> {
        self.call("DELETE", &format!("/v1/messages/{id}"), NONE)
    }

    /// A link anyone can open, and the full URL to send them. The key is only in
    /// the URL fragment, which browsers never send; `page` is usually `LINK_PAGE`.
    pub fn create_link(&self, page: &str, server: &str, item: &Item, expires: u64, max_views: Option<u32>) -> Result<String> {
        let (link, fragment) = plaintext_core::create_link(item, expires, max_views);
        self.call::<()>("POST", "/v1/links", Some(&link))?;
        Ok(format!("{}#{}/{}/{}", page.split('#').next().unwrap_or_default(), server.trim_end_matches('/'), link.id, fragment))
    }
}

fn zeroize_key(raw: &[u8]) -> Option<plaintext_core::crypto::Key> {
    Some(zeroize::Zeroizing::new(raw.try_into().ok()?))
}

/// Open a share link (anyone, no account): fetch the sealed blob and decrypt it.
pub fn open_link<T: Transport>(t: &T, id: &Hex, fragment: &str) -> Result<Item> {
    let blob: B64 = call(t, "GET", &format!("/v1/links/{id}"), None, NONE)?;
    Ok(plaintext_core::open_link(id, &blob.0, fragment)?)
}

#[cfg(test)]
mod tests;
