//! Everything a Plaintext app does over the network, on top of the sans-IO core:
//! signing in, syncing vaults (pull, verify, merge, push, retry on conflict),
//! keeping the keyring's pins in sync, sharing and agents. Every app (CLI, MCP,
//! the UniFFI bindings for iOS/Android/desktop) uses this, so sync rules exist once.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use plaintext_core::api::*;
use plaintext_core::crypto::{Derived, SecretKey, derive};
use plaintext_core::identity::{Keyring, Me};
use plaintext_core::item::{FileRef, Item};
use plaintext_core::{Account, Content, Vault, VaultMeta};
use serde::Serialize;
use serde::de::DeserializeOwned;

pub use plaintext_core;

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
impl From<plaintext_core::Error> for Error {
    fn from(e: plaintext_core::Error) -> Self {
        Error::Core(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// An inbox message as opened, or why it couldn't be.
pub type Received = std::result::Result<(Message, Content), plaintext_core::Error>;

pub fn now() -> u64 {
    now_ms() / 1000
}

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("clock after 1970").as_millis() as u64
}

/// How requests reach the server. `Http` for real use; tests and embedders may plug in others.
pub trait Transport {
    fn send(&self, method: &str, path: &str, token: Option<&str>, body: Option<Vec<u8>>) -> Result<(u16, Vec<u8>)>;
    /// The server's host as the user typed it (`crypto::server_host`); logins are signed for it.
    fn host(&self) -> String;
}

pub struct Http {
    pub base: String,
    agent: ureq::Agent,
}

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
        let bytes = resp.body_mut().with_config().limit(128 << 20).read_to_vec().map_err(|e| Error::Network(e.to_string()))?;
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
    let (status, bytes) = raw(t, method, path, token, body.map(|b| serde_json::to_vec(b).expect("serializable")))?;
    let bytes = if status == 204 || bytes.is_empty() { b"null".to_vec() } else { bytes };
    serde_json::from_slice(&bytes).map_err(|e| Error::Server(status, format!("unexpected response: {e}")))
}

fn raw<T: Transport>(t: &T, method: &str, path: &str, token: Option<&str>, body: Option<Vec<u8>>) -> Result<(u16, Vec<u8>)> {
    let (status, bytes) = t.send(method, path, token, body)?;
    if !(200..300).contains(&status) {
        return Err(Error::Server(status, String::from_utf8_lossy(&bytes).into_owned()));
    }
    Ok((status, bytes))
}

pub const NONE: Option<&()> = None;

/// How long a file no item refers to stays on the server (`Session::collect_files`).
pub const FILE_GRACE: u64 = 7 * 24 * 3600;

/// A signed-in, unlocked account.
pub struct Session<T: Transport> {
    pub t: T,
    pub token: String,
    pub account: Account,
    pub keyring: Keyring,
    keyring_counter: u64,
    keyring_dirty: bool,
    pub admin: bool,
    pub vaults: BTreeMap<Hex, Vault>,
    /// Vaults the server stopped listing. Their verified state is kept, so if
    /// they come back the server can't hand us an older copy as if new.
    pub hidden: BTreeMap<Hex, Vault>,
    /// Per vault, members whose accounts the server says were deleted.
    gone: BTreeMap<Hex, Vec<String>>,
    /// What the last `sync` couldn't do, for the user to see: vaults that didn't
    /// verify (kept as last verified, or left out if never verified) and invite
    /// conflicts. One bad vault doesn't stop the rest from syncing.
    pub problems: Vec<String>,
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
        let req = plaintext_core::login_request(d, now_ms(), device, &t.host());
        let resp: LoginResponse = call(&t, "POST", "/v1/login", None, Some(&req))?;
        let acct: AccountResponse = call(&t, "GET", "/v1/account", Some(&resp.token), NONE)?;
        let (account, keyring) = plaintext_core::unlock(d, &acct)?;
        Ok(Session {
            t,
            token: resp.token,
            account,
            keyring,
            keyring_counter: acct.keyring_counter,
            keyring_dirty: false,
            admin: acct.admin,
            vaults: BTreeMap::new(),
            hidden: BTreeMap::new(),
            gone: BTreeMap::new(),
            problems: Vec::new(),
        })
    }

    /// Pick up a stored session (token + Account Key, e.g. from the OS keychain)
    /// without re-entering the password.
    pub fn resume(t: T, token: String, account: Account) -> Result<Self> {
        let acct: AccountResponse = call(&t, "GET", "/v1/account", Some(&token), NONE)?;
        let keyring = Keyring::open(&account, &acct.keyring.0)?;
        Ok(Session { t, token, account, keyring, keyring_counter: acct.keyring_counter, keyring_dirty: false, admin: acct.admin, vaults: BTreeMap::new(), hidden: BTreeMap::new(), gone: BTreeMap::new(), problems: Vec::new() })
    }

    pub fn call<R: DeserializeOwned>(&self, method: &str, path: &str, body: Option<&impl Serialize>) -> Result<R> {
        call(&self.t, method, path, Some(&self.token), body)
    }

    pub fn me(&self) -> Me {
        self.keyring.me()
    }

    pub fn username(&self) -> &str {
        &self.keyring.username
    }

    /// Pull every vault, verify, merge, push local changes, and sync the keyring.
    pub fn sync(&mut self) -> Result<()> {
        let acct: AccountResponse = self.call("GET", "/v1/account", NONE)?;
        self.admin = acct.admin;
        let unlisted: Vec<Hex> = self.vaults.keys().filter(|id| !acct.vaults.contains(id)).copied().collect();
        for id in unlisted {
            let v = self.vaults.remove(&id).expect("listed above");
            self.hidden.insert(id, v);
        }
        self.problems.clear();
        // A vault whose account is out of storage keeps its unpushed changes and
        // reports the error at the end, without holding up the other vaults. So does
        // a member removal another device raced, or one too big to send; the next sync retries.
        let mut full = None;
        for id in &acct.vaults {
            let v = self.hidden.remove(id).unwrap_or_else(|| Vault::new(*id));
            self.vaults.entry(*id).or_insert(v);
            match self.sync_vault(id).and_then(|_| self.remove_members(id, None)) {
                // Best effort: an older server or a role that changed mid-run just means next time.
                Ok(()) => drop(self.collect_files(id, 0)),
                // Every 409 and 413 comes after a pull, so collecting is still safe, and
                // over quota it's what makes room for the refused change.
                Err(e @ Error::Server(409 | 413, _)) => {
                    drop(self.collect_files(id, 0));
                    full = Some(e);
                }
                // Anyone can share a vault with you (or an agent); one that doesn't
                // check out mustn't stop the others. Network and session errors still do.
                Err(e @ (Error::Core(_) | Error::Server(403 | 404, _) | Error::NotFound(_))) => {
                    let known = self.vaults.get(id).filter(|v| v.roster.is_some()).map(|v| v.meta.name.clone());
                    if known.is_none() {
                        self.vaults.remove(id);
                    }
                    let name = known.unwrap_or_else(|| id.to_string());
                    // Only pending changes make a reader's push fail: say how to drop them.
                    let hint = match e {
                        Error::Core(plaintext_core::Error::ReadOnly) => format!(", so this device's changes to it can't be sent; to drop them, run plaintext vault reset {}", if name.contains(char::is_whitespace) { format!("\"{name}\"") } else { name.clone() }),
                        _ => String::new(),
                    };
                    self.problems.push(format!("vault {name} wasn't updated: {e}{hint}"));
                }
                Err(e) => return Err(e),
            }
        }
        // Users who joined with our invites get verified through their proof.
        if !self.keyring.invites.is_empty() {
            let users = self.users()?;
            let (done, conflicts) = self.keyring.verify_invitees(&users);
            self.keyring_dirty |= !done.is_empty();
            for n in conflicts {
                self.problems.push(format!(
                    "someone signed up with your invite as {n}, but you already had different keys for {n}; compare fingerprints in person (plaintext user verify {n} --fingerprint …)"
                ));
            }
        }
        self.save_keyring()?;
        full.map_or(Ok(()), Err)
    }

    fn pull(&mut self, id: &Hex) -> Result<()> {
        let v = self.vaults.get(id).ok_or(Error::NotFound("vault".into()))?;
        let resp: VaultResponse = self.call("GET", &format!("/v1/vaults/{id}?{}", v.pull_query()), NONE)?;
        let v = self.vaults.get_mut(id).expect("checked above");
        self.keyring_dirty |= v.apply(&resp, &mut self.keyring, now())?;
        self.gone.insert(*id, resp.gone);
        Ok(())
    }

    /// Pull, then push pending changes.
    pub fn sync_vault(&mut self, id: &Hex) -> Result<()> {
        self.pull(id)?;
        self.push(id)
    }

    /// Pull a vault and refuse if we may only read it. A reader's sync never
    /// pushes, so a change made anyway would stay on this device without a word.
    pub fn writable(&mut self, id: &Hex) -> Result<()> {
        self.pull(id)?;
        self.may_write(id)
    }

    fn may_write(&self, id: &Hex) -> Result<()> {
        let v = self.vaults.get(id).ok_or(Error::NotFound("vault".into()))?;
        match v.role(self.username(), now()) {
            Some(r) if r >= Role::Writer => Ok(()),
            _ => Err(plaintext_core::Error::ReadOnly.into()),
        }
    }

    /// Make a change and push it, refusing first if we may only read the vault.
    /// Offline, the change still goes in and waits for the next sync, unless the
    /// roster we already have says we only read.
    fn change(&mut self, id: &Hex, f: impl FnOnce(&mut Vault)) -> Result<()> {
        let pulled = self.pull(id);
        if matches!(pulled, Err(ref e) if !matches!(e, Error::Network(_) | Error::Server(500..=599, _))) {
            return pulled;
        }
        // A vault never pulled has no roster yet: the pull's error says more.
        if let Err(e) = self.may_write(id) {
            return if self.vaults[id].roster.is_none() { pulled.and(Err(e)) } else { Err(e) };
        }
        f(self.vaults.get_mut(id).expect("checked above"));
        pulled?;
        self.push(id)
    }

    /// Drop this device's changes to a vault that haven't reached the server
    /// (say, made before we became a reader) by downloading it again. The new copy
    /// must be the version this device already verified; otherwise, or if the
    /// download fails, nothing changes. Returns how many changes were dropped.
    pub fn discard_changes(&mut self, id: &Hex) -> Result<usize> {
        self.pull(id)?;
        let n = self.vaults[id].changes();
        if n == 0 {
            return Ok(0);
        }
        // Edits overwrote, and deletes removed, the server's copies: fetch every item.
        let mut fresh = Vault::new(*id);
        let resp: VaultResponse = self.call("GET", &format!("/v1/vaults/{id}?{}", fresh.pull_query()), NONE)?;
        let mut keyring = self.keyring.clone();
        let changed = fresh.apply(&resp, &mut keyring, now())?;
        let old = &self.vaults[id];
        if !fresh.same_head(old) {
            return Err(if fresh.counter < old.counter { plaintext_core::Error::Rollback.into() } else { Error::Refused("the vault changed meanwhile; try again".into()) });
        }
        self.keyring = keyring;
        self.keyring_dirty |= changed;
        self.vaults.insert(*id, fresh);
        self.save_keyring()?;
        Ok(n)
    }

    /// Push pending changes (a pull came just before); on a conflict pull again and retry.
    fn push(&mut self, id: &Hex) -> Result<()> {
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
            match raw(&self.t, "PUT", &format!("/v1/vaults/{id}"), Some(&self.token), Some(serde_json::to_vec(&put).expect("serializable"))) {
                Ok(_) => {
                    self.vaults.get_mut(id).expect("exists").pushed(&put);
                    return Ok(());
                }
                Err(Error::Server(409, _)) => self.pull(id)?,
                Err(e) => return Err(e),
            }
        }
        Err(Error::Server(409, "the vault kept changing; try again".into()))
    }

    /// Removes `who` (if given) with a new vault key. Members whose access expired,
    /// or whose accounts were deleted, go in the same roster version (the server
    /// refuses a roster naming a deleted account); without `who` that happens only
    /// on an owner's device with nothing unpushed, whichever notices first.
    fn remove_members(&mut self, id: &Hex, who: Option<&str>) -> Result<()> {
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
        self.call::<()>("POST", &format!("/v1/vaults/{id}/roster"), Some(&update))?;
        self.pull(id)
    }

    /// Fold in this device's own copy of the keyring (saved after the last run):
    /// pins it holds can't be erased by a server serving an older keyring.
    pub fn merge_local_keyring(&mut self, local_blob: &[u8]) -> Result<()> {
        let mut local = Keyring::open(&self.account, local_blob)?;
        if local.username != self.keyring.username {
            return Err(plaintext_core::Error::Tampered.into());
        }
        self.keyring_dirty |= local.merge_from(&self.keyring);
        self.keyring = local;
        self.save_keyring()
    }

    /// This device's copy of the keyring, sealed with the Account Key. Persist it
    /// and pass it to `merge_local_keyring` after signing in again.
    pub fn keyring_snapshot(&self) -> Vec<u8> {
        self.keyring.seal(&self.account)
    }

    /// Upload the keyring if pins changed. On a conflict, merge with the server's
    /// copy: pins are only ever added, and a pin this device made wins.
    pub fn save_keyring(&mut self) -> Result<()> {
        for _ in 0..5 {
            if !self.keyring_dirty {
                return Ok(());
            }
            let put = KeyringPut { expected_counter: self.keyring_counter, keyring: B64(self.keyring.seal(&self.account)) };
            match raw(&self.t, "PUT", "/v1/account/keyring", Some(&self.token), Some(serde_json::to_vec(&put).expect("serializable"))) {
                Ok(_) => {
                    self.keyring_counter += 1;
                    self.keyring_dirty = false;
                }
                Err(Error::Server(409, _)) => {
                    let acct: AccountResponse = self.call("GET", "/v1/account", NONE)?;
                    let server = Keyring::open(&self.account, &acct.keyring.0)?;
                    self.keyring.merge_from(&server);
                    self.keyring_counter = acct.keyring_counter;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    // ---------- Users ----------

    /// Everyone on the server for admins and on invite-only servers; on open
    /// (hosted) servers, only the people who joined with your invites.
    pub fn users(&self) -> Result<Vec<UserInfo>> {
        self.call("GET", "/v1/users", NONE)
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

    pub fn fingerprint(&self, username: &str) -> Option<String> {
        if username == self.username() {
            return Some(self.me().fingerprint());
        }
        let c = self.keyring.contacts.get(username)?;
        Some(plaintext_core::crypto::fingerprint(username, &c.sign_pk.0, &c.enc_pk.0))
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
        match self.sync() {
            Ok(()) | Err(Error::Server(413, _)) => {}
            Err(e) => return Err(e),
        }
        let me = self.username().to_string();
        let mut blocking = Vec::new();
        for v in self.vaults.values() {
            let Some(r) = &v.roster else { continue };
            if v.role(&me, now()) != Some(Role::Owner) {
                continue;
            }
            // Who keeps the vault, as the server counts them: current members other
            // than us, our agents, and disabled or deleted accounts.
            let gone = self.gone.get(&v.id).map(Vec::as_slice).unwrap_or_default();
            let mut keepers = Vec::new();
            for m in r.members.iter().filter(|m| m.username != me && m.expires.is_none_or(|e| e > now()) && !gone.contains(&m.username)) {
                match self.call::<UserInfo>("GET", &format!("/v1/users/{}", m.username), NONE) {
                    Err(Error::Server(404, _)) => {}
                    Ok(u) if u.disabled || serde_json::from_slice::<Identity>(&u.identity.body.0).is_ok_and(|i| i.owner.as_deref() == Some(&me)) => {}
                    Ok(_) => keepers.push(m.role),
                    Err(e) => return Err(e),
                }
            }
            if !keepers.is_empty() && !keepers.contains(&Role::Owner) {
                blocking.push(v.meta.name.clone());
            }
        }
        if !blocking.is_empty() {
            return Err(Error::Refused(format!(
                "you're the only owner of {}, which others use: make one of them an owner, or remove them, first",
                blocking.join(", ")
            )));
        }
        self.call("DELETE", "/v1/account", Some(&plaintext_core::delete_account(d, now_ms(), &self.t.host())))
    }

    pub fn logout(&self) -> Result<()> {
        self.call("POST", "/v1/logout", NONE)
    }

    // ---------- Vaults ----------

    pub fn create_vault(&mut self, name: &str) -> Result<Hex> {
        let (v, nv) = Vault::create(&self.me(), name)?;
        self.call::<()>("POST", "/v1/vaults", Some(&nv))?;
        let id = v.id;
        self.vaults.insert(id, v);
        Ok(id)
    }

    pub fn rename_vault(&mut self, id: &Hex, meta: VaultMeta) -> Result<()> {
        self.change(id, |v| v.set_meta(meta))
    }

    /// Give `username` access to a vault. Pins them first if they're new to us.
    pub fn share_vault(&mut self, id: &Hex, username: &str, role: Role, expires: Option<u64>) -> Result<()> {
        if !self.keyring.contacts.contains_key(username) {
            self.pin_user(username)?;
        }
        self.sync_vault(id)?;
        self.remove_members(id, None)?;
        let v = self.vaults.get(id).ok_or(Error::NotFound("vault".into()))?;
        let update = v.grant(&self.me(), &self.keyring, username, role, expires, now())?;
        self.call::<()>("POST", &format!("/v1/vaults/{id}/roster"), Some(&update))?;
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

    pub fn audit(&self, id: &Hex) -> Result<Vec<AuditEntry>> {
        self.call("GET", &format!("/v1/vaults/{id}/audit"), NONE)
    }

    /// Find a vault by id prefix or name (case-insensitive).
    pub fn vault(&self, name: &str) -> Result<Hex> {
        let n = name.to_lowercase();
        let hits: Vec<Hex> = self
            .vaults
            .iter()
            .filter(|(id, v)| v.meta.name.to_lowercase() == n || id.to_string().starts_with(&n))
            .map(|(id, _)| *id)
            .collect();
        match hits.as_slice() {
            [one] => Ok(*one),
            [] => Err(Error::NotFound(format!("vault {name}"))),
            _ => Err(Error::NotFound(format!("one vault called {name} (several match)"))),
        }
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
    pub fn put_item(&mut self, vault: &Hex, id: Hex, item: Item) -> Result<()> {
        self.change(vault, |v| v.put(id, item))
    }

    /// Delete an item and push. Its attachments stay on the server until a later
    /// sync collects them (`collect_files`), so another device that brings the item
    /// back with an edit it hadn't pushed doesn't find its files gone.
    pub fn delete_item(&mut self, vault: &Hex, id: Hex) -> Result<()> {
        self.change(vault, |v| v.delete(id))
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

    /// Delete the vault's files that no item refers to once this device has seen
    /// them so for `FILE_GRACE` (`Vault::collect_files`). They come from deleted
    /// items, edits that dropped them, and uploads whose item never got pushed;
    /// they count against the quota until then. Writers only, and only right
    /// after a pull (`sync` does that). The grace runs on the server's clock;
    /// tests move it forward by `skew` seconds.
    pub(crate) fn collect_files(&mut self, vault: &Hex, skew: u64) -> Result<()> {
        let v = self.vaults.get(vault).ok_or(Error::NotFound("vault".into()))?;
        if v.role(self.username(), now()).is_none_or(|r| r < Role::Writer) {
            return Ok(());
        }
        let list = self.files(vault)?;
        let listed: Vec<Hex> = list.files.into_iter().map(|f| f.id).collect();
        let due = self.vaults.get_mut(vault).expect("checked above").collect_files(&listed, list.now + skew, FILE_GRACE);
        for f in &due {
            self.delete_file(vault, f)?;
        }
        Ok(())
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
