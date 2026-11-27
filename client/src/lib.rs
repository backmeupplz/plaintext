//! Everything a Plaintext app does over the network, on top of the sans-IO core:
//! signing in, syncing vaults (pull, verify, merge, push, retry on conflict),
//! keeping the keyring's pins in sync, sharing and agents. Every app (CLI, MCP,
//! the UniFFI bindings for iOS/Android/desktop) uses this, so sync rules exist once.

use std::collections::BTreeMap;
use std::path::Path;
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
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::Core(e) => e.fmt(f),
            Error::Server(code, msg) => write!(f, "server said {code}: {msg}"),
            Error::Network(e) => write!(f, "couldn't reach the server: {e}"),
            Error::NotFound(what) => write!(f, "{what} not found"),
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
}

pub struct Http {
    pub base: String,
    agent: ureq::Agent,
}

impl Http {
    pub fn new(base: &str) -> Http {
        let agent = ureq::Agent::config_builder().http_status_as_error(false).build().into();
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
}

impl<T: Transport> Session<T> {
    /// Create an account. The first user of a server becomes its admin and needs
    /// no invite. Show the Secret Key to the user once.
    pub fn signup(t: T, username: &str, password: &str, invite: Option<&str>, device: &str) -> Result<(SecretKey, Self)> {
        // Invite codes are `id.secret`; anything else is the server's setup code.
        let setup = invite.filter(|c| !c.contains('.'));
        let (sk, mut s) = plaintext_core::signup(username, password, invite.filter(|c| c.contains('.')))?;
        s.request.setup = setup.map(String::from);
        call::<_, ()>(&t, "POST", "/v1/signup", None, Some(&s.request))?;
        let mut session = Self::login(t, &derive(password, &sk), device)?;
        // The invite names who sent it and their fingerprint: pin and verify them.
        if let Some((inviter, fp)) = invite.and_then(plaintext_core::identity::invite_sender) {
            session.pin_user(&inviter)?;
            if session.fingerprint(&inviter).map(|f| f.replace(' ', "")) == Some(fp) {
                session.mark_verified(&inviter)?;
            } else {
                return Err(plaintext_core::Error::KeyChanged(inviter).into());
            }
        }
        Ok((sk, session))
    }

    /// Sign in with keys derived from (password, Secret Key) or an agent key.
    pub fn login(t: T, d: &Derived, device: &str) -> Result<Self> {
        let req = plaintext_core::login_request(d, now_ms(), device);
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
        })
    }

    /// Pick up a stored session (token + Account Key, e.g. from the OS keychain)
    /// without re-entering the password.
    pub fn resume(t: T, token: String, account: Account) -> Result<Self> {
        let acct: AccountResponse = call(&t, "GET", "/v1/account", Some(&token), NONE)?;
        let keyring = Keyring::open(&account, &acct.keyring.0)?;
        Ok(Session { t, token, account, keyring, keyring_counter: acct.keyring_counter, keyring_dirty: false, admin: acct.admin, vaults: BTreeMap::new(), hidden: BTreeMap::new() })
    }

    /// Open a stored session with no network: the token and Account Key from the
    /// keychain plus this device's own sealed copies in `dir` (see `save_local`).
    /// Items can be read and edited; `sync` sends the edits once the server is back.
    pub fn offline(t: T, token: String, account: Account, dir: &Path) -> Result<Self> {
        let blob = std::fs::read(dir.join("keyring.bin")).map_err(|_| Error::NotFound("this device's saved copy".into()))?;
        let keyring = Keyring::open(&account, &blob)?;
        let mut s = Session { t, token, account, keyring, keyring_counter: 0, keyring_dirty: false, admin: false, vaults: BTreeMap::new(), hidden: BTreeMap::new() };
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
            let Some(id) = f.file_name().to_str().and_then(|n| n.strip_suffix(".bin")).and_then(|n| n.parse::<Hex>().ok()) else { continue };
            if let Ok(blob) = std::fs::read(f.path())
                && let Ok(v) = Vault::restore(&self.account, id, &blob)
            {
                self.vaults.insert(id, v);
            }
        }
    }

    /// Save this device's state to `dir`, sealed with the Account Key: every vault
    /// snapshot (hidden ones too, so they can't come back older) and the keyring.
    pub fn save_local(&self, dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        let write = |name: String, data: Vec<u8>| -> std::io::Result<()> {
            let tmp = dir.join(format!("{name}.tmp"));
            std::fs::write(&tmp, data)?;
            std::fs::rename(tmp, dir.join(format!("{name}.bin")))
        };
        for (id, v) in self.vaults.iter().chain(&self.hidden) {
            write(id.to_string(), v.snapshot(&self.account))?;
        }
        write("keyring".into(), self.keyring_snapshot())
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
        // Another device (or this one, opened offline) changed the keyring: fold it in.
        if acct.keyring_counter != self.keyring_counter {
            let server = Keyring::open(&self.account, &acct.keyring.0)?;
            self.keyring_dirty |= self.keyring.merge_from(&server);
            self.keyring_counter = acct.keyring_counter;
        }
        let unlisted: Vec<Hex> = self.vaults.keys().filter(|id| !acct.vaults.contains(id)).copied().collect();
        for id in unlisted {
            let v = self.vaults.remove(&id).expect("listed above");
            self.hidden.insert(id, v);
        }
        for id in &acct.vaults {
            let v = self.hidden.remove(id).unwrap_or_else(|| Vault::new(*id));
            self.vaults.entry(*id).or_insert(v);
            self.sync_vault(id)?;
            self.revoke_expired(id)?;
        }
        // Users who joined with our invites get verified through their proof.
        if !self.keyring.invites.is_empty() {
            let users = self.users()?;
            self.keyring_dirty |= !self.keyring.verify_invitees(&users).is_empty();
        }
        self.save_keyring()
    }

    fn pull(&mut self, id: &Hex) -> Result<()> {
        let v = self.vaults.get(id).ok_or(Error::NotFound("vault".into()))?;
        let resp: VaultResponse = self.call("GET", &format!("/v1/vaults/{id}?{}", v.pull_query()), NONE)?;
        let v = self.vaults.get_mut(id).expect("checked above");
        self.keyring_dirty |= v.apply(&resp, &mut self.keyring, now())?;
        Ok(())
    }

    /// Pull, then push pending changes; on a conflict pull again and retry.
    pub fn sync_vault(&mut self, id: &Hex) -> Result<()> {
        self.pull(id)?;
        for _ in 0..5 {
            let me = self.me();
            let v = self.vaults.get_mut(id).ok_or(Error::NotFound("vault".into()))?;
            if !v.has_changes() || v.role(&me.username, now()).is_none_or(|r| r < Role::Writer) {
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

    /// Members whose access expired get removed for real (new vault key) by
    /// whichever owner's device notices first.
    fn revoke_expired(&mut self, id: &Hex) -> Result<()> {
        let me = self.username().to_string();
        let Some(v) = self.vaults.get(id) else { return Ok(()) };
        if v.role(&me, now()) != Some(Role::Owner) || v.has_changes() {
            return Ok(());
        }
        let expired: Vec<String> = v
            .roster
            .iter()
            .flat_map(|r| &r.members)
            .filter(|m| m.expires.is_some_and(|e| now() >= e))
            .map(|m| m.username.clone())
            .collect();
        for name in expired {
            self.revoke(id, &name)?;
        }
        Ok(())
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

    pub fn users(&self) -> Result<Vec<UserInfo>> {
        self.call("GET", "/v1/users", NONE)
    }

    /// Look a user up in the server directory and pin their keys (trust on first
    /// use; compare fingerprints to verify). Fails if they differ from a pin.
    pub fn pin_user(&mut self, username: &str) -> Result<Identity> {
        let u = self.users()?.into_iter().find(|u| u.identity.signer == username).ok_or(Error::NotFound(format!("user {username}")))?;
        let before = self.keyring.contacts.contains_key(username);
        let id = self.keyring.pin_identity(&u.identity)?;
        self.keyring_dirty |= !before;
        self.save_keyring()?;
        Ok(id)
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

    /// An invite code for a new user (admins only). Send it to them yourself.
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
        self.vaults.get_mut(id).ok_or(Error::NotFound("vault".into()))?.set_meta(meta);
        self.sync_vault(id)
    }

    /// Give `username` access to a vault. Pins them first if they're new to us.
    pub fn share_vault(&mut self, id: &Hex, username: &str, role: Role, expires: Option<u64>) -> Result<()> {
        if !self.keyring.contacts.contains_key(username) {
            self.pin_user(username)?;
        }
        self.sync_vault(id)?;
        let v = self.vaults.get(id).ok_or(Error::NotFound("vault".into()))?;
        let update = v.grant(&self.me(), &self.keyring, username, role, expires, now())?;
        self.call::<()>("POST", &format!("/v1/vaults/{id}/roster"), Some(&update))?;
        self.pull(id)
    }

    /// Remove someone and replace the vault key.
    pub fn revoke(&mut self, id: &Hex, username: &str) -> Result<()> {
        self.sync_vault(id)?;
        let v = self.vaults.get(id).ok_or(Error::NotFound("vault".into()))?;
        let update = v.revoke(&self.me(), username, now())?;
        self.call::<()>("POST", &format!("/v1/vaults/{id}/roster"), Some(&update))?;
        self.pull(id)
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

    /// The vault new items go to by default: the one this account made at signup,
    /// else one it created itself. Never a vault someone else shared, so nobody
    /// can collect your new logins by sharing you a vault called "Personal".
    pub fn default_vault(&self) -> Result<Hex> {
        let me = self.username().to_string();
        let own = |v: &&Vault| v.creator == me && v.role(&me, now()).is_some_and(|r| r >= Role::Writer);
        self.keyring
            .default_vault
            .and_then(|id| self.vaults.get(&id))
            .filter(own)
            .or_else(|| self.vaults.values().find(own))
            .map(|v| v.id)
            .ok_or(Error::Core(plaintext_core::Error::ReadOnly))
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
        self.vaults.get_mut(vault).ok_or(Error::NotFound("vault".into()))?.put(id, item);
        self.sync_vault(vault)
    }

    pub fn delete_item(&mut self, vault: &Hex, id: Hex) -> Result<()> {
        self.vaults.get_mut(vault).ok_or(Error::NotFound("vault".into()))?.delete(id);
        self.sync_vault(vault)
    }

    /// Save imported items: each source vault goes to our own vault of that name
    /// (made if needed; "Personal" and unnamed ones to the default vault), or all
    /// to `into`. Attachments are uploaded. Returns how many items were saved.
    pub fn import(&mut self, imported: Vec<import::Imported>, into: Option<Hex>) -> Result<usize> {
        let mut n = 0;
        for v in imported {
            let vid = match into {
                Some(id) => id,
                None if v.name.is_empty() || v.name.eq_ignore_ascii_case("personal") => self.default_vault()?,
                None => match self.own_vault(&v.name) {
                    Some(id) => id,
                    None => self.create_vault(&v.name)?,
                },
            };
            for (mut it, files) in v.items {
                for (name, bytes) in files {
                    it.files.push(self.upload_file(&vid, &name, &bytes)?);
                }
                self.vaults.get_mut(&vid).ok_or(Error::NotFound("vault".into()))?.put(plaintext_core::new_item_id(), it);
                n += 1;
            }
            self.sync_vault(&vid)?;
        }
        Ok(n)
    }

    // ---------- Files ----------

    pub fn upload_file(&self, vault: &Hex, name: &str, data: &[u8]) -> Result<FileRef> {
        let id = plaintext_core::new_item_id();
        let key = plaintext_core::crypto::random_key();
        let blob = plaintext_core::crypto::seal(&key, &plaintext_core::crypto::ad("file", &[&vault.0, &id.0]), data);
        raw(&self.t, "PUT", &format!("/v1/vaults/{vault}/files/{id}"), Some(&self.token), Some(blob.clone()))?;
        Ok(FileRef {
            id,
            name: name.into(),
            size: data.len() as u64,
            key: B64(key.to_vec()),
            hash: B64(plaintext_core::crypto::sha256(&blob).to_vec()),
        })
    }

    pub fn download_file(&self, vault: &Hex, f: &FileRef) -> Result<Vec<u8>> {
        let (_, blob) = raw(&self.t, "GET", &format!("/v1/vaults/{vault}/files/{}", f.id), Some(&self.token), None)?;
        if plaintext_core::crypto::sha256(&blob)[..] != f.hash.0[..] {
            return Err(plaintext_core::Error::Tampered.into());
        }
        let key: plaintext_core::crypto::Key =
            zeroize_key(&f.key.0).ok_or(Error::Core(plaintext_core::Error::Tampered))?;
        Ok(plaintext_core::crypto::open(&key, &plaintext_core::crypto::ad("file", &[&vault.0, &f.id.0]), &blob)?.to_vec())
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
    /// the URL fragment; the viewer page is the static one at getplaintext.org.
    pub fn create_link(&self, server: &str, item: &Item, expires: u64, max_views: Option<u32>) -> Result<String> {
        let (link, fragment) = plaintext_core::create_link(item, expires, max_views);
        self.call::<()>("POST", "/v1/links", Some(&link))?;
        Ok(format!("https://getplaintext.org/s/#{}/{}/{}", server.trim_end_matches('/'), link.id, fragment))
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
