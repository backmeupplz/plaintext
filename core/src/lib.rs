//! Plaintext core: all crypto and sync rules, shared by the server, the CLI, the
//! native apps (UniFFI) and the browser extensions (WASM). Sans-IO: callers move
//! the request/response types over HTTP; nothing here touches the network.

pub mod api;
pub mod crypto;
pub mod identity;
pub mod item;
pub mod tools;
pub mod vault;

use std::fmt;

use api::*;
use crypto::*;
use identity::{Keyring, Me, invite_proof, verify_doc};
use item::Item;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub use vault::{Vault, VaultMeta};

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    BadSecretKey,
    BadInvite,
    BadUsername,
    /// Wrong password/Secret Key, or the server altered a blob.
    Tampered,
    BadSignature,
    /// The server served an older or forked state than this device has seen.
    Rollback,
    /// The server left out, added or swapped an item.
    ManifestMismatch,
    /// A user's keys differ from the ones pinned for them.
    KeyChanged(String),
    UnknownUser(String),
    NotMember,
    NotOwner,
    ReadOnly,
    PendingChanges,
    Expired,
    BadJson,
    /// An agent was shown a vault its owner never signed for.
    NotFromOwner,
    /// Owners can't expire: a roster they signed must stay verifiable forever.
    OwnerExpiry,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::BadSecretKey => f.write_str("that key is mistyped"),
            Error::BadInvite => f.write_str("that invite code is mistyped"),
            Error::BadUsername => f.write_str("usernames are 2–32 lowercase letters, digits, dots, dashes or underscores"),
            Error::Tampered => f.write_str("wrong password or Secret Key, or the data was altered"),
            Error::BadSignature => f.write_str("a signature didn't check out, so the server may have altered something"),
            Error::Rollback => f.write_str("the server sent an older or different copy than this device has seen"),
            Error::ManifestMismatch => f.write_str("the server's vault doesn't match its signed manifest"),
            Error::KeyChanged(u) => write!(f, "{u}'s keys changed since you last saw them; verify their fingerprint before trusting them"),
            Error::UnknownUser(u) => write!(f, "{u} isn't in your contacts yet"),
            Error::NotMember => f.write_str("you're not a member of this vault"),
            Error::NotOwner => f.write_str("only a vault owner can do that"),
            Error::ReadOnly => f.write_str("you can only read this vault"),
            Error::PendingChanges => f.write_str("push your pending changes first"),
            Error::Expired => f.write_str("this has expired"),
            Error::BadJson => f.write_str("malformed data"),
            Error::NotFromOwner => f.write_str("this vault wasn't shared by this agent's owner, so the agent doesn't trust it"),
            Error::OwnerExpiry => f.write_str("owners can't have an expiry; give them edit access with an expiry instead"),
        }
    }
}
impl std::error::Error for Error {}

/// Plaintext is padded to this many bytes so blob sizes don't reveal lengths.
const PAD: usize = 256;

/// Pad JSON to a multiple of `PAD` bytes; trailing whitespace is valid JSON.
pub(crate) fn pad(json: &mut Vec<u8>) {
    let padded = json.len().div_ceil(PAD).max(1) * PAD;
    json.resize(padded, b' ');
}

pub(crate) fn seal_json<T: Serialize>(key: &Key, ad: &[u8], v: &T) -> Vec<u8> {
    let mut json = Zeroizing::new(serde_json::to_vec(v).expect("serializable"));
    pad(&mut json);
    seal(key, ad, &json)
}

pub(crate) fn open_json<T: for<'de> Deserialize<'de>>(key: &Key, ad: &[u8], blob: &[u8]) -> Result<T, Error> {
    serde_json::from_slice(&open(key, ad, blob)?).map_err(|_| Error::BadJson)
}

// ---------- Accounts ----------

/// An unlocked account on one device.
pub struct Account {
    pub id: Id,
    pub account_key: Key,
}

pub struct Signup {
    pub request: SignupRequest,
    pub account: Account,
    pub keyring: Keyring,
    pub vault: Option<Vault>,
}

fn new_account(d: &Derived, username: &str, kind: Kind, owner: Option<&Me>, invite: Option<&str>) -> Result<Signup, Error> {
    if !identity::valid_username(username) {
        return Err(Error::BadUsername);
    }
    let account = Account { id: d.account_id, account_key: random_key() };
    let mut keyring = Keyring::new(username);
    // An agent starts out trusting its owner, and only its owner: the server
    // can't stand up a look-alike owner (or anyone else) for it to obey.
    if let Some(o) = owner {
        keyring.pin(&o.username, &o.sign_pk(), &o.enc_pk())?;
        keyring.mark_verified(&o.username);
        keyring.owner = Some(o.username.clone());
    }
    let identity = keyring.identity(kind, owner.map(|o| o.username.clone()));
    let (vault, new_vault) = match kind {
        Kind::Human => {
            let (v, nv) = Vault::create(&keyring.me(), "Personal")?;
            keyring.default_vault = Some(v.id);
            (Some(v), Some(nv))
        }
        Kind::Agent => (None, None),
    };
    let invite = invite.map(|code| invite_proof(code, &identity)).transpose()?;
    let request = SignupRequest {
        account_id: Hex(d.account_id),
        auth_key: B64(d.auth.verifying_key().to_bytes().to_vec()),
        account_key: B64(seal_key(&d.unlock_key, &ad("account-key", &[&d.account_id]), &account.account_key)),
        identity,
        keyring: B64(keyring.seal(&account)),
        vault: new_vault,
        invite,
        setup: None,
    };
    Ok(Signup { request, account, keyring, vault })
}

/// A new human account. Show `secret_key` once (Emergency Kit) and keep it in the
/// OS keychain. `invite` is the code from an invite link (not needed by the first
/// user of a server).
pub fn signup(username: &str, password: &str, invite: Option<&str>) -> Result<(SecretKey, Signup), Error> {
    let sk = SecretKey::generate();
    let s = new_account(&derive(password, &sk), username, Kind::Human, None, invite)?;
    Ok((sk, s))
}

/// A new agent controlled by `owner`, who pins and verifies it right away. Send
/// the request with the owner's session to `POST /v1/agents`; hand the agent its key.
pub fn create_agent(owner: &mut Keyring, name: &str) -> Result<(AgentKey, Signup), Error> {
    let key = AgentKey::generate();
    let s = new_account(&derive_agent(&key), name, Kind::Agent, Some(&owner.me()), None)?;
    owner.pin_identity(&s.request.identity)?;
    owner.mark_verified(name);
    Ok((key, s))
}

/// `host` is `crypto::server_host` of the address the client connects to.
pub fn login_request(d: &Derived, ts_ms: u64, device: &str, host: &str) -> LoginRequest {
    LoginRequest { account_id: Hex(d.account_id), ts: ts_ms, sig: B64(sign_login(d, ts_ms, host).to_vec()), device: device.into(), ttl: None }
}

/// Decrypt the Account Key and keyring. Fails on a wrong password or Secret Key.
pub fn unlock(d: &Derived, resp: &AccountResponse) -> Result<(Account, Keyring), Error> {
    let account_key = open_key(&d.unlock_key, &ad("account-key", &[&d.account_id]), &resp.account_key.0)?;
    let account = Account { id: d.account_id, account_key };
    let keyring = Keyring::open(&account, &resp.keyring.0)?;
    if keyring.username != resp.username {
        return Err(Error::Tampered);
    }
    Ok((account, keyring))
}

/// Re-wrap the Account Key under a new password. Items, vaults and the Secret
/// Key stay as they are.
pub fn change_password(old: &Derived, account: &Account, sk: &SecretKey, new_password: &str, ts_ms: u64) -> PasswordChange {
    let new = derive(new_password, sk);
    let account_key = seal_key(&new.unlock_key, &ad("account-key", &[&account.id]), &account.account_key);
    let auth_key = new.auth.verifying_key().to_bytes().to_vec();
    let msg = password_change_message(&account.id, ts_ms, &auth_key, &account_key);
    use ed25519_dalek::Signer;
    PasswordChange { ts: ts_ms, auth_key: B64(auth_key), account_key: B64(account_key), sig: B64(old.auth.sign(&msg).to_bytes().to_vec()) }
}

/// Proof for `DELETE /v1/account` that whoever asks knows the password (or agent key).
pub fn delete_account(d: &Derived, ts_ms: u64, host: &str) -> AccountDelete {
    use ed25519_dalek::Signer;
    AccountDelete { ts: ts_ms, sig: B64(d.auth.sign(&account_delete_message(&d.account_id, ts_ms, host)).to_bytes().to_vec()) }
}

// ---------- Messages: items shared with one user, agent access requests ----------

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Content {
    Item(Box<Item>),
    Request(String),
}

/// The sealed part of a message names both ends, so nobody holding the envelope
/// can re-sign it as someone else or redirect it.
fn message_ad(id: &Hex, from: &str, to: &str) -> Vec<u8> {
    [ad("message", &[&id.0]), from.as_bytes().to_vec(), vec![0], to.as_bytes().to_vec()].concat()
}

/// Seal `content` to a pinned contact and sign it. An item goes out as its
/// current fields only (`Item::shareable`).
pub fn send(me: &Me, keyring: &Keyring, to: &str, content: &Content, expires: Option<u64>) -> Result<Signed, Error> {
    let c = keyring.contacts.get(to).ok_or(Error::UnknownUser(to.into()))?;
    let id = Hex(random());
    let (kind, content) = match content {
        Content::Item(it) => (MessageKind::Item, Content::Item(Box::new(it.shareable()))),
        Content::Request(t) => (MessageKind::Request, Content::Request(t.clone())),
    };
    let mut json = Zeroizing::new(serde_json::to_vec(&content).expect("serializable"));
    pad(&mut json);
    let sealed = seal_to(&c.enc_pk.0, &message_ad(&id, &me.username, to), &json)?;
    Ok(me.sign_doc("message", &Message { id, to: to.into(), kind, expires, sealed: B64(sealed) }))
}

/// Open a message from the inbox: the sender must be a pinned contact.
pub fn receive(keyring: &Keyring, s: &Signed, now: u64) -> Result<(Message, Content), Error> {
    let pk = keyring.sign_pk(&s.signer).ok_or(Error::UnknownUser(s.signer.clone()))?;
    let m: Message = verify_doc(s, "message", &pk)?;
    if m.to != keyring.username {
        return Err(Error::Tampered);
    }
    if m.expires.is_some_and(|e| now >= e) {
        return Err(Error::Expired);
    }
    let me = keyring.me();
    let raw = open_from(&me.enc, &message_ad(&m.id, &s.signer, &m.to), &m.sealed.0)?;
    let content = serde_json::from_slice(&raw).map_err(|_| Error::BadJson)?;
    Ok((m, content))
}

// ---------- Links anyone can open ----------

/// Seal an item for a link. The returned fragment goes after `#` in the URL and
/// never reaches any server. Only the item's current fields go in (`Item::shareable`).
pub fn create_link(item: &Item, expires: u64, max_views: Option<u32>) -> (NewLink, String) {
    let id = Hex(random());
    let key = random_key();
    let blob = seal_json(&key, &ad("link", &[&id.0]), &item.shareable());
    (NewLink { id, blob: B64(blob), expires, max_views }, hex::encode(&key[..]))
}

pub fn open_link(id: &Hex, blob: &[u8], fragment: &str) -> Result<Item, Error> {
    let raw = hex::decode(fragment.trim()).map_err(|_| Error::Tampered)?;
    let key: Key = Zeroizing::new(raw.as_slice().try_into().map_err(|_| Error::Tampered)?);
    open_json(&key, &ad("link", &[&id.0]), blob)
}

pub fn new_item_id() -> Hex {
    Hex(random())
}

#[cfg(test)]
mod tests;
