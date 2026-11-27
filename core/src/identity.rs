//! Identity keys and the keyring: each account's private keys plus the public
//! keys it has pinned for everyone else. Pinning is what stops a server from
//! swapping someone's key to read what you share with them.

use std::collections::BTreeMap;

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use serde::de::DeserializeOwned;
use x25519_dalek::StaticSecret;
use zeroize::Zeroizing;

use crate::Error;
use crate::api::*;
use crate::crypto::*;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Contact {
    pub sign_pk: B64,
    pub enc_pk: B64,
    /// Confirmed out of band: by fingerprint, QR, or an invite this account sent.
    #[serde(default)]
    pub verified: bool,
}

/// Sealed with the Account Key and synced, so pins follow the user to new devices.
#[derive(Serialize, Deserialize, Clone)]
pub struct Keyring {
    pub username: String,
    sign_sk: B64,
    enc_sk: B64,
    #[serde(default)]
    pub contacts: BTreeMap<String, Contact>,
    /// Secrets of invites this account sent and nobody has used yet.
    #[serde(default)]
    pub invites: BTreeMap<Hex, B64>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl Drop for Keyring {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.sign_sk.0.zeroize();
        self.enc_sk.0.zeroize();
    }
}

/// The unlocked keys of the signed-in account.
pub struct Me {
    pub username: String,
    pub sign: SigningKey,
    pub enc: StaticSecret,
}

impl Me {
    pub fn sign_pk(&self) -> B64 {
        B64(self.sign.verifying_key().to_bytes().to_vec())
    }
    pub fn enc_pk(&self) -> B64 {
        B64(x25519_dalek::PublicKey::from(&self.enc).as_bytes().to_vec())
    }
    pub fn member(&self, role: Role) -> Member {
        Member { username: self.username.clone(), sign_pk: self.sign_pk(), enc_pk: self.enc_pk(), role, expires: None }
    }
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.username, &self.sign_pk().0, &self.enc_pk().0)
    }

    pub fn sign_doc<T: Serialize>(&self, domain: &str, v: &T) -> Signed {
        let body = serde_json::to_vec(v).expect("serializable");
        let sig = sign(&self.sign, domain, &body);
        Signed { body: B64(body), signer: self.username.clone(), sig: B64(sig.to_vec()) }
    }
}

/// Check `s` is signed by `sign_pk` and parse its body.
pub fn verify_doc<T: DeserializeOwned>(s: &Signed, domain: &str, sign_pk: &[u8]) -> Result<T, Error> {
    verify(sign_pk, domain, &s.body.0, &s.sig.0)?;
    serde_json::from_slice(&s.body.0).map_err(|_| Error::BadJson)
}

pub fn valid_username(u: &str) -> bool {
    (2..=32).contains(&u.len())
        && u.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        && u.as_bytes()[0].is_ascii_alphanumeric()
}

impl Keyring {
    pub fn new(username: &str) -> Keyring {
        Keyring {
            username: username.into(),
            sign_sk: B64(random::<32>().to_vec()),
            enc_sk: B64(random::<32>().to_vec()),
            contacts: BTreeMap::new(),
            invites: BTreeMap::new(),
            extra: Default::default(),
        }
    }

    pub fn me(&self) -> Me {
        let s: [u8; 32] = self.sign_sk.0.as_slice().try_into().expect("32-byte key");
        let e: [u8; 32] = self.enc_sk.0.as_slice().try_into().expect("32-byte key");
        Me { username: self.username.clone(), sign: SigningKey::from_bytes(&s), enc: StaticSecret::from(e) }
    }

    pub fn seal(&self, account: &crate::Account) -> Vec<u8> {
        let json = Zeroizing::new(serde_json::to_vec(self).expect("serializable"));
        seal(&account.account_key, &ad("keyring", &[&account.id]), &json)
    }

    pub fn open(account: &crate::Account, blob: &[u8]) -> Result<Keyring, Error> {
        let raw = open(&account.account_key, &ad("keyring", &[&account.id]), blob)?;
        serde_json::from_slice(&raw).map_err(|_| Error::BadJson)
    }

    /// This account's self-signed public identity.
    pub fn identity(&self, kind: Kind, owner: Option<String>) -> Signed {
        let me = self.me();
        me.sign_doc("identity", &Identity { username: me.username.clone(), kind, owner, sign_pk: me.sign_pk(), enc_pk: me.enc_pk() })
    }

    /// The pinned signing key for `username` (ourselves included).
    pub fn sign_pk(&self, username: &str) -> Option<Vec<u8>> {
        if username == self.username {
            return Some(self.me().sign_pk().0);
        }
        self.contacts.get(username).map(|c| c.sign_pk.0.clone())
    }

    /// Pin a user's keys on first sight; refuse if they differ from the pinned ones.
    /// Returns true if the keyring changed (the caller then syncs it).
    pub fn pin(&mut self, username: &str, sign_pk: &B64, enc_pk: &B64) -> Result<bool, Error> {
        if username == self.username {
            let me = self.me();
            return if me.sign_pk() == *sign_pk && me.enc_pk() == *enc_pk { Ok(false) } else { Err(Error::KeyChanged(username.into())) };
        }
        match self.contacts.get(username) {
            Some(c) if c.sign_pk == *sign_pk && c.enc_pk == *enc_pk => Ok(false),
            Some(_) => Err(Error::KeyChanged(username.into())),
            None => {
                self.contacts.insert(username.into(), Contact { sign_pk: sign_pk.clone(), enc_pk: enc_pk.clone(), verified: false });
                Ok(true)
            }
        }
    }

    /// Check a user's self-signed identity and pin it.
    pub fn pin_identity(&mut self, signed: &Signed) -> Result<Identity, Error> {
        let unverified: Identity = serde_json::from_slice(&signed.body.0).map_err(|_| Error::BadJson)?;
        let id: Identity = verify_doc(signed, "identity", &unverified.sign_pk.0)?;
        if signed.signer != id.username {
            return Err(Error::BadSignature);
        }
        self.pin(&id.username, &id.sign_pk, &id.enc_pk)?;
        Ok(id)
    }

    pub fn mark_verified(&mut self, username: &str) -> bool {
        self.contacts.get_mut(username).map(|c| !std::mem::replace(&mut c.verified, true)).unwrap_or(false)
    }

    /// Make an invite: the server gets the id, the link carries id + secret.
    pub fn new_invite(&mut self) -> (Hex, String) {
        let id = Hex(random());
        let secret: [u8; 16] = random();
        self.invites.insert(id, B64(secret.to_vec()));
        (id, format!("{}.{}", id, hex::encode(secret)))
    }

    /// Mark users who signed up with one of our invites as verified, using the
    /// proof only the invite link's holder could make. Returns who was verified.
    pub fn verify_invitees(&mut self, users: &[UserInfo]) -> Vec<String> {
        let mut done = Vec::new();
        for u in users {
            let Some(inv) = &u.invite else { continue };
            let Some(secret) = self.invites.get(&inv.id) else { continue };
            if hmac(&secret.0, &u.identity.body.0)[..] != inv.proof.0[..] {
                continue;
            }
            if self.pin_identity(&u.identity).is_ok() {
                self.mark_verified(&u.identity.signer);
                self.invites.remove(&inv.id);
                done.push(u.identity.signer.clone());
            }
        }
        done
    }
}

/// Parse an invite code (`<id>.<secret>`) into what signup sends.
pub fn invite_proof(code: &str, identity: &Signed) -> Result<InviteProof, Error> {
    let (id, secret) = code.trim().split_once('.').ok_or(Error::BadInvite)?;
    let id: Hex = id.parse().map_err(|_| Error::BadInvite)?;
    let secret = hex::decode(secret).map_err(|_| Error::BadInvite)?;
    Ok(InviteProof { id, proof: B64(hmac(&secret, &identity.body.0).to_vec()) })
}
