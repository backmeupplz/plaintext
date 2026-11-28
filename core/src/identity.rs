//! Identity keys and the keyring: each account's private keys plus the public
//! keys it has pinned for everyone else. Pinning is what stops a server from
//! swapping someone's key to read what you share with them.

use std::collections::BTreeMap;

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use serde::de::DeserializeOwned;
use x25519_dalek::StaticSecret;

use crate::Error;
use crate::api::*;
use crate::crypto::*;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Contact {
    pub sign_pk: B64,
    pub enc_pk: B64,
    pub kem_pk: B64,
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
    /// The vault this account made for itself at signup: where new items go
    /// unless told otherwise (never a vault someone else shared).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_vault: Option<Hex>,
    /// For an agent: the person who made it. Pinned and verified from the start,
    /// and the only one whose vaults the agent accepts (see `Vault::apply`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// The newest roster version (and its hash) seen for each vault, so a new
    /// device can't be shown a vault as it was before someone was removed.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub rosters: BTreeMap<Hex, (u64, B64)>,
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
    pub kem: KemKey,
}

impl Me {
    pub fn sign_pk(&self) -> B64 {
        B64(self.sign.verifying_key().to_bytes().to_vec())
    }
    pub fn enc_pk(&self) -> B64 {
        B64(x25519_dalek::PublicKey::from(&self.enc).as_bytes().to_vec())
    }
    pub fn kem_pk(&self) -> B64 {
        B64(kem_pk(&self.kem))
    }
    pub fn member(&self, role: Role) -> Member {
        Member { username: self.username.clone(), sign_pk: self.sign_pk(), enc_pk: self.enc_pk(), kem_pk: self.kem_pk(), role, expires: None }
    }
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.username, &self.sign_pk().0, &self.enc_pk().0, &self.kem_pk().0)
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
            default_vault: None,
            owner: None,
            rosters: BTreeMap::new(),
            extra: Default::default(),
        }
    }

    pub fn me(&self) -> Me {
        let s: [u8; 32] = self.sign_sk.0.as_slice().try_into().expect("32-byte key");
        let e: [u8; 32] = self.enc_sk.0.as_slice().try_into().expect("32-byte key");
        Me { username: self.username.clone(), sign: SigningKey::from_bytes(&s), enc: StaticSecret::from(e), kem: kem_key(&e) }
    }

    pub fn seal(&self, account: &crate::Account) -> Vec<u8> {
        crate::seal_json(&account.account_key, &ad("keyring", &[&account.id]), self)
    }

    pub fn open(account: &crate::Account, blob: &[u8]) -> Result<Keyring, Error> {
        let raw = open(&account.account_key, &ad("keyring", &[&account.id]), blob)?;
        serde_json::from_slice(&raw).map_err(|_| Error::BadJson)
    }

    /// This account's self-signed public identity.
    pub fn identity(&self, kind: Kind, owner: Option<String>) -> Signed {
        let me = self.me();
        me.sign_doc("identity", &Identity { username: me.username.clone(), kind, owner, sign_pk: me.sign_pk(), enc_pk: me.enc_pk(), kem_pk: me.kem_pk() })
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
    pub fn pin(&mut self, username: &str, sign_pk: &B64, enc_pk: &B64, kem_pk: &B64) -> Result<bool, Error> {
        if username == self.username {
            let me = self.me();
            return if me.sign_pk() == *sign_pk && me.enc_pk() == *enc_pk && me.kem_pk() == *kem_pk { Ok(false) } else { Err(Error::KeyChanged(username.into())) };
        }
        match self.contacts.get(username) {
            Some(c) if c.sign_pk == *sign_pk && c.enc_pk == *enc_pk && c.kem_pk == *kem_pk => Ok(false),
            Some(_) => Err(Error::KeyChanged(username.into())),
            None => {
                self.contacts.insert(username.into(), Contact { sign_pk: sign_pk.clone(), enc_pk: enc_pk.clone(), kem_pk: kem_pk.clone(), verified: false });
                Ok(true)
            }
        }
    }

    /// Check a user's self-signed identity and pin it.
    pub fn pin_identity(&mut self, signed: &Signed) -> Result<Identity, Error> {
        let id = check_identity(signed)?;
        self.pin(&id.username, &id.sign_pk, &id.enc_pk, &id.kem_pk)?;
        Ok(id)
    }

    /// Replace whatever is pinned for this user with `signed`, marked verified.
    /// Only for keys confirmed out of band (a fingerprint compared in person, an
    /// invite proof): it overrides the refusal that protects every other path.
    pub fn repin_verified(&mut self, signed: &Signed) -> Result<Identity, Error> {
        let id = check_identity(signed)?;
        if id.username == self.username {
            return Err(Error::KeyChanged(id.username));
        }
        self.contacts.insert(id.username.clone(), Contact { sign_pk: id.sign_pk.clone(), enc_pk: id.enc_pk.clone(), kem_pk: id.kem_pk.clone(), verified: true });
        Ok(id)
    }

    /// Fold another copy of this keyring (the server's) into this one, which wins:
    /// pins are only ever added, a pin this copy holds is never replaced, and
    /// verification marks carry over only for identical keys. Returns true if
    /// the result differs from `other` (so it should be uploaded).
    pub fn merge_from(&mut self, other: &Keyring) -> bool {
        for (name, c) in &other.contacts {
            let mine = self.contacts.entry(name.clone()).or_insert_with(|| c.clone());
            if mine.sign_pk == c.sign_pk && mine.enc_pk == c.enc_pk && mine.kem_pk == c.kem_pk {
                mine.verified |= c.verified;
            }
        }
        for (id, s) in &other.invites {
            self.invites.entry(*id).or_insert_with(|| s.clone());
        }
        if self.default_vault.is_none() {
            self.default_vault = other.default_vault;
        }
        if self.owner.is_none() {
            self.owner.clone_from(&other.owner);
        }
        for (id, (v, h)) in &other.rosters {
            if self.rosters.get(id).is_none_or(|(mine, _)| v > mine) {
                self.rosters.insert(*id, (*v, h.clone()));
            }
        }
        self.contacts != other.contacts
            || self.invites != other.invites
            || self.default_vault != other.default_vault
            || self.owner != other.owner
            || self.rosters != other.rosters
    }

    pub fn mark_verified(&mut self, username: &str) -> bool {
        self.contacts.get_mut(username).map(|c| !std::mem::replace(&mut c.verified, true)).unwrap_or(false)
    }

    /// Make an invite: the server gets the id; the code carries id, secret, and
    /// our username and fingerprint, so each side verifies the other on signup.
    pub fn new_invite(&mut self) -> (Hex, String) {
        let id = Hex(random());
        let secret: [u8; 16] = random();
        self.invites.insert(id, B64(secret.to_vec()));
        let fp = self.me().fingerprint().replace(' ', "");
        (id, format!("{}.{}.{}.{fp}", id, hex::encode(secret), self.username))
    }

    /// Mark users who signed up with one of our invites as verified, using the
    /// proof only the invite link's holder could make. Returns who was verified,
    /// and the names where the proof checks out but different keys are already
    /// pinned. Neither side wins those silently: a first-use pin is the server's
    /// word, and an invite proof only shows that someone holding the code made
    /// that identity, not that the name is theirs (the server lists the names).
    /// The user settles it by comparing fingerprints; the invite stays until then.
    pub fn verify_invitees(&mut self, users: &[UserInfo]) -> (Vec<String>, Vec<String>) {
        let (mut done, mut conflicts) = (Vec::new(), Vec::new());
        for u in users {
            let Some(inv) = &u.invite else { continue };
            let Some(secret) = self.invites.get(&inv.id) else { continue };
            if hmac(&secret.0, &u.identity.body.0)[..] != inv.proof.0[..] {
                continue;
            }
            match self.pin_identity(&u.identity) {
                Ok(_) => {
                    self.mark_verified(&u.identity.signer);
                    self.invites.remove(&inv.id);
                    done.push(u.identity.signer.clone());
                }
                Err(Error::KeyChanged(name)) => conflicts.push(name),
                Err(_) => {}
            }
        }
        (done, conflicts)
    }
}

/// A self-signed identity, checked: signed by its own key, under its own name.
pub fn check_identity(signed: &Signed) -> Result<Identity, Error> {
    let unverified: Identity = serde_json::from_slice(&signed.body.0).map_err(|_| Error::BadJson)?;
    let id: Identity = verify_doc(signed, "identity", &unverified.sign_pk.0)?;
    if signed.signer != id.username || !valid_kem_pk(&id.kem_pk.0) {
        return Err(Error::BadSignature);
    }
    Ok(id)
}

/// Who sent an invite code and their fingerprint, if the code carries them.
pub fn invite_sender(code: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = code.trim().split('.').collect();
    // Usernames may contain dots: the fingerprint is last, the username in between.
    (parts.len() >= 4).then(|| (parts[2..parts.len() - 1].join("."), parts[parts.len() - 1].to_string()))
}

/// Parse an invite code (`<id>.<secret>[.<inviter>.<fingerprint>]`) into what signup sends.
pub fn invite_proof(code: &str, identity: &Signed) -> Result<InviteProof, Error> {
    let mut parts = code.trim().split('.');
    let (Some(id), Some(secret)) = (parts.next(), parts.next()) else { return Err(Error::BadInvite) };
    let id: Hex = id.parse().map_err(|_| Error::BadInvite)?;
    let secret = hex::decode(secret).map_err(|_| Error::BadInvite)?;
    Ok(InviteProof { id, proof: B64(hmac(&secret, &identity.body.0).to_vec()) })
}
