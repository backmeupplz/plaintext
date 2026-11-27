//! Plaintext core: all crypto and sync rules, shared by the server, the native
//! apps (UniFFI) and the browser extensions (WASM). Sans-IO: callers move the
//! request/response types over HTTP; nothing here touches the network.

pub mod api;
pub mod crypto;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use api::*;
use crypto::*;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    BadSecretKey,
    /// Wrong password/Secret Key, or the server altered a blob.
    Tampered,
    /// The server served an older vault state than this device has seen.
    Rollback,
    /// The server left out, added or swapped an item.
    ManifestMismatch,
    BadJson,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            Error::BadSecretKey => "that Secret Key is mistyped",
            Error::Tampered => "wrong password or Secret Key, or the data was altered",
            Error::Rollback => "the server sent an older copy of the vault",
            Error::ManifestMismatch => "the server's vault doesn't match its signed manifest",
            Error::BadJson => "malformed data",
        })
    }
}
impl std::error::Error for Error {}

/// A vault entry. Unknown fields are kept, so an older client never drops data
/// written by a newer one.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Item {
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub title: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub username: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub password: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub urls: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub totp: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notes: String,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// Plaintext is padded to this many bytes so blob sizes don't reveal password lengths.
const PAD: usize = 256;

fn seal_json<T: Serialize>(key: &Key, ad: &[u8], v: &T) -> Vec<u8> {
    let mut json = Zeroizing::new(serde_json::to_vec(v).expect("serializable"));
    let padded = json.len().div_ceil(PAD).max(1) * PAD;
    json.resize(padded, b' '); // trailing whitespace is valid JSON
    seal(key, ad, &json)
}

fn open_json<T: for<'de> Deserialize<'de>>(key: &Key, ad: &[u8], blob: &[u8]) -> Result<T, Error> {
    serde_json::from_slice(&open(key, ad, blob)?).map_err(|_| Error::BadJson)
}

// ---------- Account ----------

/// An unlocked account on one device.
pub struct Account {
    pub id: Id,
    pub account_key: Key,
}

pub struct Signup {
    /// Show once in the Emergency Kit; store in the OS keychain.
    pub secret_key: SecretKey,
    pub request: SignupRequest,
    pub account: Account,
    pub vault: Vault,
}

pub fn signup(password: &str) -> Signup {
    let secret_key = SecretKey::generate();
    let d = derive(password, &secret_key);
    let account = Account { id: d.account_id, account_key: random_key() };
    let vault = Vault::new(Hex(random()), random_key());
    let request = SignupRequest {
        account_id: Hex(d.account_id),
        auth_key: B64(d.auth.verifying_key().to_bytes().to_vec()),
        account_key: B64(seal_key(&d.unlock_key, &ad("account-key", &[&d.account_id]), &account.account_key)),
        vault: NewVault {
            id: vault.id,
            vault_key: B64(account.seal_vault_key(&vault)),
            manifest: B64(vault.seal_manifest(0)),
        },
    };
    Signup { secret_key, request, account, vault }
}

pub fn login_request(d: &Derived, ts: u64, device: &str) -> LoginRequest {
    LoginRequest {
        account_id: Hex(d.account_id),
        ts,
        sig: B64(sign_login(d, ts).to_vec()),
        device: device.into(),
    }
}

impl Account {
    /// Decrypt the Account Key and every vault key. Fails if the password or
    /// Secret Key is wrong, or if the server swapped any wrapped key.
    pub fn unlock(d: &Derived, resp: &AccountResponse) -> Result<(Account, Vec<Vault>), Error> {
        let account_key = open_key(&d.unlock_key, &ad("account-key", &[&d.account_id]), &resp.account_key.0)?;
        let account = Account { id: d.account_id, account_key };
        let vaults = resp
            .vaults
            .iter()
            .map(|v| Ok(Vault::new(v.id, open_key(&account.account_key, &ad("vault-key", &[&v.id.0]), &v.vault_key.0)?)))
            .collect::<Result<_, Error>>()?;
        Ok((account, vaults))
    }

    pub fn seal_vault_key(&self, v: &Vault) -> Vec<u8> {
        seal_key(&self.account_key, &ad("vault-key", &[&v.id.0]), &v.key)
    }
}

// ---------- Vault sync ----------

/// The encrypted index of a vault: its counter and the hash of every item blob.
/// Lets a client detect a server that drops, swaps, adds or rolls back items.
#[derive(Serialize, Deserialize)]
struct Manifest {
    counter: u64,
    items: BTreeMap<Hex, B64>,
}

struct Entry {
    item: Item,
    blob: Vec<u8>,
}

pub struct Vault {
    pub id: Hex,
    key: Key,
    /// Highest counter this device has verified. Persist it: it's the rollback guard.
    pub counter: u64,
    entries: BTreeMap<Hex, Entry>,
    dirty: BTreeSet<Hex>,
    deleted: BTreeSet<Hex>,
}

impl Vault {
    pub fn new(id: Hex, key: Key) -> Self {
        Self { id, key, counter: 0, entries: BTreeMap::new(), dirty: BTreeSet::new(), deleted: BTreeSet::new() }
    }

    pub fn items(&self) -> impl Iterator<Item = (&Hex, &Item)> {
        self.entries.iter().map(|(id, e)| (id, &e.item))
    }

    pub fn get(&self, id: &Hex) -> Option<&Item> {
        self.entries.get(id).map(|e| &e.item)
    }

    pub fn put(&mut self, id: Hex, item: Item) {
        self.entries.insert(id, Entry { item, blob: Vec::new() });
        self.dirty.insert(id);
        self.deleted.remove(&id);
    }

    pub fn delete(&mut self, id: Hex) {
        self.entries.remove(&id);
        self.dirty.remove(&id);
        self.deleted.insert(id);
    }

    pub fn has_changes(&self) -> bool {
        !self.dirty.is_empty() || !self.deleted.is_empty()
    }

    fn item_ad(&self, id: &Hex) -> Vec<u8> {
        ad("item", &[&self.id.0, &id.0])
    }

    fn seal_manifest(&self, counter: u64) -> Vec<u8> {
        let items = self.entries.iter().map(|(id, e)| (*id, B64(sha256(&e.blob).to_vec()))).collect();
        seal_json(&self.key, &ad("manifest", &[&self.id.0]), &Manifest { counter, items })
    }

    /// Apply a server response after verifying it against its manifest. Local
    /// unpushed edits win over remote ones (they get pushed next).
    pub fn apply(&mut self, resp: &VaultResponse) -> Result<(), Error> {
        let m: Manifest = open_json(&self.key, &ad("manifest", &[&self.id.0]), &resp.manifest.0)?;
        if m.counter != resp.counter {
            return Err(Error::ManifestMismatch);
        }
        if m.counter < self.counter {
            return Err(Error::Rollback);
        }
        // Same counter: the server must describe exactly what this device already
        // verified. Otherwise it is serving a different branch it kept back (for
        // example a push it answered with an error but stored).
        if m.counter == self.counter {
            let clean = |id: &Hex| !self.dirty.contains(id) && !self.deleted.contains(id);
            let same = m.items.keys().filter(|id| clean(id)).count()
                == self.entries.keys().filter(|id| clean(id)).count()
                && self.entries.iter().filter(|(id, _)| clean(id)).all(|(id, e)| {
                    m.items.get(id).is_some_and(|h| h.0[..] == sha256(&e.blob)[..])
                });
            if !same {
                return Err(Error::Rollback);
            }
        }
        let mut received = BTreeMap::new();
        for ib in &resp.items {
            match m.items.get(&ib.id) {
                Some(h) if h.0 == sha256(&ib.blob.0) => {}
                _ => return Err(Error::ManifestMismatch),
            }
            let item = open_json(&self.key, &self.item_ad(&ib.id), &ib.blob.0)?;
            received.insert(ib.id, Entry { item, blob: ib.blob.0.clone() });
        }
        // Verify everything before touching self, so a bad response changes nothing.
        let local = |id: &Hex| !self.dirty.contains(id) && !self.deleted.contains(id) && !received.contains_key(id);
        for (id, hash) in m.items.iter().filter(|(id, _)| local(id)) {
            match self.entries.get(id) {
                Some(e) if sha256(&e.blob)[..] == hash.0[..] => {}
                _ => return Err(Error::ManifestMismatch),
            }
        }
        let mut next = BTreeMap::new();
        for id in m.items.keys() {
            if self.dirty.contains(id) || self.deleted.contains(id) {
                continue;
            }
            let e = received.remove(id).or_else(|| self.entries.remove(id)).expect("verified above");
            next.insert(*id, e);
        }
        for id in &self.dirty {
            if let Some(e) = self.entries.remove(id) {
                next.insert(*id, e);
            }
        }
        self.entries = next;
        self.counter = m.counter;
        Ok(())
    }

    /// Seal pending changes into a request. After a 2xx call `pushed`; after a
    /// 409, pull (`apply`) and call `push` again.
    pub fn push(&mut self) -> VaultPut {
        let mut upserts = Vec::new();
        for id in &self.dirty {
            let ad = self.item_ad(id);
            let e = self.entries.get_mut(id).expect("dirty entries exist");
            e.blob = seal_json(&self.key, &ad, &e.item);
            upserts.push(ItemBlob { id: *id, blob: B64(e.blob.clone()) });
        }
        VaultPut {
            expected_counter: self.counter,
            manifest: B64(self.seal_manifest(self.counter + 1)),
            upserts,
            deletes: self.deleted.iter().copied().collect(),
        }
    }

    /// Only what `put` carried becomes clean: an item edited while the push was
    /// in flight stays dirty and goes out with the next push.
    pub fn pushed(&mut self, put: &VaultPut) {
        self.counter = put.expected_counter + 1;
        for u in &put.upserts {
            if self.entries.get(&u.id).is_some_and(|e| e.blob == u.blob.0) {
                self.dirty.remove(&u.id);
            }
        }
        for d in &put.deletes {
            self.deleted.remove(d);
        }
    }

    /// Everything a device must keep between runs, encrypted: verified items,
    /// unpushed edits, and the counter that guards against rollback.
    pub fn snapshot(&self) -> VaultSnapshot {
        let items = self
            .entries
            .iter()
            .map(|(id, e)| {
                let blob = if self.dirty.contains(id) { seal_json(&self.key, &self.item_ad(id), &e.item) } else { e.blob.clone() };
                ItemBlob { id: *id, blob: B64(blob) }
            })
            .collect();
        VaultSnapshot {
            counter: self.counter,
            items,
            dirty: self.dirty.iter().copied().collect(),
            deleted: self.deleted.iter().copied().collect(),
        }
    }

    pub fn restore(id: Hex, key: Key, snap: &VaultSnapshot) -> Result<Vault, Error> {
        let mut v = Vault::new(id, key);
        v.counter = snap.counter;
        v.dirty = snap.dirty.iter().copied().collect();
        v.deleted = snap.deleted.iter().copied().collect();
        for ib in &snap.items {
            let item = open_json(&v.key, &v.item_ad(&ib.id), &ib.blob.0)?;
            v.entries.insert(ib.id, Entry { item, blob: ib.blob.0.clone() });
        }
        Ok(v)
    }
}

/// A device's local copy of one vault. Safe to write to disk: items stay sealed.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultSnapshot {
    pub counter: u64,
    pub items: Vec<ItemBlob>,
    pub dirty: Vec<Hex>,
    pub deleted: Vec<Hex>,
}

pub fn new_item_id() -> Hex {
    Hex(random())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_key_roundtrip_and_typos() {
        let sk = SecretKey::generate();
        let s = sk.encode();
        assert_eq!(s.len(), 3 + 4 * 7 + 3);
        assert_eq!(SecretKey::parse(&s).unwrap().0, sk.0);
        assert_eq!(SecretKey::parse(&s.to_lowercase().replace('-', " ")).unwrap().0, sk.0);
        // Flip one data character: the check pair catches it.
        let mut typo: Vec<char> = s.chars().collect();
        typo[5] = if typo[5] == 'X' { 'Y' } else { 'X' };
        assert!(SecretKey::parse(&typo.into_iter().collect::<String>()).is_err());
    }

    /// Known-answer vector, cross-checked by an independent Python implementation
    /// (tools/kat.py). Every client must reproduce these.
    #[test]
    fn derivation_vector() {
        let sk = SecretKey(Zeroizing::new(*b"0123456789abcdef"));
        let d = derive("correct horse battery staple", &sk);
        assert_eq!(sk.encode(), "A1-60RK4CS-M6MV3EE-1SC5H66-S35CRKK");
        assert_eq!(hex::encode(d.account_id), "56b207c3195b23dae0bf24712ac02cc7");
        assert_eq!(hex::encode(&d.unlock_key[..]), "fd4d37679f671a8d07d5829c500f74121626736e1bd4eb50eeca35cc0427f572");
        assert_eq!(hex::encode(d.auth.verifying_key().to_bytes()), "03e592d4a72ee252a9908027fe26d1ec1e0c17fc90f6a1c17dea91c18162cc20");
    }

    #[test]
    fn wrong_password_fails() {
        let s = signup("hunter2");
        let resp = AccountResponse {
            account_key: s.request.account_key.clone(),
            vaults: vec![VaultInfo { id: s.request.vault.id, vault_key: s.request.vault.vault_key.clone(), counter: 0 }],
        };
        assert!(Account::unlock(&derive("hunter2", &s.secret_key), &resp).is_ok());
        assert_eq!(Account::unlock(&derive("hunter3", &s.secret_key), &resp).err(), Some(Error::Tampered));
        assert_eq!(Account::unlock(&derive("hunter2", &SecretKey::generate()), &resp).err(), Some(Error::Tampered));
    }

    const BLOB_VECTOR: &str = "01030303030303030303030303030303030303030303030303f46a2a721b55a38803873c9683da27fbe1fc928015e0d59931";

    fn server_view(v: &mut Vault) -> VaultResponse {
        let put = v.push();
        v.pushed(&put);
        VaultResponse { counter: put.expected_counter + 1, manifest: put.manifest, items: put.upserts }
    }

    #[test]
    fn server_tampering_is_detected() {
        let key = random_key();
        let id = Hex(random());
        let mut a = Vault::new(id, Zeroizing::new(*key));
        let (x, y) = (new_item_id(), new_item_id());
        a.put(x, Item { title: "x".into(), password: "px".into(), ..Default::default() });
        a.put(y, Item { title: "y".into(), password: "py".into(), ..Default::default() });
        let good = server_view(&mut a);

        let fresh = || Vault::new(id, Zeroizing::new(*key));
        assert!(fresh().apply(&good).is_ok());

        // Swap blobs between two items.
        let mut swapped = good.clone();
        swapped.items[0].id = good.items[1].id;
        swapped.items[1].id = good.items[0].id;
        assert!(fresh().apply(&swapped).is_err());

        // Withhold an item.
        let mut dropped = good.clone();
        dropped.items.pop();
        assert_eq!(fresh().apply(&dropped).err(), Some(Error::ManifestMismatch));

        // Lie about the counter.
        let mut counter = good.clone();
        counter.counter = 7;
        assert_eq!(fresh().apply(&counter).err(), Some(Error::ManifestMismatch));

        // Roll back to an older state after the device has seen a newer one.
        let mut b = fresh();
        b.apply(&good).unwrap();
        b.put(new_item_id(), Item { title: "z".into(), ..Default::default() });
        let newer = server_view(&mut b);
        // `newer` is a delta (only z), so a fresh device can't verify it alone.
        let mut c = fresh();
        assert_eq!(c.apply(&newer).err(), Some(Error::ManifestMismatch));
        c.apply(&good).unwrap();
        c.apply(&newer).unwrap();
        assert_eq!(c.items().count(), 3);
        assert_eq!(c.apply(&good).err(), Some(Error::Rollback));

        // Fork at the same counter: the server answers a push with an error but
        // keeps it, accepts the retry (which adds another item) at the same
        // counter, and later serves the first push to drop the newer item.
        let mut d = fresh();
        d.apply(&good).unwrap();
        d.put(new_item_id(), Item { title: "first".into(), ..Default::default() });
        let kept = d.push(); // "failed": pushed() is not called
        let kept = VaultResponse { counter: kept.expected_counter + 1, manifest: kept.manifest, items: kept.upserts };
        let late = new_item_id();
        d.put(late, Item { title: "second".into(), ..Default::default() });
        server_view(&mut d);
        assert_eq!(d.apply(&kept).err(), Some(Error::Rollback));
        assert!(d.get(&late).is_some());
    }

    #[test]
    fn edit_during_push_stays_dirty() {
        let mut v = Vault::new(Hex(random()), random_key());
        let id = new_item_id();
        v.put(id, Item { title: "v1".into(), ..Default::default() });
        let put = v.push();
        v.put(id, Item { title: "v2".into(), ..Default::default() });
        v.pushed(&put);
        assert!(v.has_changes());
        assert_eq!(v.push().upserts.len(), 1);
    }

    #[test]
    fn snapshot_restore_keeps_counter_and_edits() {
        let key = random_key();
        let mut v = Vault::new(Hex(random()), Zeroizing::new(*key));
        let (a, b) = (new_item_id(), new_item_id());
        v.put(a, Item { title: "synced".into(), ..Default::default() });
        let resp = server_view(&mut v);
        v.put(b, Item { title: "unpushed".into(), ..Default::default() });
        let snap: VaultSnapshot = serde_json::from_str(&serde_json::to_string(&v.snapshot()).unwrap()).unwrap();
        let mut r = Vault::restore(v.id, Zeroizing::new(*key), &snap).unwrap();
        assert_eq!(r.counter, 1);
        assert_eq!(r.get(&b).unwrap().title, "unpushed");
        assert!(r.has_changes());
        r.apply(&resp).unwrap(); // same state: accepted, edit kept
        assert_eq!(r.items().count(), 2);
    }

    /// Frozen blob format: this must open forever.
    #[test]
    fn blob_vector() {
        let key = Zeroizing::new([7u8; 32]);
        let blob = hex::decode(BLOB_VECTOR).unwrap();
        assert_eq!(&open(&key, &ad("item", &[&[1u8; 16], &[2u8; 16]]), &blob).unwrap()[..], b"plaintext");
    }

    #[test]
    fn unknown_fields_survive() {
        let item: Item = serde_json::from_str(r#"{"title":"t","passkey":{"rp":"x"}}"#).unwrap();
        assert!(serde_json::to_string(&item).unwrap().contains("passkey"));
    }
}
