//! A vault on one device: verified roster, vault key, items, and the sync rules.
//!
//! Trust chain, all checked here and never delegated to the server:
//! roster v0 is signed by an owner listed in it; each later roster is signed by an
//! owner of the previous one and links to it by hash; the vault key a member
//! unwraps must match the roster's `key_check`; each manifest is signed by a
//! writer, links to the previous manifest by hash, and commits to every item blob.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::api::*;
use crate::crypto::*;
use crate::identity::{Keyring, Me, verify_doc};
use crate::item::Item;
use crate::{Account, Error, open_json, seal_json};

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct VaultMeta {
    #[serde(default)]
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Serialize, Deserialize)]
struct ManifestBody {
    meta: VaultMeta,
    items: BTreeMap<Hex, B64>,
}

#[derive(Serialize, Deserialize, Clone)]
struct Entry {
    item: Item,
    #[serde(with = "b64vec")]
    blob: Vec<u8>,
}

mod b64vec {
    use crate::api::B64;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        B64(v.to_vec()).serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        Ok(B64::deserialize(d)?.0)
    }
}

#[derive(Serialize, Deserialize)]
pub struct Vault {
    pub id: Hex,
    key: Option<B64>,
    pub roster: Option<Roster>,
    roster_hash: B64,
    /// For every roster version verified: its epoch and who could write in it.
    versions: BTreeMap<u64, (u64, BTreeSet<String>)>,
    /// Who signed roster v0, i.e. created the vault.
    pub creator: String,
    pub meta: VaultMeta,
    /// Highest manifest counter verified. It's the rollback guard, so persist it.
    pub counter: u64,
    last: B64,
    entries: BTreeMap<Hex, Entry>,
    /// For locally edited items: the hash of the version the edit started from.
    base: BTreeMap<Hex, B64>,
    dirty: BTreeSet<Hex>,
    deleted: BTreeSet<Hex>,
    meta_dirty: bool,
}

fn h(b: &[u8]) -> B64 {
    B64(sha256(b).to_vec())
}

fn key_ad(vault: &Hex, epoch: u64, username: &str) -> Vec<u8> {
    [ad("vault-key", &[&vault.0]), epoch.to_be_bytes().to_vec(), username.as_bytes().to_vec()].concat()
}

fn key_check(vk: &Key, vault: &Hex, epoch: u64) -> B64 {
    B64(hmac(&vk[..], &[b"plaintext/v1/key-check".as_slice(), &vault.0, &epoch.to_be_bytes()].concat()).to_vec())
}

fn wrap(vk: &Key, vault: &Hex, epoch: u64, m: &Member) -> Result<WrappedKey, Error> {
    Ok(WrappedKey { username: m.username.clone(), epoch, key: B64(seal_to(&m.enc_pk.0, &key_ad(vault, epoch, &m.username), &vk[..])?) })
}

fn active(m: &Member, now: u64) -> bool {
    m.expires.is_none_or(|e| now < e)
}

impl Vault {
    /// A vault this device knows only by id; the first `apply` fills it in.
    pub fn new(id: Hex) -> Vault {
        Vault {
            id,
            key: None,
            roster: None,
            roster_hash: B64::default(),
            versions: BTreeMap::new(),
            creator: String::new(),
            meta: VaultMeta::default(),
            counter: 0,
            last: B64::default(),
            entries: BTreeMap::new(),
            base: BTreeMap::new(),
            dirty: BTreeSet::new(),
            deleted: BTreeSet::new(),
            meta_dirty: false,
        }
    }

    /// A new vault owned by `me`, and the request that creates it on the server.
    pub fn create(me: &Me, name: &str) -> Result<(Vault, NewVault), Error> {
        let mut v = Vault::new(Hex(random()));
        let vk = random_key();
        let roster = Roster {
            vault_id: v.id,
            version: 0,
            prev: B64::default(),
            epoch: 0,
            key_check: key_check(&vk, &v.id, 0),
            members: vec![me.member(Role::Owner)],
        };
        let signed = me.sign_doc("roster", &roster);
        let keys = vec![wrap(&vk, &v.id, 0, &roster.members[0])?];
        v.roster_hash = h(&signed.body.0);
        v.versions.insert(0, (0, BTreeSet::from([me.username.clone()])));
        v.creator = me.username.clone();
        v.roster = Some(roster);
        v.key = Some(B64(vk.to_vec()));
        v.meta.name = name.into();
        v.meta_dirty = true;
        let put = v.push(me, 0)?;
        v.pushed(&put);
        Ok((v, NewVault { roster: signed, keys, manifest: put.manifest }))
    }

    fn key(&self) -> Result<Key, Error> {
        let k = self.key.as_ref().ok_or(Error::NotMember)?;
        Ok(Zeroizing::new(k.0.as_slice().try_into().map_err(|_| Error::Tampered)?))
    }

    pub fn role(&self, username: &str, now: u64) -> Option<Role> {
        self.roster.as_ref()?.members.iter().find(|m| m.username == username && active(m, now)).map(|m| m.role)
    }

    pub fn items(&self) -> impl Iterator<Item = (&Hex, &Item)> {
        self.entries.iter().map(|(id, e)| (id, &e.item))
    }

    pub fn get(&self, id: &Hex) -> Option<&Item> {
        self.entries.get(id).map(|e| &e.item)
    }

    pub fn put(&mut self, id: Hex, item: Item) {
        if let Some(e) = self.entries.get(&id)
            && !self.dirty.contains(&id)
        {
            self.base.insert(id, h(&e.blob));
        }
        self.entries.insert(id, Entry { item, blob: Vec::new() });
        self.dirty.insert(id);
        self.deleted.remove(&id);
    }

    pub fn delete(&mut self, id: Hex) {
        if let Some(e) = self.entries.remove(&id)
            && !self.dirty.contains(&id)
        {
            self.base.insert(id, h(&e.blob));
        }
        self.dirty.remove(&id);
        self.deleted.insert(id);
    }

    pub fn set_meta(&mut self, meta: VaultMeta) {
        self.meta = meta;
        self.meta_dirty = true;
    }

    pub fn has_changes(&self) -> bool {
        !self.dirty.is_empty() || !self.deleted.is_empty() || self.meta_dirty
    }

    fn item_ad(&self, id: &Hex) -> Vec<u8> {
        ad("item", &[&self.id.0, &id.0])
    }

    /// The `?since=&roster=` query for the next pull.
    pub fn pull_query(&self) -> String {
        match &self.roster {
            Some(r) => format!("since={}&roster={}", self.counter, r.version),
            // A device with no state starts from the latest manifest.
            None => "since=0&latest=true".into(),
        }
    }

    /// Verify a server response and merge it. Nothing changes unless all of it
    /// checks out. May pin new members' keys in `keyring`; returns true if it did
    /// (sync the keyring then).
    pub fn apply(&mut self, resp: &VaultResponse, keyring: &mut Keyring, now: u64) -> Result<bool, Error> {
        let me = keyring.me();
        let mut kr_changed = false;

        // 1. Roster chain.
        let mut roster = self.roster.clone();
        let mut roster_hash = self.roster_hash.clone();
        let mut versions = self.versions.clone();
        let mut creator = self.creator.clone();
        for s in &resp.rosters {
            let r: Roster = serde_json::from_slice(&s.body.0).map_err(|_| Error::BadJson)?;
            if r.vault_id != self.id {
                return Err(Error::Tampered);
            }
            let signer = match &roster {
                None if r.version == 0 && r.prev.0.is_empty() => r.members.iter().find(|m| m.username == s.signer),
                Some(prev) if r.version == prev.version + 1 && r.prev == roster_hash => {
                    prev.members.iter().find(|m| m.username == s.signer && active(m, now))
                }
                _ => return Err(Error::Rollback),
            };
            let signer = signer.filter(|m| m.role == Role::Owner).ok_or(Error::BadSignature)?;
            for m in &r.members {
                kr_changed |= keyring.pin(&m.username, &m.sign_pk, &m.enc_pk)?;
            }
            verify_doc::<Roster>(s, "roster", &signer.sign_pk.0)?;
            if r.version == 0 {
                creator = s.signer.clone();
            }
            versions.insert(r.version, (r.epoch, r.members.iter().filter(|m| m.role >= Role::Writer).map(|m| m.username.clone()).collect()));
            roster_hash = h(&s.body.0);
            roster = Some(r);
        }
        let roster = roster.ok_or(Error::NotMember)?;
        if !roster.members.iter().any(|m| m.username == me.username && active(m, now)) {
            return Err(Error::NotMember);
        }

        // 2. Vault key for the current epoch, checked against the owner's commitment.
        let key = match (&self.key, &self.roster) {
            (Some(k), Some(old)) if old.epoch == roster.epoch => k.clone(),
            _ => {
                let wrapped = resp.key.as_ref().ok_or(Error::NotMember)?;
                let raw = open_from(&me.enc, &key_ad(&self.id, roster.epoch, &me.username), &wrapped.0)?;
                let vk: Key = Zeroizing::new(raw[..].try_into().map_err(|_| Error::Tampered)?);
                if key_check(&vk, &self.id, roster.epoch) != roster.key_check {
                    return Err(Error::Tampered);
                }
                B64(vk.to_vec())
            }
        };
        let vk: Key = Zeroizing::new(key.0.as_slice().try_into().map_err(|_| Error::Tampered)?);

        // 3. Manifest chain: consecutive, hash-linked, each signed by someone who
        //    could write under the roster version it names, in that version's epoch.
        //    A device with no state yet may start from any manifest (its first sync
        //    is trust on first use either way); after that, every link is checked.
        let (mut counter, mut last) = (self.counter, self.last.clone());
        let mut latest: Option<(ManifestEnvelope, String)> = None;
        for s in &resp.manifests {
            let env: ManifestEnvelope = serde_json::from_slice(&s.body.0).map_err(|_| Error::BadJson)?;
            let fresh = latest.is_none() && self.counter == 0;
            if env.vault_id != self.id || (!fresh && (env.counter != counter + 1 || env.prev != last)) {
                return Err(Error::Rollback);
            }
            match versions.get(&env.roster) {
                Some((epoch, w)) if *epoch == env.epoch && w.contains(&s.signer) => {}
                _ => return Err(Error::BadSignature),
            }
            let pk = keyring.sign_pk(&s.signer).ok_or(Error::BadSignature)?;
            verify_doc::<ManifestEnvelope>(s, "manifest", &pk)?;
            counter = env.counter;
            last = h(&s.body.0);
            latest = Some((env, s.signer.clone()));
        }
        if resp.counter != counter {
            return Err(if resp.counter < self.counter { Error::Rollback } else { Error::ManifestMismatch });
        }

        // 4. The latest manifest decides the items. It must be under the current key
        //    and written by someone who may write now.
        let Some((env, signer)) = latest else {
            if self.roster.as_ref().map(|r| r.epoch) != Some(roster.epoch) {
                return Err(Error::ManifestMismatch);
            }
            self.roster = Some(roster);
            self.roster_hash = roster_hash;
            self.versions = versions;
            self.creator = creator;
            return Ok(kr_changed);
        };
        // Demotion and removal replace the key, so anything under the current
        // epoch was written by someone who could write at the time.
        let _ = signer;
        if env.epoch != roster.epoch {
            return Err(Error::ManifestMismatch);
        }
        let m: ManifestBody = open_json(&vk, &ad("manifest", &[&self.id.0]), &env.sealed.0)?;

        let mut received = BTreeMap::new();
        for ib in &resp.items {
            match m.items.get(&ib.id) {
                Some(hash) if *hash == h(&ib.blob.0) => {}
                _ => return Err(Error::ManifestMismatch),
            }
            let item: Item = open_json(&vk, &self.item_ad(&ib.id), &ib.blob.0)?;
            received.insert(ib.id, Entry { item, blob: ib.blob.0.clone() });
        }
        let pending = |id: &Hex| self.dirty.contains(id) || self.deleted.contains(id);
        for (id, hash) in &m.items {
            if !pending(id) && !received.contains_key(id) && self.entries.get(id).is_none_or(|e| h(&e.blob) != *hash) {
                return Err(Error::ManifestMismatch);
            }
        }

        // 5. Merge. Local unpushed edits win; if the server's copy also changed
        //    since the edit began, it's kept as a conflict copy.
        let mut next = BTreeMap::new();
        let mut conflicts = Vec::new();
        let mut deleted = self.deleted.clone();
        for (id, hash) in &m.items {
            let changed_remotely = self.base.get(id).is_some_and(|b| b != hash);
            if self.dirty.contains(id) {
                if changed_remotely && let Some(e) = received.remove(id) {
                    conflicts.push(e.item);
                }
                continue;
            }
            if deleted.contains(id) {
                if !changed_remotely {
                    continue;
                }
                deleted.remove(id);
            }
            let e = match received.remove(id) {
                Some(e) => e,
                None => self.entries.get(id).cloned().ok_or(Error::ManifestMismatch)?,
            };
            next.insert(*id, e);
        }
        for id in &self.dirty {
            if let Some(e) = self.entries.get(id) {
                next.insert(*id, e.clone());
            }
        }
        self.entries = next;
        self.deleted = deleted;
        for mut item in conflicts {
            item.title = format!("{} (conflict)", item.title);
            self.put(Hex(random()), item);
        }
        if !self.meta_dirty {
            self.meta = m.meta;
        }
        self.roster = Some(roster);
        self.roster_hash = roster_hash;
        self.versions = versions;
        self.creator = creator;
        self.key = Some(key);
        self.counter = counter;
        self.last = last;
        Ok(kr_changed)
    }

    fn seal_manifest(&self, me: &Me, vk: &Key, epoch: u64, roster: u64, items: BTreeMap<Hex, B64>) -> Signed {
        let sealed = seal_json(vk, &ad("manifest", &[&self.id.0]), &ManifestBody { meta: self.meta.clone(), items });
        let env = ManifestEnvelope { vault_id: self.id, counter: self.counter + 1, epoch, roster, prev: self.last.clone(), sealed: B64(sealed) };
        me.sign_doc("manifest", &env)
    }

    /// Seal pending changes into a signed request. After a 2xx call `pushed`;
    /// after a 409, pull (`apply`) and push again.
    pub fn push(&mut self, me: &Me, now: u64) -> Result<VaultPut, Error> {
        if self.role(&me.username, now).is_none_or(|r| r < Role::Writer) {
            return Err(Error::ReadOnly);
        }
        let vk = self.key()?;
        let mut upserts = Vec::new();
        for id in &self.dirty {
            let ad = self.item_ad(id);
            let e = self.entries.get_mut(id).expect("dirty entries exist");
            e.blob = seal_json(&vk, &ad, &e.item);
            upserts.push(ItemBlob { id: *id, blob: B64(e.blob.clone()) });
        }
        let items = self.entries.iter().map(|(id, e)| (*id, h(&e.blob))).collect();
        let (epoch, version) = self.roster.as_ref().map_or((0, 0), |r| (r.epoch, r.version));
        Ok(VaultPut {
            expected_counter: self.counter,
            manifest: self.seal_manifest(me, &vk, epoch, version, items),
            upserts,
            deletes: self.deleted.iter().copied().collect(),
        })
    }

    /// Only what `put` carried becomes clean: an item edited while the push was
    /// in flight stays dirty and goes out next time.
    pub fn pushed(&mut self, put: &VaultPut) {
        let env: ManifestEnvelope = serde_json::from_slice(&put.manifest.body.0).expect("we built it");
        self.counter = env.counter;
        self.last = h(&put.manifest.body.0);
        for u in &put.upserts {
            if self.entries.get(&u.id).is_some_and(|e| e.blob == u.blob.0) {
                self.dirty.remove(&u.id);
                self.base.remove(&u.id);
            }
        }
        for d in &put.deletes {
            self.deleted.remove(d);
            self.base.remove(d);
        }
        self.meta_dirty = false;
    }

    fn next_roster(&self, me: &Me, now: u64) -> Result<Roster, Error> {
        if self.role(&me.username, now) != Some(Role::Owner) {
            return Err(Error::NotOwner);
        }
        let mut r = self.roster.clone().ok_or(Error::NotMember)?;
        r.version += 1;
        r.prev = self.roster_hash.clone();
        Ok(r)
    }

    /// Add someone (or change their role or expiry). Their keys must already be
    /// pinned in `keyring`, which is what makes this safe against a key swap.
    pub fn grant(&self, me: &Me, keyring: &Keyring, username: &str, role: Role, expires: Option<u64>, now: u64) -> Result<RosterUpdate, Error> {
        let c = keyring.contacts.get(username).ok_or(Error::UnknownUser(username.into()))?;
        let member = Member { username: username.into(), sign_pk: c.sign_pk.clone(), enc_pk: c.enc_pk.clone(), role, expires };
        let mut r = self.next_roster(me, now)?;
        let old = r.members.iter().find(|m| m.username == username).map(|m| m.role);
        r.members.retain(|m| m.username != username);
        r.members.push(member.clone());
        // A demoted member still holds the key, so demotion replaces it, like removal.
        if old.is_some_and(|o| role < o) {
            return self.rotate(me, r);
        }
        let keys = if old.is_none() { vec![wrap(&self.key()?, &self.id, r.epoch, &member)?] } else { vec![] };
        Ok(RosterUpdate { roster: me.sign_doc("roster", &r), keys, rotation: None })
    }

    /// Remove someone: a new vault key, every item re-sealed, so nothing written
    /// from now on is readable with the old key. Push pending changes first.
    pub fn revoke(&self, me: &Me, username: &str, now: u64) -> Result<RosterUpdate, Error> {
        if self.has_changes() {
            return Err(Error::PendingChanges);
        }
        let mut r = self.next_roster(me, now)?;
        r.members.retain(|m| m.username != username);
        self.rotate(me, r)
    }

    /// A new epoch: fresh key for the members of `r`, every item re-sealed.
    fn rotate(&self, me: &Me, mut r: Roster) -> Result<RosterUpdate, Error> {
        if self.has_changes() {
            return Err(Error::PendingChanges);
        }
        r.epoch += 1;
        let vk = random_key();
        r.key_check = key_check(&vk, &self.id, r.epoch);
        let keys = r.members.iter().map(|m| wrap(&vk, &self.id, r.epoch, m)).collect::<Result<_, _>>()?;
        let mut upserts = Vec::new();
        let mut items = BTreeMap::new();
        for (id, e) in &self.entries {
            let blob = seal_json(&vk, &self.item_ad(id), &e.item);
            items.insert(*id, h(&blob));
            upserts.push(ItemBlob { id: *id, blob: B64(blob) });
        }
        let rotation = VaultPut { expected_counter: self.counter, manifest: self.seal_manifest(me, &vk, r.epoch, r.version, items), upserts, deletes: vec![] };
        Ok(RosterUpdate { roster: me.sign_doc("roster", &r), keys, rotation: Some(rotation) })
    }

    /// Everything this device keeps between runs, sealed with the Account Key.
    pub fn snapshot(&self, account: &Account) -> Vec<u8> {
        let json = Zeroizing::new(serde_json::to_vec(self).expect("serializable"));
        seal(&account.account_key, &ad("vault-snapshot", &[&account.id, &self.id.0]), &json)
    }

    pub fn restore(account: &Account, id: Hex, blob: &[u8]) -> Result<Vault, Error> {
        let raw = open(&account.account_key, &ad("vault-snapshot", &[&account.id, &id.0]), blob)?;
        serde_json::from_slice(&raw).map_err(|_| Error::BadJson)
    }
}
