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
    /// For locally edited items: the hash of the version the edit started from,
    /// and of its content (so a re-seal under a new key isn't mistaken for an edit).
    base: BTreeMap<Hex, B64>,
    #[serde(default)]
    base_content: BTreeMap<Hex, B64>,
    /// Some roster version was signed by the agent's owner (see `apply`).
    #[serde(default)]
    owner_signed: bool,
    dirty: BTreeSet<Hex>,
    deleted: BTreeSet<Hex>,
    meta_dirty: bool,
    /// For pending changes: the files of the version they started from, which the
    /// server keeps serving until the change is pushed.
    #[serde(default)]
    base_files: BTreeMap<Hex, Vec<Hex>>,
    /// Files on the server no item here refers to, and when this device first saw
    /// each one so; and when it last looked (see `collect_files`).
    #[serde(default)]
    orphans: BTreeMap<Hex, u64>,
    #[serde(default)]
    files_checked: u64,
    /// Every pending change's `base` is the server's copy as of the last manifest
    /// (empty if the server dropped it), so a partial push may list the server's
    /// copies (`push_part`). False in snapshots from apps that didn't keep it so.
    #[serde(default)]
    exact_base: bool,
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

fn content_hash(item: &Item) -> B64 {
    h(&Zeroizing::new(serde_json::to_vec(item).expect("serializable")))
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
            base_content: BTreeMap::new(),
            owner_signed: false,
            dirty: BTreeSet::new(),
            deleted: BTreeSet::new(),
            meta_dirty: false,
            base_files: BTreeMap::new(),
            orphans: BTreeMap::new(),
            files_checked: 0,
            exact_base: true,
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
        Ok((v, NewVault { roster: signed, keys, manifest: put.manifest, sealed: put.sealed }))
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

    /// Remember what an edit or delete started from (once per pending change).
    fn mark_base(&mut self, id: Hex) {
        // Nothing pending: the local copies are the server's as of the last
        // manifest, so the `base`s set from here on are exact (even in a snapshot
        // from an older app, whose leftover ones go).
        if self.dirty.is_empty() && self.deleted.is_empty() {
            self.exact_base = true;
            self.base.clear();
            self.base_content.clear();
            self.base_files.clear();
        }
        if let Some(e) = self.entries.get(&id)
            && !self.dirty.contains(&id)
            && !self.deleted.contains(&id)
        {
            self.base.insert(id, h(&e.blob));
            self.base_content.insert(id, content_hash(&e.item));
            self.base_files.insert(id, e.item.file_ids().collect());
        }
    }

    pub fn put(&mut self, id: Hex, item: Item) {
        self.mark_base(id);
        self.entries.insert(id, Entry { item, blob: Vec::new() });
        self.dirty.insert(id);
        self.deleted.remove(&id);
    }

    pub fn delete(&mut self, id: Hex) {
        self.mark_base(id);
        self.entries.remove(&id);
        self.dirty.remove(&id);
        self.deleted.insert(id);
    }

    /// Of the files the server lists for this vault, the ones to delete: no item
    /// refers to them (current fields, earlier versions, or the server's copy of
    /// an item with a change pending here), and this device has seen them so for
    /// at least `grace` seconds. The grace covers an upload whose item isn't pushed
    /// yet, and another device bringing back a deleted item with an edit it hadn't
    /// pushed. Call it right after a pull, with the server's time.
    pub fn collect_files(&mut self, listed: &[Hex], now: u64, grace: u64) -> Vec<Hex> {
        // A snapshot from before `base_files` can't say what a pending change replaces.
        if self.dirty.iter().chain(&self.deleted).any(|id| self.base.contains_key(id) && !self.base_files.contains_key(id)) {
            return Vec::new();
        }
        let pending = self.base_files.iter().filter(|(id, _)| self.dirty.contains(id) || self.deleted.contains(id));
        let used: BTreeSet<Hex> = self.items().flat_map(|(_, i)| i.file_ids()).chain(pending.flat_map(|(_, f)| f.iter().copied())).collect();
        // The clock only runs while this device keeps looking: after a gap of more
        // than two graces (a laptop left closed) every file starts over, since a
        // file may have been referenced again in between. `now` is the server's.
        let mut seen = std::mem::take(&mut self.orphans);
        if now.saturating_sub(self.files_checked) > 2 * grace {
            seen.clear();
        }
        self.files_checked = now;
        let since = |f: &Hex| seen.get(f).map_or(now, |s| (*s).min(now));
        self.orphans = listed.iter().filter(|f| !used.contains(f)).map(|f| (*f, since(f))).collect();
        self.orphans.iter().filter(|(_, since)| now >= since.saturating_add(grace)).map(|(f, _)| *f).collect()
    }

    pub fn set_meta(&mut self, meta: VaultMeta) {
        self.meta = meta;
        self.meta_dirty = true;
    }

    pub fn has_changes(&self) -> bool {
        self.changes() > 0
    }

    /// How many changes wait to be pushed: items added, edited or deleted, and the vault's name.
    pub fn changes(&self) -> usize {
        self.dirty.len() + self.deleted.len() + usize::from(self.meta_dirty)
    }

    /// Items added or edited here and not pushed yet.
    pub fn changed(&self) -> impl Iterator<Item = (&Hex, &Item)> {
        self.dirty.iter().filter_map(|id| Some((id, self.get(id)?)))
    }

    /// Items deleted here and not pushed yet.
    pub fn deleted(&self) -> usize {
        self.deleted.len()
    }

    /// Whether the vault's name or description changed here and wasn't pushed yet.
    pub fn meta_changed(&self) -> bool {
        self.meta_dirty
    }

    /// Drop everything but the rollback guard, pending changes included. The next
    /// pull downloads the vault again from its latest manifest, which must not be
    /// older than the one verified here (it isn't checked to link to it, as for a
    /// device seeing the vault for the first time). Returns how many changes went.
    pub fn forget(&mut self) -> usize {
        let n = self.changes();
        *self = Vault { counter: self.counter, last: self.last.clone(), ..Vault::new(self.id) };
        n
    }

    /// Whether both copies verified the same latest manifest.
    pub fn same_head(&self, other: &Vault) -> bool {
        self.counter == other.counter && self.last == other.last
    }

    fn item_ad(&self, id: &Hex) -> Vec<u8> {
        ad("item", &[&self.id.0, &id.0])
    }

    /// The `?since=&roster=` query for the next pull: its first page, or with
    /// `so_far` (the pages so far, joined) the page after them.
    pub fn pull_query(&self, so_far: Option<&VaultResponse>) -> Result<String, Error> {
        let (mut q, mut roster) = match &self.roster {
            Some(r) => (format!("since={}", self.counter), Some(r.version)),
            // A device with no state starts from the latest manifest.
            None => ("since=0&latest=true".to_string(), None),
        };
        let Some(p) = so_far else {
            return Ok(roster.map_or(q.clone(), |r| format!("{q}&roster={r}")));
        };
        if let Some(s) = p.rosters.last() {
            roster = Some(serde_json::from_slice::<Roster>(&s.body.0).map_err(|_| Error::BadJson)?.version);
        }
        if let Some(r) = roster {
            q += &format!("&roster={r}");
        }
        if let Some(s) = p.manifests.last() {
            q += &format!("&from={}", serde_json::from_slice::<ManifestEnvelope>(&s.body.0).map_err(|_| Error::BadJson)?.counter);
        }
        if let Some(i) = p.items.last() {
            q += &format!("&after={}", i.id);
        }
        Ok(q + &format!("&at={}", p.counter))
    }

    /// Verify a server response and merge it. Nothing changes, the keyring
    /// included, unless all of it checks out. May pin new members' keys and record
    /// the newest roster in `keyring`; returns true if it did (sync the keyring then).
    pub fn apply(&mut self, resp: &VaultResponse, keyring: &mut Keyring, now: u64) -> Result<bool, Error> {
        let mut kr = keyring.clone();
        let changed = self.apply_with(resp, &mut kr, now)?;
        if changed {
            *keyring = kr;
        }
        Ok(changed)
    }

    fn apply_with(&mut self, resp: &VaultResponse, keyring: &mut Keyring, now: u64) -> Result<bool, Error> {
        let me = keyring.me();
        let mut kr_changed = false;
        let checkpoint = keyring.rosters.get(&self.id).cloned();
        let mut owner_signed = self.owner_signed;

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
            // Owners never expire, so who signed each version stays checkable
            // on any device at any later time.
            let signer = match &roster {
                None if r.version == 0 && r.prev.0.is_empty() => r.members.iter().find(|m| m.username == s.signer),
                Some(prev) if r.version == prev.version + 1 && r.prev == roster_hash => prev.members.iter().find(|m| m.username == s.signer),
                _ => return Err(Error::Rollback),
            };
            let signer = signer.filter(|m| m.role == Role::Owner).ok_or(Error::BadSignature)?;
            if r.members.iter().any(|m| m.role == Role::Owner && m.expires.is_some()) {
                return Err(Error::OwnerExpiry);
            }
            // A v0 signer's key comes from the roster itself: it must match any pin.
            if keyring.sign_pk(&s.signer).is_some_and(|pk| pk != signer.sign_pk.0) {
                return Err(Error::KeyChanged(s.signer.clone()));
            }
            verify_doc::<Roster>(s, "roster", &signer.sign_pk.0)?;
            if checkpoint.as_ref().is_some_and(|(v, ch)| *v == r.version && *ch != h(&s.body.0)) {
                return Err(Error::Rollback);
            }
            for m in &r.members {
                kr_changed |= keyring.pin(&m.username, &m.sign_pk, &m.enc_pk)?;
            }
            owner_signed |= keyring.owner.as_deref() == Some(s.signer.as_str());
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
        // Another device of this account has seen a newer roster (say, a removal):
        // a server showing this device an older one is hiding it.
        if checkpoint.as_ref().is_some_and(|(v, _)| roster.version < *v) {
            return Err(Error::Rollback);
        }
        if checkpoint.as_ref().is_none_or(|(v, _)| roster.version > *v) {
            keyring.rosters.insert(self.id, (roster.version, roster_hash.clone()));
            kr_changed = true;
        }
        // An agent obeys its owner only: a vault counts if its owner signed some
        // version of its roster, which no server can fake.
        if keyring.owner.is_some() && !owner_signed {
            return Err(Error::NotFromOwner);
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
        //    A vault reset to its rollback guard (`forget`) starts afresh too, unless
        //    the first manifest served is the very next one: that must link to it,
        //    and a chain that passes the guard's counter must pass its manifest.
        let (mut counter, mut last) = (self.counter, self.last.clone());
        let mut latest: Option<(ManifestEnvelope, String)> = None;
        for s in &resp.manifests {
            let env: ManifestEnvelope = serde_json::from_slice(&s.body.0).map_err(|_| Error::BadJson)?;
            // The sealed part's hash, or (written before hashes) the sealed part itself.
            if env.sealed.is_some() == env.sealed_hash.is_some() {
                return Err(Error::BadJson);
            }
            let fresh = latest.is_none() && (self.counter == 0 || (self.roster.is_none() && env.counter != self.counter + 1));
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
            if self.roster.is_none() && counter == self.counter && last != self.last {
                return Err(Error::Rollback);
            }
            latest = Some((env, s.signer.clone()));
        }
        if resp.counter != counter {
            return Err(if resp.counter < self.counter { Error::Rollback } else { Error::ManifestMismatch });
        }
        // Started afresh from a kept guard: no older copy, nor a different one of the same version.
        if self.roster.is_none() && (counter < self.counter || (counter == self.counter && last != self.last)) {
            return Err(Error::Rollback);
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
            self.owner_signed = owner_signed;
            self.drop_done_deletes();
            return Ok(kr_changed);
        };
        // Demotion and removal replace the key, so anything under the current
        // epoch was written by someone who could write at the time.
        let _ = signer;
        if env.epoch != roster.epoch {
            return Err(Error::ManifestMismatch);
        }
        let sealed = match (&env.sealed, &env.sealed_hash) {
            (Some(sealed), _) => sealed,
            (None, hash) => resp.sealed.as_ref().filter(|s| Some(&h(&s.0)) == hash.as_ref()).ok_or(Error::ManifestMismatch)?,
        };
        let m: ManifestBody = open_json(&vk, &ad("manifest", &[&self.id.0]), &sealed.0)?;

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
        let blob_changed = |id: &Hex, hash: &B64| self.base.get(id).is_some_and(|b| b != hash);
        for (id, hash) in &m.items {
            // Every changed item must come with its blob, including ones edited
            // here: otherwise the other edit would vanish instead of conflicting.
            let have = if pending(id) { !blob_changed(id, hash) } else { self.entries.get(id).is_some_and(|e| h(&e.blob) == *hash) };
            if !have && !received.contains_key(id) {
                return Err(Error::ManifestMismatch);
            }
        }

        // A pending change now starts from the server's newer copy (kept below as
        // a conflict copy if its content changed, or it was only re-sealed), so
        // later pulls, which won't resend that blob, don't wait for it (#987).
        let rebase: Vec<(Hex, B64, B64, Vec<Hex>)> = m
            .items
            .iter()
            // Or one the server has though this device never heard so: a push whose
            // answer was lost. Without a `base`, a deletes-only push would leave it out.
            .filter(|(id, hash)| pending(id) && (blob_changed(id, hash) || !self.base.contains_key(id)))
            .filter_map(|(id, hash)| received.get(id).map(|e| (*id, hash.clone(), content_hash(&e.item), e.item.file_ids().collect())))
            .collect();

        // 5. Merge. Local unpushed edits win; if the server's copy also changed
        //    since the edit began, it's kept as a conflict copy. A blob that was
        //    only re-sealed (a key rotation) is not a change.
        let mut next = BTreeMap::new();
        let mut conflicts = Vec::new();
        let mut deleted = self.deleted.clone();
        for (id, hash) in &m.items {
            let changed_remotely = blob_changed(id, hash)
                && match (received.get(id), self.base_content.get(id)) {
                    (Some(e), Some(c)) => content_hash(&e.item) != *c,
                    _ => true,
                };
            if self.dirty.contains(id) {
                // The same content as here: our own push, whose answer was lost.
                if changed_remotely
                    && let Some(e) = received.remove(id)
                    && self.entries.get(id).is_none_or(|l| content_hash(&l.item) != content_hash(&e.item))
                {
                    conflicts.push((*id, e.item));
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
        for (id, hash, content, files) in rebase {
            if self.dirty.contains(&id) || self.deleted.contains(&id) {
                self.base.insert(id, hash);
                self.base_content.insert(id, content);
                self.base_files.entry(id).or_default().extend(files);
            } else {
                self.base.remove(&id);
                self.base_content.remove(&id);
                self.base_files.remove(&id);
            }
        }
        self.base_from(&m.items);
        for (id, mut item) in conflicts {
            // The server serves this version under `id` until our edit is pushed.
            self.base_files.entry(id).or_default().extend(item.file_ids());
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
        self.owner_signed = owner_signed;
        self.key = Some(key);
        self.counter = counter;
        self.last = last;
        Ok(kr_changed)
    }

    /// Every pending change now starts from the server's copy (`items`, the latest
    /// manifest's): a partial push lists it so. One the server dropped (deleted
    /// elsewhere) gets an empty `base`: a partial push leaves it out, and if it
    /// comes back it's a change (rebased, with a conflict copy if its content differs).
    fn base_from(&mut self, items: &BTreeMap<Hex, B64>) {
        for id in self.dirty.iter().chain(&self.deleted) {
            match items.get(id) {
                Some(hash) => drop(self.base.insert(*id, hash.clone())),
                None => {
                    if let Some(b) = self.base.get_mut(id) {
                        b.0.clear();
                    }
                }
            }
        }
        self.exact_base = true;
        self.drop_done_deletes();
    }

    /// A snapshot from an older app with changes pending can't tell which `base`s
    /// are the server's copies, and a pull that brings no manifest doesn't fix that
    /// (`push_part`). This query fetches the latest manifest alone, without items,
    /// for `exact_base_from`; None when there's no need.
    pub fn exact_base_query(&self) -> Option<String> {
        let r = self.roster.as_ref().filter(|_| !self.exact_base && self.counter > 0)?;
        if self.dirty.is_empty() && self.deleted.is_empty() {
            return None;
        }
        // Items come after `after` by id: none come after the largest one.
        Some(format!("since={}&latest=true&roster={}&after={}", self.counter - 1, r.version, Hex([0xff; 16])))
    }

    /// Take the `base`s from the latest manifest (`exact_base_query`), if it's
    /// the one verified here; returns whether it was. A server that moved on
    /// meanwhile leaves this to the next pull, which brings the new manifest.
    pub fn exact_base_from(&mut self, resp: &VaultResponse) -> Result<bool, Error> {
        let Some(s) = resp.manifests.last().filter(|_| resp.counter == self.counter) else {
            return Ok(false);
        };
        // Verified when it was pulled or pushed: the same hash is the same manifest.
        if h(&s.body.0) != self.last {
            return Err(Error::Rollback);
        }
        let env: ManifestEnvelope = serde_json::from_slice(&s.body.0).map_err(|_| Error::BadJson)?;
        let sealed = match (&env.sealed, &env.sealed_hash) {
            (Some(sealed), _) => sealed,
            (None, hash) => resp.sealed.as_ref().filter(|s| Some(&h(&s.0)) == hash.as_ref()).ok_or(Error::ManifestMismatch)?,
        };
        let m: ManifestBody = open_json(&self.key()?, &ad("manifest", &[&self.id.0]), &sealed.0)?;
        self.base_from(&m.items);
        Ok(true)
    }

    /// Right after a pull: a pending delete of an item the server doesn't have
    /// (another device deleted it too, or it was added here and never stored)
    /// would remove nothing, which over the quota is refused, so it's done. With
    /// exact `base`s that's one with no `base` or an empty one. A push whose answer
    /// was lost moved the server's counter on, so that pull brought its manifest
    /// and gave its items a `base`.
    fn drop_done_deletes(&mut self) {
        if !self.exact_base {
            return;
        }
        let done: Vec<Hex> = self.deleted.iter().filter(|id| self.base.get(id).is_none_or(|b| b.0.is_empty())).copied().collect();
        for id in done {
            self.deleted.remove(&id);
            self.base.remove(&id);
            self.base_content.remove(&id);
            self.base_files.remove(&id);
        }
    }

    /// The next manifest: its signed envelope and its sealed part.
    fn seal_manifest(&self, me: &Me, vk: &Key, epoch: u64, roster: u64, items: BTreeMap<Hex, B64>) -> (Signed, B64) {
        let sealed = seal_json(vk, &ad("manifest", &[&self.id.0]), &ManifestBody { meta: self.meta.clone(), items });
        let env = ManifestEnvelope {
            vault_id: self.id,
            counter: self.counter + 1,
            epoch,
            roster,
            prev: self.last.clone(),
            sealed_hash: Some(h(&sealed)),
            sealed: None,
        };
        (me.sign_doc("manifest", &env), B64(sealed))
    }

    /// Seal pending changes into a signed request. After a 2xx call `pushed`;
    /// after a 409, pull (`apply`) and push again.
    pub fn push(&mut self, me: &Me, now: u64) -> Result<VaultPut, Error> {
        self.seal_push(me, now, usize::MAX)
    }

    /// Like `push`, but with only as many added and edited items as fit in `budget`
    /// bytes sealed (at least one, unless `budget` is 0), with every delete and the
    /// name. The rest stay pending, as the server has them. Over the quota a push
    /// must remove items, so a refused addition mustn't hold deletes up (`budget`
    /// 0); without a quota a member may stage only so much at once (a big import).
    /// A vault restored from an older app's snapshot pushes everything until it
    /// takes its `base`s from a manifest (a pull, `exact_base_from`) or a push leaves
    /// nothing pending: until then it can't tell which server copies a partial push
    /// would list.
    pub fn push_part(&mut self, me: &Me, now: u64, budget: usize) -> Result<VaultPut, Error> {
        self.seal_push(me, now, if self.exact_base { budget } else { usize::MAX })
    }

    fn seal_push(&mut self, me: &Me, now: u64, budget: usize) -> Result<VaultPut, Error> {
        if self.role(&me.username, now).is_none_or(|r| r < Role::Writer) {
            return Err(Error::ReadOnly);
        }
        let vk = self.key()?;
        let (mut upserts, mut used) = (Vec::new(), 0);
        for id in self.dirty.iter().take_while(|_| budget > 0) {
            let blob = seal_json(&vk, &self.item_ad(id), &self.entries[id].item);
            if !upserts.is_empty() && used + blob.len() > budget {
                break;
            }
            used += blob.len();
            self.entries.get_mut(id).expect("dirty entries exist").blob = blob.clone();
            upserts.push(ItemBlob { id: *id, blob: B64(blob) });
        }
        let sent: BTreeSet<Hex> = upserts.iter().map(|u| u.id).collect();
        // Left out of a partial push, an edited item stays at the server's copy
        // (`base`, empty once the server dropped it); an added one isn't there yet.
        let items = self
            .entries
            .iter()
            .filter_map(|(id, e)| match self.dirty.contains(id) && !sent.contains(id) {
                false => Some((*id, h(&e.blob))),
                true => self.base.get(id).filter(|b| !b.0.is_empty()).map(|b| (*id, b.clone())),
            })
            .collect();
        let (epoch, version) = self.roster.as_ref().map_or((0, 0), |r| (r.epoch, r.version));
        let (manifest, sealed) = self.seal_manifest(me, &vk, epoch, version, items);
        Ok(VaultPut {
            expected_counter: self.counter,
            manifest,
            sealed,
            upserts,
            deletes: self.deleted.iter().copied().collect(),
            staged: None,
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
                self.base_content.remove(&u.id);
                self.base_files.remove(&u.id);
            } else if self.dirty.contains(&u.id) || self.deleted.contains(&u.id) {
                // Changed again while this push was in flight: that change now
                // starts from the copy this push left on the server.
                match self.key().and_then(|k| open_json::<Item>(&k, &self.item_ad(&u.id), &u.blob.0)) {
                    Ok(item) => {
                        self.base.insert(u.id, h(&u.blob.0));
                        self.base_content.insert(u.id, content_hash(&item));
                        self.base_files.entry(u.id).or_default().extend(item.file_ids());
                    }
                    // Not under this vault's key: not a push of ours to begin with.
                    Err(_) => self.exact_base = false,
                }
            }
        }
        for d in &put.deletes {
            self.deleted.remove(d);
            self.base.remove(d);
            self.base_content.remove(d);
            self.base_files.remove(d);
        }
        self.meta_dirty = false;
        self.exact_base |= self.dirty.is_empty() && self.deleted.is_empty();
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
        if role == Role::Owner && expires.is_some() {
            return Err(Error::OwnerExpiry);
        }
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

    /// Remove people: a new vault key, every item re-sealed, so nothing written
    /// from now on is readable with the old key. Push pending changes first.
    pub fn revoke(&self, me: &Me, usernames: &[&str], now: u64) -> Result<RosterUpdate, Error> {
        if self.has_changes() {
            return Err(Error::PendingChanges);
        }
        let mut r = self.next_roster(me, now)?;
        r.members.retain(|m| !usernames.contains(&m.username.as_str()));
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
        let (manifest, sealed) = self.seal_manifest(me, &vk, r.epoch, r.version, items);
        let rotation = VaultPut { expected_counter: self.counter, manifest, sealed, upserts, deletes: vec![], staged: None };
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_head_needs_the_same_counter_and_manifest() {
        let (a, mut b) = (Vault::new(Hex([7; 16])), Vault::new(Hex([7; 16])));
        assert!(a.same_head(&b));
        // A fork: same counter, another manifest.
        b.last = B64(vec![1]);
        assert!(!a.same_head(&b));
        b.last = a.last.clone();
        b.counter = 1;
        assert!(!a.same_head(&b));
    }

    /// With nothing pending, an older app's snapshot holds the server's copies,
    /// so a change made after loading it may be pushed in parts.
    #[test]
    fn an_idle_older_snapshot_splits() {
        let me = crate::Keyring::new("alice").me();
        let (mut v, _) = Vault::create(&me, "x").unwrap();
        v.put(Hex([1; 16]), Item::default());
        let p = v.push(&me, 0).unwrap();
        v.pushed(&p);
        let mut json = serde_json::to_value(&v).unwrap();
        json.as_object_mut().unwrap().remove("exact_base");
        let mut old: Vault = serde_json::from_value(json).unwrap();
        for i in 2..5u8 {
            old.put(Hex([i; 16]), Item::default());
        }
        assert_eq!(old.push_part(&me, 0, 1).unwrap().upserts.len(), 1);
    }

    /// A snapshot from an older app may hold stale `base`s: it pushes everything
    /// at once until a push leaves nothing pending (or it takes its `base`s from a manifest).
    #[test]
    fn older_snapshots_push_everything() {
        let me = crate::Keyring::new("alice").me();
        let (mut v, _) = Vault::create(&me, "x").unwrap();
        let x = Hex([1; 16]);
        v.put(x, Item::default());
        let p = v.push(&me, 0).unwrap();
        v.pushed(&p);
        v.delete(x);
        v.put(Hex([2; 16]), Item::default());
        v.put(Hex([3; 16]), Item::default());
        assert_eq!(v.push_part(&me, 0, 1).unwrap().upserts.len(), 1);
        let mut json = serde_json::to_value(&v).unwrap();
        json.as_object_mut().unwrap().remove("exact_base");
        let mut old: Vault = serde_json::from_value(json).unwrap();
        assert_eq!(old.push_part(&me, 0, 0).unwrap().upserts.len(), 2);
        let p = old.push_part(&me, 0, 1).unwrap();
        assert_eq!((p.upserts.len(), p.deletes.len()), (2, 1));
        old.pushed(&p);
        old.put(Hex([4; 16]), Item::default());
        assert!(old.push_part(&me, 0, 0).unwrap().upserts.is_empty());
    }
}
