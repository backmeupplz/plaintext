use super::*;
use crate::vault::Vault;

const BLOB_VECTOR: &str = "01030303030303030303030303030303030303030303030303f46a2a721b55a38803873c9683da27fbe1fc928015e0d59931";

#[test]
fn secret_key_roundtrip_and_typos() {
    let sk = SecretKey::generate();
    let s = sk.encode();
    assert_eq!(s.len(), 3 + 4 * 7 + 3);
    assert_eq!(SecretKey::parse(&s).unwrap().0, sk.0);
    assert_eq!(SecretKey::parse(&s.to_lowercase().replace('-', " ")).unwrap().0, sk.0);
    let mut typo: Vec<char> = s.chars().collect();
    typo[5] = if typo[5] == 'X' { 'Y' } else { 'X' };
    assert!(SecretKey::parse(&typo.into_iter().collect::<String>()).is_err());
}

#[test]
fn agent_key_roundtrip() {
    let k = AgentKey::generate();
    assert_eq!(AgentKey::parse(&k.encode()).unwrap().0, k.0);
    assert!(AgentKey::parse("ptk_abc").is_err());
}

/// Known-answer vectors, cross-checked by an independent Python implementation
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
fn blob_vector() {
    let key = Zeroizing::new([7u8; 32]);
    let blob = hex::decode(BLOB_VECTOR).unwrap();
    assert_eq!(&open(&key, &ad("item", &[&[1u8; 16], &[2u8; 16]]), &blob).unwrap()[..], b"plaintext");
}

#[test]
fn seal_to_roundtrip() {
    let kr = Keyring::new("alice");
    let me = kr.me();
    let blob = seal_to(&me.enc_pk().0, b"ad", b"hi").unwrap();
    assert_eq!(&open_from(&me.enc, b"ad", &blob).unwrap()[..], b"hi");
    assert!(open_from(&me.enc, b"other", &blob).is_err());
    // A low-order point instead of a real key is refused.
    assert!(seal_to(&[0u8; 32], b"ad", b"hi").is_err());
}

fn account_response(s: &Signup) -> AccountResponse {
    AccountResponse {
        username: s.keyring.username.clone(),
        admin: false,
        account_key: s.request.account_key.clone(),
        keyring: s.request.keyring.clone(),
        keyring_counter: 0,
        vaults: vec![],
    }
}

#[test]
fn unlock_and_password_change() {
    let (sk, s) = signup("alice", "hunter2", None).unwrap();
    let resp = account_response(&s);
    let (acct, kr) = unlock(&derive("hunter2", &sk), &resp).unwrap();
    assert_eq!(kr.username, "alice");
    assert_eq!(unlock(&derive("hunter3", &sk), &resp).err(), Some(Error::Tampered));
    assert_eq!(unlock(&derive("hunter2", &SecretKey::generate()), &resp).err(), Some(Error::Tampered));

    let pc = change_password(&derive("hunter2", &sk), &acct, &sk, "new pass", 1);
    let mut resp2 = resp.clone();
    resp2.account_key = pc.account_key.clone();
    assert!(unlock(&derive("new pass", &sk), &resp2).is_ok());
    assert!(unlock(&derive("hunter2", &sk), &resp2).is_err());
    assert_eq!(pc.auth_key.0, derive("new pass", &sk).auth.verifying_key().to_bytes().to_vec());
}

/// Two users who have pinned each other.
fn pair() -> (Keyring, Keyring) {
    let mut a = Keyring::new("alice");
    let mut b = Keyring::new("bob");
    a.pin_identity(&b.identity(Kind::Human, None)).unwrap();
    b.pin_identity(&a.identity(Kind::Human, None)).unwrap();
    (a, b)
}

/// What an honest server would send a device that has seen nothing yet.
struct Log {
    rosters: Vec<Signed>,
    manifests: Vec<Signed>,
    keys: Vec<WrappedKey>,
    items: BTreeMap<Hex, B64>,
}

use std::collections::BTreeMap;

impl Log {
    fn new(nv: &NewVault) -> Log {
        Log { rosters: vec![nv.roster.clone()], manifests: vec![nv.manifest.clone()], keys: nv.keys.clone(), items: BTreeMap::new() }
    }
    fn put(&mut self, p: &VaultPut) {
        self.manifests.push(p.manifest.clone());
        for u in &p.upserts {
            self.items.insert(u.id, u.blob.clone());
        }
        for d in &p.deletes {
            self.items.remove(d);
        }
    }
    fn roster(&mut self, u: &RosterUpdate) {
        self.rosters.push(u.roster.clone());
        self.keys.extend(u.keys.iter().cloned());
        if let Some(r) = &u.rotation {
            self.items.clear();
            self.put(r);
        }
    }
    fn full(&self, user: &str) -> VaultResponse {
        VaultResponse {
            counter: self.manifests.len() as u64,
            manifests: self.manifests.clone(),
            rosters: self.rosters.clone(),
            key: self.keys.iter().rev().find(|k| k.username == user).map(|k| k.key.clone()),
            items: self.items.iter().map(|(id, blob)| ItemBlob { id: *id, blob: blob.clone() }).collect(),
        }
    }
}

fn login(title: &str, pw: &str) -> Item {
    Item { kind: "login".into(), title: title.into(), password: pw.into(), ..Default::default() }
}

#[test]
fn sync_and_server_tampering() {
    let (mut a, _) = pair();
    let me = a.me();
    let (mut v, nv) = Vault::create(&me, "Shared").unwrap();
    let mut log = Log::new(&nv);
    let (x, y) = (new_item_id(), new_item_id());
    v.put(x, login("x", "px"));
    v.put(y, login("y", "py"));
    let p = v.push(&me, 0).unwrap();
    v.pushed(&p);
    log.put(&p);
    let good = log.full("alice");

    let fresh = |kr: &mut Keyring, r: &VaultResponse| Vault::new(v.id).apply(r, kr, 0).map(|_| ());
    assert_eq!(fresh(&mut a, &good), Ok(()));

    let mut swapped = good.clone();
    let (i0, i1) = (swapped.items[0].id, swapped.items[1].id);
    swapped.items[0].id = i1;
    swapped.items[1].id = i0;
    assert!(fresh(&mut a, &swapped).is_err());

    let mut dropped = good.clone();
    dropped.items.pop();
    assert_eq!(fresh(&mut a, &dropped), Err(Error::ManifestMismatch));

    let mut gap = good.clone();
    gap.manifests.remove(0);
    assert_eq!(fresh(&mut a, &gap), Err(Error::Rollback));

    let mut lie = good.clone();
    lie.counter = 9;
    assert_eq!(fresh(&mut a, &lie), Err(Error::ManifestMismatch));

    // The server swaps in a vault key of its own, sealed to alice's real key.
    let mut subst = good.clone();
    let fake = seal_to(&me.enc_pk().0, &[ad("vault-key", &[&v.id.0]), 0u64.to_be_bytes().to_vec(), b"alice".to_vec()].concat(), &[9u8; 32]).unwrap();
    subst.key = Some(B64(fake));
    assert_eq!(fresh(&mut a, &subst), Err(Error::Tampered));

    // A device that has seen counter 2 refuses to go back.
    let mut d = Vault::new(v.id);
    d.apply(&good, &mut a, 0).unwrap();
    let mut old = good.clone();
    old.manifests.clear();
    old.rosters.clear();
    old.items.clear();
    old.counter = 1;
    assert_eq!(d.apply(&old, &mut a, 0), Err(Error::Rollback));

    // A fork: a different manifest at the same counter doesn't link to ours.
    let mut f = Vault::new(v.id);
    let mut log2 = Log::new(&nv);
    f.apply(&log2.full("alice"), &mut a, 0).unwrap();
    f.put(new_item_id(), login("other branch", "z"));
    let pf = f.push(&me, 0).unwrap();
    log2.put(&pf);
    let mut next = Vault::new(v.id);
    next.apply(&good, &mut a, 0).unwrap();
    let fork = VaultResponse { counter: 3, manifests: vec![pf.manifest.clone()], rosters: vec![], key: None, items: pf.upserts.clone() };
    assert_eq!(next.apply(&fork, &mut a, 0), Err(Error::Rollback));
}

#[test]
fn sharing_roles_and_revocation() {
    let (mut a, mut b) = pair();
    let (am, bm) = (a.me(), b.me());
    let (mut v, nv) = Vault::create(&am, "Family").unwrap();
    let mut log = Log::new(&nv);
    let id = new_item_id();
    v.put(id, login("Netflix", "n3tfl1x"));
    let p = v.push(&am, 0).unwrap();
    v.pushed(&p);
    log.put(&p);

    // Bob as reader: he can read, can't push, and a manifest he signs anyway is refused.
    let g = v.grant(&am, &a, "bob", Role::Reader, None, 0).unwrap();
    log.roster(&g);
    v.apply(&VaultResponse { counter: log.manifests.len() as u64, rosters: vec![g.roster.clone()], ..Default::default() }, &mut a, 0).unwrap();
    let mut vb = Vault::new(v.id);
    vb.apply(&log.full("bob"), &mut b, 0).unwrap();
    assert_eq!(vb.get(&id).unwrap().password, "n3tfl1x");
    vb.put(new_item_id(), login("sneaky", "x"));
    assert_eq!(vb.push(&bm, 0).err(), Some(Error::ReadOnly));

    // A server that lets the reader write anyway: everyone else refuses it.
    vb.roster.as_mut().unwrap().members.iter_mut().for_each(|m| m.role = Role::Owner);
    let forged = vb.push(&bm, 0).unwrap();
    let mut log_forged = Log { rosters: log.rosters.clone(), manifests: log.manifests.clone(), keys: log.keys.clone(), items: log.items.clone() };
    log_forged.put(&forged);
    assert_eq!(Vault::new(v.id).apply(&log_forged.full("alice"), &mut a, 0).err(), Some(Error::BadSignature));

    // Expiry: after it, bob is treated as removed.
    let g2 = v.grant(&am, &a, "bob", Role::Writer, Some(100), 0).unwrap();
    log.roster(&g2);
    assert!(Vault::new(v.id).apply(&log.full("bob"), &mut b, 50).is_ok());
    assert_eq!(Vault::new(v.id).apply(&log.full("bob"), &mut b, 100).err(), Some(Error::NotMember));

    // Revocation rotates the key: bob gets no new key and can't read what follows.
    let mut v = Vault::new(v.id);
    v.apply(&log.full("alice"), &mut a, 0).unwrap();
    let r = v.revoke(&am, "bob", 0).unwrap();
    log.roster(&r);
    assert!(r.keys.iter().all(|k| k.username != "bob"));
    let mut va = Vault::new(v.id);
    va.apply(&log.full("alice"), &mut a, 0).unwrap();
    assert_eq!(va.get(&id).unwrap().password, "n3tfl1x");
    assert_eq!(Vault::new(v.id).apply(&log.full("bob"), &mut b, 0).err(), Some(Error::NotMember));
}

#[test]
fn swapped_identity_key_is_caught() {
    let (mut a, mut b) = pair();
    let am = a.me();
    let (v, nv) = Vault::create(&am, "x").unwrap();
    let g = v.grant(&am, &a, "bob", Role::Reader, None, 0).unwrap();
    let mut log = Log::new(&nv);
    log.roster(&g);
    // Bob thinks alice has different keys than the roster's.
    b.contacts.get_mut("alice").unwrap().sign_pk = Keyring::new("alice").me().sign_pk();
    assert_eq!(Vault::new(v.id).apply(&log.full("bob"), &mut b, 0).err(), Some(Error::KeyChanged("alice".into())));
    // Granting to someone not pinned is refused outright.
    a.contacts.remove("bob");
    assert_eq!(v.grant(&am, &a, "bob", Role::Reader, None, 0).err(), Some(Error::UnknownUser("bob".into())));
}

#[test]
fn concurrent_edit_keeps_conflict_copy() {
    let (mut a, _) = pair();
    let me = a.me();
    let (mut v1, nv) = Vault::create(&me, "x").unwrap();
    let mut log = Log::new(&nv);
    let id = new_item_id();
    v1.put(id, login("bank", "one"));
    let p = v1.push(&me, 0).unwrap();
    v1.pushed(&p);
    log.put(&p);
    let mut v2 = Vault::new(v1.id);
    v2.apply(&log.full("alice"), &mut a, 0).unwrap();

    v1.put(id, login("bank", "from device 1"));
    let p1 = v1.push(&me, 0).unwrap();
    v1.pushed(&p1);
    log.put(&p1);
    v2.put(id, login("bank", "from device 2"));
    let resp = VaultResponse { counter: 3, manifests: vec![p1.manifest.clone()], rosters: vec![], key: None, items: p1.upserts.clone() };
    v2.apply(&resp, &mut a, 0).unwrap();
    assert_eq!(v2.get(&id).unwrap().password, "from device 2");
    let copy = v2.items().find(|(_, i)| i.title == "bank (conflict)").unwrap().1;
    assert_eq!(copy.password, "from device 1");
}

#[test]
fn edit_during_push_stays_dirty_and_snapshot_restores() {
    let (a, _) = pair();
    let me = a.me();
    let (mut v, _) = Vault::create(&me, "x").unwrap();
    let id = new_item_id();
    v.put(id, login("v1", ""));
    let put = v.push(&me, 0).unwrap();
    v.put(id, login("v2", ""));
    v.pushed(&put);
    assert!(v.has_changes());

    let acct = Account { id: random(), account_key: random_key() };
    let r = Vault::restore(&acct, v.id, &v.snapshot(&acct)).unwrap();
    assert_eq!((r.counter, r.get(&id).unwrap().title.as_str(), r.has_changes()), (2, "v2", true));
}

#[test]
fn messages_and_links() {
    let (a, b) = pair();
    let item = login("wifi", "hunter2hunter2");
    let msg = send(&a.me(), &a, "bob", &Content::Item(Box::new(item.clone())), Some(100)).unwrap();
    let (m, c) = receive(&b, &msg, 50).unwrap();
    assert_eq!((m.kind, c), (MessageKind::Item, Content::Item(Box::new(item.clone()))));
    assert_eq!(receive(&b, &msg, 100).err(), Some(Error::Expired));
    // Someone else (or the server) can't read it or forge the sender.
    assert!(receive(&a, &msg, 0).is_err());
    let mut forged = msg.clone();
    forged.signer = "carol".into();
    assert!(receive(&b, &forged, 0).is_err());

    let (link, frag) = create_link(&item, 100, Some(1));
    assert_eq!(open_link(&link.id, &link.blob.0, &frag).unwrap(), item);
    assert!(open_link(&new_item_id(), &link.blob.0, &frag).is_err());
}

#[test]
fn invites_verify_both_sides() {
    let mut admin = Keyring::new("admin");
    let (_, code) = admin.new_invite();
    let (_, s) = signup("newbie", "pw", Some(&code)).unwrap();
    let user = UserInfo { identity: s.request.identity.clone(), admin: false, disabled: false, invite: s.request.invite.clone() };
    assert_eq!(admin.verify_invitees(std::slice::from_ref(&user)), vec!["newbie".to_string()]);
    assert!(admin.contacts["newbie"].verified && admin.invites.is_empty());

    // A server substituting the new user's identity can't produce the proof.
    let mut admin2 = Keyring::new("admin");
    let (_, code2) = admin2.new_invite();
    let (_, s2) = signup("newbie", "pw", Some(&code2)).unwrap();
    let swapped = UserInfo { identity: Keyring::new("newbie").identity(Kind::Human, None), invite: s2.request.invite.clone(), ..user };
    assert!(admin2.verify_invitees(&[swapped]).is_empty());
}

#[test]
fn agents_are_pinned_by_their_owner() {
    let mut owner = Keyring::new("alice");
    let (key, s) = create_agent(&mut owner, "deploy-bot").unwrap();
    assert!(owner.contacts["deploy-bot"].verified);
    assert!(s.vault.is_none());
    let id: Identity = serde_json::from_slice(&s.request.identity.body.0).unwrap();
    assert_eq!((id.kind, id.owner.as_deref()), (Kind::Agent, Some("alice")));
    assert_eq!(derive_agent(&AgentKey::parse(&key.encode()).unwrap()).account_id, s.account.id);
}
