use super::*;
use crate::item::{Field, FileRef, Passkey, Section};
use crate::vault::Vault;

const BLOB_VECTOR: &str = "01030303030303030303030303030303030303030303030303f46a2a721b55a38803873c9683da27fbe1fc928015e0d59931";

#[test]
fn secret_key_roundtrip_and_typos() {
    let sk = SecretKey::generate();
    let s = sk.encode();
    assert_eq!(s.len(), 3 + 4 * 7 + 3);
    assert_eq!(SecretKey::parse(&s).unwrap().0, sk.0);
    assert_eq!(SecretKey::parse(&s.to_lowercase().replace('-', " ")).unwrap().0, sk.0);
    // The check pair is 10 bits of SHA-256, so a data-character typo slips past it
    // 1 time in 1024 by design. A typo in a check character always fails (the data,
    // and so the expected check pair, is unchanged); a data typo is tested on a
    // fixed key below so the test can't flake.
    let mut typo: Vec<char> = s.chars().collect();
    let last = typo.len() - 1;
    typo[last] = if typo[last] == 'X' { 'Y' } else { 'X' };
    assert!(SecretKey::parse(&typo.into_iter().collect::<String>()).is_err());
    let fixed = "A1-60RK4CS-M6MV3EE-1SC5H66-S35CRKK";
    assert!(SecretKey::parse(fixed).is_ok());
    assert!(SecretKey::parse(&fixed.replacen("60RK", "60XK", 1)).is_err());
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
        quota: None,
        usage: 0,
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
            gone: vec![],
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
    let fork = VaultResponse { counter: 3, manifests: vec![pf.manifest.clone()], rosters: vec![], key: None, items: pf.upserts.clone(), gone: vec![] };
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
    let r = v.revoke(&am, &["bob"], 0).unwrap();
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
    let resp = VaultResponse { counter: 3, manifests: vec![p1.manifest.clone()], rosters: vec![], key: None, items: p1.upserts.clone(), gone: vec![] };
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
fn links_carry_only_the_current_item() {
    let version = |pw: &str| Item {
        username: "me".into(),
        urls: vec!["https://x.test".into()],
        totp: "JBSWY3DPEHPK3PXP".into(),
        notes: "router in the hall".into(),
        sections: vec![Section { title: "s".into(), fields: vec![Field { label: "pin".into(), kind: "concealed".into(), value: "1234".into(), ..Default::default() }] }],
        tags: vec!["home".into()],
        ..login("wifi", pw)
    };
    let mut item = version("first-pw-1");
    item.edit(version("second-pw-2"), 10);
    item.edit(version("current-pw-3"), 20);
    item.favorite = true;
    item.archived = true;
    item.passkeys.push(Passkey {
        rp_id: "x.test".into(),
        credential_id: B64(vec![1]),
        user_handle: B64(vec![2]),
        user_name: "me".into(),
        private_key: B64(b"passkey-private".to_vec()),
        counter: 0,
        created: 0,
        extra: Default::default(),
    });
    item.files.push(FileRef { id: new_item_id(), name: "f".into(), size: 1, key: B64(b"file-key-bytes".to_vec()), hash: B64(vec![3]) });
    item.extra.insert("future".into(), "future-secret".into());
    assert!(!item.history.is_empty() && !item.password_history.is_empty());

    let (link, frag) = create_link(&item, 100, None);
    let got = open_link(&link.id, &link.blob.0, &frag).unwrap();
    let want = Item { history: vec![], password_history: vec![], passkeys: vec![], files: vec![], favorite: false, archived: false, extra: Default::default(), ..item.clone() };
    assert_eq!(got, want);
    let json = serde_json::to_string(&got).unwrap();
    for leak in ["first-pw-1", "second-pw-2", "future-secret"] {
        assert!(!json.contains(leak), "{leak} leaked into a link");
    }
}

#[test]
fn invites_verify_both_sides() {
    let mut admin = Keyring::new("admin");
    let (_, code) = admin.new_invite();
    let (_, s) = signup("newbie", "pw", Some(&code)).unwrap();
    let user = UserInfo { identity: s.request.identity.clone(), admin: false, disabled: false, invite: s.request.invite.clone() };
    assert_eq!(admin.verify_invitees(std::slice::from_ref(&user)).0, vec!["newbie".to_string()]);
    assert!(admin.contacts["newbie"].verified && admin.invites.is_empty());

    // A server substituting the new user's identity can't produce the proof.
    let mut admin2 = Keyring::new("admin");
    let (_, code2) = admin2.new_invite();
    let (_, s2) = signup("newbie", "pw", Some(&code2)).unwrap();
    let swapped = UserInfo { identity: Keyring::new("newbie").identity(Kind::Human, None), invite: s2.request.invite.clone(), ..user };
    assert!(admin2.verify_invitees(&[swapped]).0.is_empty());
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

#[test]
fn expired_writer_history_stays_valid_and_demotion_rotates() {
    let (mut a, mut b) = pair();
    let (am, bm) = (a.me(), b.me());
    let (v, nv) = Vault::create(&am, "Team").unwrap();
    let mut log = Log::new(&nv);
    let g = v.grant(&am, &a, "bob", Role::Writer, Some(100), 0).unwrap();
    assert!(g.rotation.is_none());
    log.roster(&g);
    // Bob writes last, before his access expires.
    let mut vb = Vault::new(v.id);
    vb.apply(&log.full("bob"), &mut b, 50).unwrap();
    vb.put(new_item_id(), login("bob's", "x"));
    let p = vb.push(&bm, 50).unwrap();
    log.put(&p);
    // Long after the expiry, a new device of alice's still syncs: bob could write then.
    let mut fresh = Vault::new(v.id);
    fresh.apply(&log.full("alice"), &mut a, 10_000).unwrap();
    assert_eq!(fresh.items().count(), 1);
    assert_eq!(fresh.creator, "alice");

    // Demoting bob to reader replaces the key; he keeps reading under the new one.
    let d = fresh.grant(&am, &a, "bob", Role::Reader, None, 10_000).unwrap();
    assert!(d.rotation.is_some());
    log.roster(&d);
    let mut vb2 = Vault::new(v.id);
    vb2.apply(&log.full("bob"), &mut b, 10_000).unwrap();
    assert_eq!(vb2.items().count(), 1);
    assert_eq!(vb2.role("bob", 10_000), Some(Role::Reader));
}

#[test]
fn fresh_device_can_start_from_the_latest_manifest() {
    let (mut a, _) = pair();
    let me = a.me();
    let (mut v, nv) = Vault::create(&me, "x").unwrap();
    let mut log = Log::new(&nv);
    for i in 0..3 {
        v.put(new_item_id(), login(&format!("i{i}"), "p"));
        let p = v.push(&me, 0).unwrap();
        v.pushed(&p);
        log.put(&p);
    }
    let mut latest = log.full("alice");
    latest.manifests = vec![latest.manifests.pop().unwrap()];
    let mut d = Vault::new(v.id);
    d.apply(&latest, &mut a, 0).unwrap();
    assert_eq!((d.items().count(), d.counter), (3, 4));
    // But a device with state still needs every link.
    let mut stale = log.full("alice");
    stale.manifests.truncate(2);
    stale.counter = 2;
    stale.items.clear();
    let mut e = Vault::new(v.id);
    e.apply(&Log::new(&nv).full("alice"), &mut a, 0).unwrap();
    let mut skip = log.full("alice");
    skip.manifests = vec![skip.manifests.pop().unwrap()];
    skip.rosters.clear();
    assert_eq!(e.apply(&skip, &mut a, 0).err(), Some(Error::Rollback));
}

/// Cross-checked by tools/kat.py.
#[test]
fn agent_and_fingerprint_vectors() {
    let d = derive_agent(&AgentKey(Zeroizing::new([5u8; 32])));
    assert_eq!(hex::encode(d.account_id), "272662a8c3c49ef130dfea9152628f6a");
    assert_eq!(hex::encode(d.auth.verifying_key().to_bytes()), "c4fad018f30f508ab8f9d287954471fb8c8fdf4b6a1b028bb6eb9072f8d10bfa");
    assert_eq!(fingerprint("alice", &[1u8; 32], &[2u8; 32]), "K45K00 6D7D9J H3NF4F PN9AAK");
}

#[test]
fn server_host_normalizes() {
    use crate::crypto::server_host;
    for (url, host) in [
        ("https://Vault.Example.com/", "vault.example.com"),
        ("https://vault.example.com:443/x?y#z", "vault.example.com"),
        ("http://192.168.1.5:8080", "192.168.1.5:8080"),
        ("vault.example.com", "vault.example.com"),
        ("http://[::1]:80", "[::1]"),
    ] {
        assert_eq!(server_host(url), host, "{url}");
    }
}

// ---------- Attacks from the 2026-11 security audit; each must stay fixed ----------

/// Advance an owner's own vault after a roster change it signed.
fn adopt(v: &mut Vault, log: &Log, u: &RosterUpdate, kr: &mut Keyring) {
    v.apply(&VaultResponse { counter: log.manifests.len() as u64, rosters: vec![u.roster.clone()], ..Default::default() }, kr, 0).unwrap();
}

#[test]
fn audit_rejected_roster_still_pins() {
    let (mut a, _) = pair();
    let am = a.me();
    let (v, nv) = Vault::create(&am, "x").unwrap();
    let mut d = Vault::new(v.id);
    d.apply(&Log::new(&nv).full("alice"), &mut a, 0).unwrap();
    // The server appends roster v1 "signed by alice", adding its own "carol"; alice never signed it.
    let mut server_carol = Keyring::new("carol");
    let mut r: Roster = serde_json::from_slice(&nv.roster.body.0).unwrap();
    r.version = 1;
    r.prev = B64(sha256(&nv.roster.body.0).to_vec());
    r.members.push(server_carol.me().member(Role::Reader));
    let mut forged = server_carol.me().sign_doc("roster", &r);
    forged.signer = "alice".into();
    assert_eq!(d.apply(&VaultResponse { counter: 1, rosters: vec![forged], ..Default::default() }, &mut a, 0), Err(Error::BadSignature));
    // Rejected, but the keyring was already changed. What alice sends "carol" now is the server's.
    server_carol.pin_identity(&a.identity(Kind::Human, None)).unwrap();
    let leaked = send(&am, &a, "carol", &Content::Request("prod DB password is hunter2".into()), None)
        .ok()
        .and_then(|m| receive(&server_carol, &m, 0).ok())
        .map(|(_, c)| c);
    assert!(!a.contacts.contains_key("carol"), "a rejected roster pinned carol to the server's key; server then read {leaked:?}");
}

#[test]
fn audit_agent_accepts_vault_from_servers_own_owner() {
    let mut owner = Keyring::new("alice");
    let (_, agent) = create_agent(&mut owner, "ci-bot").unwrap();
    let mut agent_kr = agent.keyring; // the agent's keyring as stored at signup
    assert!(agent_kr.contacts["alice"].verified && agent_kr.owner.as_deref() == Some("alice"));
    // The server's own "alice" makes a vault "CI" holding the real agent as a writer.
    let mut fake = Keyring::new("alice");
    fake.pin_identity(&agent.request.identity).unwrap();
    let fm = fake.me();
    let (mut fv, fnv) = Vault::create(&fm, "CI").unwrap();
    let mut log = Log::new(&fnv);
    let g = fv.grant(&fm, &fake, "ci-bot", Role::Writer, None, 0).unwrap();
    log.roster(&g);
    adopt(&mut fv, &log, &g, &mut fake);
    fv.put(new_item_id(), login("Deploy token", "attacker-chosen-token"));
    let p = fv.push(&fm, 0).unwrap();
    fv.pushed(&p);
    log.put(&p);
    let mut av = Vault::new(fv.id);
    // The agent knows its owner's real keys, so the look-alike "alice" is caught.
    assert_eq!(av.apply(&log.full("ci-bot"), &mut agent_kr, 0).err(), Some(Error::KeyChanged("alice".into())));
}

#[test]
fn audit_new_device_stays_on_pre_revocation_epoch() {
    let (mut a, mut b) = pair();
    let (am, bm) = (a.me(), b.me());
    let (mut v, nv) = Vault::create(&am, "Team").unwrap();
    let mut log = Log::new(&nv);
    let g = v.grant(&am, &a, "bob", Role::Writer, None, 0).unwrap();
    log.roster(&g);
    adopt(&mut v, &log, &g, &mut a);
    let mut fork = Log { rosters: log.rosters.clone(), manifests: log.manifests.clone(), keys: log.keys.clone(), items: log.items.clone() };
    let mut vb = Vault::new(v.id);
    vb.apply(&fork.full("bob"), &mut b, 0).unwrap();
    // Alice removes bob: new epoch, new key, every item re-sealed. Her device
    // pulls the new roster, which records it in her (synced) keyring.
    let r = v.revoke(&am, &["bob"], 0).unwrap();
    log.roster(&r);
    let rot = r.rotation.as_ref().unwrap();
    let delta = VaultResponse { counter: log.manifests.len() as u64, manifests: vec![rot.manifest.clone()], rosters: vec![r.roster.clone()], key: log.full("alice").key, items: rot.upserts.clone(), gone: vec![] };
    v.apply(&delta, &mut a, 0).unwrap();
    // Removed bob writes on the old branch; the server serves that branch to alice's new phone.
    vb.put(new_item_id(), login("Bank", "planted-by-removed-bob"));
    let pb = vb.push(&bm, 0).unwrap();
    vb.pushed(&pb);
    fork.put(&pb);
    let mut phone = Vault::new(v.id);
    // The phone gets the keyring: a server still serving the old branch is caught.
    // (A server that also serves the phone an old keyring isn't: see DESIGN, Known limits.)
    assert_eq!(phone.apply(&fork.full("alice"), &mut a, 0), Err(Error::Rollback));
}

#[test]
fn audit_server_drops_concurrent_edit_without_conflict_copy() {
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
    v1.put(id, login("bank", "rotated-on-device-1"));
    let p1 = v1.push(&me, 0).unwrap();
    v1.pushed(&p1);
    log.put(&p1);
    v2.put(id, login("bank", "stale-edit-on-device-2"));
    // Same response as concurrent_edit_keeps_conflict_copy, minus the changed item's blob.
    let resp = VaultResponse { counter: 3, manifests: vec![p1.manifest.clone()], rosters: vec![], key: None, items: vec![], gone: vec![] };
    // Refused: the other edit would otherwise vanish instead of becoming a conflict copy.
    assert_eq!(v2.apply(&resp, &mut a, 0), Err(Error::ManifestMismatch));
}

#[test]
fn audit_message_resigned_by_other_sender() {
    let (a, mut b) = pair();
    let mallory = Keyring::new("mallory");
    b.pin_identity(&mallory.identity(Kind::Human, None)).unwrap();
    let msg = send(&a.me(), &a, "bob", &Content::Item(Box::new(login("Prod DB", "s3cret-from-alice"))), None).unwrap();
    // Whoever holds the envelope (the server) re-signs alice's ciphertext as mallory.
    let body: Message = serde_json::from_slice(&msg.body.0).unwrap();
    let resigned = mallory.me().sign_doc("message", &body);
    let got = receive(&b, &resigned, 0);
    assert!(got.is_err(), "bob accepts alice's item as sent by {}: {:?}", resigned.signer, got.map(|(_, c)| c));
}

#[test]
fn audit_unpadded_message_and_keyring_lengths() {
    let (a, _) = pair();
    let len = |pw: &str| {
        let s = send(&a.me(), &a, "bob", &Content::Item(Box::new(login("wifi", pw))), None).unwrap();
        serde_json::from_slice::<Message>(&s.body.0).unwrap().sealed.0.len()
    };
    let acct = Account { id: random(), account_key: random_key() };
    let mut k = a.clone();
    let before = k.seal(&acct).len();
    k.mark_verified("bob");
    let after = k.seal(&acct).len();
    assert!(len("12345678") == len("123456789") && before == after,
        "message: 8-char pw {} bytes, 9-char pw {} bytes; keyring {} bytes before verifying bob, {} after", len("12345678"), len("123456789"), before, after);
}

#[test]
fn audit_expired_owner_makes_history_unverifiable() {
    let (mut a, mut b) = pair();
    let (am, bm) = (a.me(), b.me());
    let (mut v, nv) = Vault::create(&am, "Team").unwrap();
    // Owners can't expire: a roster they signed has to stay checkable forever.
    assert_eq!(v.grant(&am, &a, "bob", Role::Owner, Some(100), 0).err(), Some(Error::OwnerExpiry));
    let mut log = Log::new(&nv);
    let g = v.grant(&am, &a, "bob", Role::Owner, None, 0).unwrap();
    log.roster(&g);
    adopt(&mut v, &log, &g, &mut a);
    // While he is an owner, bob adds carol; later alice removes bob.
    let carol = Keyring::new("carol");
    b.pin_identity(&carol.identity(Kind::Human, None)).unwrap();
    let mut vb = Vault::new(v.id);
    vb.apply(&log.full("bob"), &mut b, 50).unwrap();
    let g2 = vb.grant(&bm, &b, "carol", Role::Reader, None, 50).unwrap();
    log.roster(&g2);
    v.apply(&VaultResponse { counter: log.manifests.len() as u64, rosters: vec![g2.roster.clone()], ..Default::default() }, &mut a, 60).unwrap();
    let r = v.revoke(&am, &["bob"], 200).unwrap();
    log.roster(&r);
    let later = Vault::new(v.id).apply(&log.full("alice"), &mut a, 300);
    assert!(later.is_ok(), "a fresh device of the vault's creator after bob left: {later:?}");
}

#[test]
fn audit_invite_proof_loses_to_server_prepin() {
    let mut admin = Keyring::new("admin");
    let (_, code) = admin.new_invite();
    // Before the invitee signs up, the server lists a vault of its own in admin's account,
    // roster v0 signed by its own "newbie". Syncing it pins "newbie" with no user action.
    let mut fake = Keyring::new("newbie");
    fake.pin_identity(&admin.identity(Kind::Human, None)).unwrap();
    let fm = fake.me();
    let (fv, fnv) = Vault::create(&fm, "Welcome").unwrap();
    let mut log = Log::new(&fnv);
    let g = fv.grant(&fm, &fake, "admin", Role::Reader, None, 0).unwrap();
    log.roster(&g);
    Vault::new(fv.id).apply(&log.full("admin"), &mut admin, 0).unwrap();
    // The real newbie signs up with the code; the proof checks out.
    let (_, s) = signup("newbie", "pw", Some(&code)).unwrap();
    let user = UserInfo { identity: s.request.identity.clone(), admin: false, disabled: false, invite: s.request.invite.clone() };
    // Neither wins silently: the proof only shows that whoever held the code made
    // this identity, and the server chose which name it's listed under.
    let (done, conflicts) = admin.verify_invitees(&[user]);
    assert!(done.is_empty());
    assert_eq!(conflicts, vec!["newbie".to_string()], "the conflict is reported");
    assert_eq!(admin.contacts["newbie"].sign_pk, fm.sign_pk(), "the earlier pin is kept until the user compares fingerprints");
    assert!(!admin.invites.is_empty(), "the invite stays, so it verifies once the pin is fixed");
}

#[test]
fn audit_agent_only_obeys_vaults_its_owner_signed() {
    let mut owner = Keyring::new("alice");
    let (_, agent) = create_agent(&mut owner, "ci-bot").unwrap();
    let mut agent_kr = agent.keyring;
    // A server-made "mallory" shares a vault with the agent: refused.
    let mut mallory = Keyring::new("mallory");
    mallory.pin_identity(&agent.request.identity).unwrap();
    let mm = mallory.me();
    let (mut fv, fnv) = Vault::create(&mm, "CI").unwrap();
    let mut log = Log::new(&fnv);
    let g = fv.grant(&mm, &mallory, "ci-bot", Role::Writer, None, 0).unwrap();
    log.roster(&g);
    adopt(&mut fv, &log, &g, &mut mallory);
    assert_eq!(Vault::new(fv.id).apply(&log.full("ci-bot"), &mut agent_kr, 0).err(), Some(Error::NotFromOwner));
    // Bob's vault, which alice co-owns, shared with the agent by alice: accepted.
    let mut bob = Keyring::new("bob");
    bob.pin_identity(&owner.identity(Kind::Human, None)).unwrap();
    owner.pin_identity(&bob.identity(Kind::Human, None)).unwrap();
    let bm = bob.me();
    let (mut bv, bnv) = Vault::create(&bm, "Infra").unwrap();
    let mut log = Log::new(&bnv);
    let g = bv.grant(&bm, &bob, "alice", Role::Owner, None, 0).unwrap();
    log.roster(&g);
    adopt(&mut bv, &log, &g, &mut bob);
    let mut av = Vault::new(bv.id);
    av.apply(&log.full("alice"), &mut owner, 0).unwrap();
    let g2 = av.grant(&owner.me(), &owner, "ci-bot", Role::Reader, None, 0).unwrap();
    log.roster(&g2);
    assert!(Vault::new(bv.id).apply(&log.full("ci-bot"), &mut agent_kr, 0).is_ok());
}

#[test]
fn audit_delayed_rotation_undoes_a_delete() {
    let (mut a, _) = pair();
    let am = a.me();
    let (mut v, nv) = Vault::create(&am, "x").unwrap();
    let mut log = Log::new(&nv);
    let id = new_item_id();
    v.put(id, login("leaked api key", "compromised"));
    let p = v.push(&am, 0).unwrap();
    v.pushed(&p);
    log.put(&p);
    let g = v.grant(&am, &a, "bob", Role::Reader, None, 0).unwrap();
    log.roster(&g);
    adopt(&mut v, &log, &g, &mut a);
    // Alice's second device, in sync.
    let mut d2 = Vault::new(v.id);
    d2.apply(&log.full("alice"), &mut a, 0).unwrap();
    // The laptop removes bob (key rotation); the server holds that back from device 2 for now.
    let r = v.revoke(&am, &["bob"], 0).unwrap();
    log.roster(&r);
    // Device 2 deletes the item, then pulls before pushing (as sync_vault does).
    d2.delete(id);
    let resp = VaultResponse { counter: log.manifests.len() as u64, manifests: vec![r.rotation.as_ref().unwrap().manifest.clone()], rosters: vec![r.roster.clone()], key: log.full("alice").key, items: r.rotation.as_ref().unwrap().upserts.clone(), gone: vec![] };
    d2.apply(&resp, &mut a, 0).unwrap();
    assert!(d2.get(&id).is_none() && d2.has_changes(), "delete undone by a re-seal: item back = {:?}, pending delete = {}", d2.get(&id).map(|i| &i.title), d2.has_changes());
}

#[test]
fn attachment_names_are_never_paths() {
    use crate::item::safe_file_name;
    for (name, safe) in [
        ("passport.pdf", "passport.pdf"),
        ("../../Library/Preferences/x.plist", "x.plist"),
        ("/etc/passwd", "passwd"),
        ("C:\\Windows\\evil.dll", "evil.dll"),
        ("..", "attachment"),
        ("dir/..", "attachment"),
        ("", "attachment"),
        ("a\u{1b}]52;c;x\u{7}b.txt", "a]52;c;xb.txt"),
    ] {
        assert_eq!(safe_file_name(name), safe, "{name:?}");
    }
}

#[test]
fn attachments_are_padded() {
    let (key, vault, file) = (random_key(), random::<16>(), random::<16>());
    for (len, want) in [(0, 256), (1, 256), (300, 304), (5000, 5120), (1_000_000, 1_015_808), (40_000_000, 40_894_464)] {
        assert_eq!(padded_file_len(len), want, "{len}");
    }
    let mut last = 0;
    for len in (0..MAX_FILE).step_by(9973).chain([MAX_FILE - SEAL_OVERHEAD]) {
        let p = padded_file_len(len);
        assert!(p >= len && p >= last && p + SEAL_OVERHEAD <= MAX_FILE.max(len + SEAL_OVERHEAD), "{len}");
        assert!(len < PAD || p - len <= len / 8, "{len}: at most 12.5% bigger");
        last = p;
    }
    assert_eq!(padded_file_len(MAX_FILE - SEAL_OVERHEAD) + SEAL_OVERHEAD, MAX_FILE, "the biggest file the server takes still fits");
    assert_eq!(padded_file_len(usize::MAX), usize::MAX);
    let blob = seal_file(&key, &vault, &file, b"%PDF scan");
    assert_eq!(blob.len(), 256 + SEAL_OVERHEAD);
    assert_eq!(&open_file(&key, &vault, &file, 9, &blob).unwrap()[..], b"%PDF scan");
    assert_eq!(open_file(&key, &vault, &file, 257, &blob), Err(Error::Tampered), "a size past the blob");
    let big = seal_file(&key, &vault, &file, &[7; 5000]);
    assert_eq!(open_file(&key, &vault, &file, 5000, &big).unwrap().len(), 5000);
    let raw = open(&key, &ad("file", &[&vault, &file]), &big).unwrap();
    assert_eq!((raw.len(), raw[5000..].iter().all(|&b| b == 0)), (5120, true), "zero padding");
    assert_eq!(open_file(&key, &vault, &file, u64::MAX, &blob), Err(Error::Tampered));
    // Files uploaded before padding are exactly their size.
    let old = seal(&key, &ad("file", &[&vault, &file]), b"old file");
    assert_eq!(&open_file(&key, &vault, &file, 8, &old).unwrap()[..], b"old file");
}

/// A pull with just this manifest and its blobs (what the server sends after `p`).
fn delta(log: &Log, p: &VaultPut) -> VaultResponse {
    VaultResponse { counter: log.manifests.len() as u64, manifests: vec![p.manifest.clone()], rosters: vec![], key: None, items: p.upserts.clone(), gone: vec![] }
}

fn titles(v: &Vault) -> Vec<String> {
    let mut t: Vec<String> = v.items().map(|(_, i)| format!("{}={}", i.title, i.password)).collect();
    t.sort();
    t
}

/// #987: an item edited here while the server also changed it keeps syncing
/// afterwards, though later pulls don't resend that item's blob.
#[test]
fn pending_edit_keeps_syncing_after_a_conflict() {
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
    v2.apply(&delta(&log, &p1), &mut a, 0).unwrap();
    // Device 1 adds something else; device 2 pulls again, its edit still pending.
    v1.put(new_item_id(), login("other", "x"));
    let p2 = v1.push(&me, 0).unwrap();
    v1.pushed(&p2);
    log.put(&p2);
    v2.apply(&delta(&log, &p2), &mut a, 0).unwrap();
    let p3 = v2.push(&me, 0).unwrap();
    v2.pushed(&p3);
    log.put(&p3);
    let mut fresh = Vault::new(v1.id);
    fresh.apply(&log.full("alice"), &mut a, 0).unwrap();
    assert_eq!(titles(&fresh), ["bank (conflict)=from device 1", "bank=from device 2", "other=x"]);
}

/// #987, the re-seal case: a key rotation re-seals an item edited or deleted here.
#[test]
fn pending_edit_and_delete_keep_syncing_after_a_rotation() {
    let (mut a, _) = pair();
    let am = a.me();
    let (mut v, nv) = Vault::create(&am, "x").unwrap();
    let mut log = Log::new(&nv);
    let (x, y) = (new_item_id(), new_item_id());
    v.put(x, login("edit me", "old"));
    v.put(y, login("delete me", "y"));
    let p = v.push(&am, 0).unwrap();
    v.pushed(&p);
    log.put(&p);
    let g = v.grant(&am, &a, "bob", Role::Reader, None, 0).unwrap();
    log.roster(&g);
    adopt(&mut v, &log, &g, &mut a);
    let mut d2 = Vault::new(v.id);
    d2.apply(&log.full("alice"), &mut a, 0).unwrap();
    let r = v.revoke(&am, &["bob"], 0).unwrap();
    log.roster(&r);
    let rot = r.rotation.as_ref().unwrap();
    let rotation = VaultResponse { counter: log.manifests.len() as u64, manifests: vec![rot.manifest.clone()], rosters: vec![r.roster.clone()], key: log.full("alice").key, items: rot.upserts.clone(), gone: vec![] };
    v.apply(&rotation, &mut a, 0).unwrap();
    d2.put(x, login("edit me", "new"));
    d2.delete(y);
    d2.apply(&rotation, &mut a, 0).unwrap();
    // The laptop adds an item; device 2 pulls again with both changes pending.
    v.put(new_item_id(), login("later", "z"));
    let p2 = v.push(&am, 0).unwrap();
    v.pushed(&p2);
    log.put(&p2);
    d2.apply(&delta(&log, &p2), &mut a, 0).unwrap();
    let p3 = d2.push(&am, 0).unwrap();
    d2.pushed(&p3);
    log.put(&p3);
    let mut fresh = Vault::new(v.id);
    fresh.apply(&log.full("alice"), &mut a, 0).unwrap();
    assert_eq!(titles(&fresh), ["edit me=new", "later=z"]);
}
