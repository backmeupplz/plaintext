//! End to end over real HTTP: a family, a shared vault, an agent, inbox, links,
//! files, password change, and a database that never holds anything readable.

use super::*;
use plaintext_core::crypto::{AgentKey, derive_agent};
use plaintext_core::item::Item;

fn server() -> (String, std::path::PathBuf) {
    let path = std::env::temp_dir().join(format!("plaintext-e2e-{}.db", hex::encode(plaintext_core::crypto::random::<8>())));
    let db = plaintext_server::open_db(path.to_str().unwrap()).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            tx.send(l.local_addr().unwrap()).unwrap();
            axum::serve(l, plaintext_server::app(db, Some("first-run-code".into()))).await.unwrap();
        });
    });
    (format!("http://{}", rx.recv().unwrap()), path)
}

fn login(url: &str, pw: &str, sk: &SecretKey) -> Session<Http> {
    Session::login(Http::new(url), &derive(pw, sk), "test").unwrap()
}

fn item(title: &str, pw: &str) -> Item {
    Item { kind: "login".into(), title: title.into(), username: format!("{title}-user"), password: pw.into(), ..Default::default() }
}

fn status(r: Result<impl Sized>) -> u16 {
    match r {
        Err(Error::Server(code, _)) => code,
        Ok(_) => 200,
        Err(e) => panic!("{e}"),
    }
}

#[test]
fn family_agent_and_sharing() {
    let (url, path) = server();

    // The first user becomes the admin; the next needs an invite.
    assert_eq!(status(Session::signup(Http::new(&url), "mallory", "pw", None, "x")), 403, "the setup code guards the first account");
    let (ask, mut alice) = Session::signup(Http::new(&url), "alice", "alice pw", Some("first-run-code"), "laptop").unwrap();
    assert!(alice.admin);
    assert_eq!(status(Session::signup(Http::new(&url), "bob", "bob pw", None, "phone")), 403);
    let code = alice.invite().unwrap();
    let (bsk, mut bob) = Session::signup(Http::new(&url), "bob", "bob pw", Some(&code), "phone").unwrap();
    assert!(!bob.admin);
    assert_eq!(status(Session::signup(Http::new(&url), "carol", "pw", Some(&code), "x")), 403); // used up
    alice.sync().unwrap();
    assert!(alice.keyring.contacts["bob"].verified, "the invite proof verifies bob for alice");
    assert!(bob.keyring.contacts["alice"].verified, "the invite code verifies alice for bob");

    // Personal items sync to alice's second device.
    alice.sync().unwrap();
    let personal = alice.default_vault().unwrap();
    let id = plaintext_core::new_item_id();
    alice.put_item(&personal, id, item("Bank of Nowhere", "SuperSecret-9431")).unwrap();
    let mut alice2 = login(&url, "alice pw", &ask);
    alice2.sync().unwrap();
    assert_eq!(alice2.one("bank of nowhere", None).unwrap().2.password, "SuperSecret-9431");

    // A family vault shared with bob as a writer.
    let fam = alice.create_vault("Family").unwrap();
    alice.put_item(&fam, plaintext_core::new_item_id(), item("Netflix", "n3tfl1x-pass")).unwrap();
    alice.share_vault(&fam, "bob", Role::Writer, None).unwrap();
    bob.sync().unwrap();
    assert_eq!(bob.vaults[&fam].meta.name, "Family");
    let (_, nid, mut netflix) = bob.one("netflix", None).unwrap();
    netflix.notes = "shared login, don't change".into();
    bob.put_item(&fam, nid, netflix).unwrap();
    alice.sync().unwrap();
    assert_eq!(alice.vaults[&fam].get(&nid).unwrap().notes, "shared login, don't change");
    assert!(bob.one("bank of nowhere", None).is_err(), "bob can't see alice's personal vault");

    // Removing bob replaces the key; he loses the vault and can't fetch it.
    alice.revoke(&fam, "bob").unwrap();
    alice.put_item(&fam, plaintext_core::new_item_id(), item("New after bob", "after-revoke-secret")).unwrap();
    bob.sync().unwrap();
    assert!(!bob.vaults.contains_key(&fam));
    assert_eq!(status(bob.call::<VaultResponse>("GET", &format!("/v1/vaults/{fam}?since=0"), NONE)), 404);

    // An agent with read-only, expiring access to one vault.
    let ci = alice.create_vault("CI").unwrap();
    alice.put_item(&ci, plaintext_core::new_item_id(), item("Deploy token", "ghp_deploy_token_123")).unwrap();
    let key = alice.create_agent("ci-bot").unwrap();
    alice.share_vault(&ci, "ci-bot", Role::Reader, Some(now() + 3600)).unwrap();
    let key = AgentKey::parse(&key.encode()).unwrap();
    let mut agent = Session::login(Http::new(&url), &derive_agent(&key), "ci").unwrap();
    agent.sync().unwrap();
    assert_eq!(agent.vaults.len(), 1);
    assert_eq!(agent.one("deploy token", None).unwrap().2.password, "ghp_deploy_token_123");
    assert!(agent.find("netflix", None).is_empty());
    // Read-only: the client refuses, and so does the server if the client misbehaves.
    agent.vaults.get_mut(&ci).unwrap().put(plaintext_core::new_item_id(), item("x", "y"));
    agent.sync().unwrap(); // a reader's sync never pushes
    let agent_me = agent.me();
    let av = agent.vaults.get_mut(&ci).unwrap();
    assert_eq!(av.push(&agent_me, now()).err(), Some(plaintext_core::Error::ReadOnly));
    av.roster.as_mut().unwrap().members.iter_mut().for_each(|m| m.role = Role::Writer);
    let put = av.push(&agent_me, now()).unwrap();
    assert_eq!(status(agent.call::<()>("PUT", &format!("/v1/vaults/{ci}"), Some(&put))), 403);
    assert!(alice.audit(&ci).unwrap().iter().any(|e| e.username == "ci-bot" && e.action == "read"));
    assert_eq!(status(agent.create_vault("mine")), 403);
    assert_eq!(status(agent.invite()), 403);

    // The agent asks its owner for something; the owner sees it.
    agent.send("alice", &Content::Request("need the prod DB password for the migration".into()), None).unwrap();
    let inbox = alice.inbox().unwrap();
    let (from, msg) = &inbox[0];
    assert_eq!(from, "ci-bot");
    let (m, c) = msg.as_ref().unwrap();
    assert_eq!(*c, Content::Request("need the prod DB password for the migration".into()));
    alice.delete_message(&m.id).unwrap();

    // Alice shares one item with bob's inbox, and makes a link for anyone.
    alice.send("bob", &Content::Item(Box::new(item("Wifi", "hunter2hunter2"))), Some(now() + 60)).unwrap();
    let got = bob.inbox().unwrap();
    assert!(matches!(&got[0].1, Ok((_, Content::Item(i))) if i.password == "hunter2hunter2"));
    let link = alice.create_link(&url, &item("Door code", "4711-door"), now() + 600, Some(1)).unwrap();
    let rest = link.split('#').nth(1).unwrap();
    let parts: Vec<&str> = rest.rsplitn(3, '/').collect();
    let (frag, lid) = (parts[0], parts[1].parse::<Hex>().unwrap());
    assert_eq!(open_link(&Http::new(&url), &lid, frag).unwrap().password, "4711-door");
    assert_eq!(status(open_link(&Http::new(&url), &lid, frag)), 404, "one view only");

    // Files are sealed client-side with their own key.
    let f = alice.upload_file(&personal, "passport.pdf", b"%PDF passport scan").unwrap();
    assert_eq!(alice.download_file(&personal, &f).unwrap(), b"%PDF passport scan");

    // Password change: other sessions end, the old password stops working.
    alice.change_password(&derive("alice pw", &ask), &ask, "new alice pw").unwrap();
    assert_eq!(status(alice2.sessions()), 401);
    assert!(Session::login(Http::new(&url), &derive("alice pw", &ask), "x").is_err());
    let mut alice3 = login(&url, "new alice pw", &ask);
    alice3.sync().unwrap();
    assert!(alice3.one("bank of nowhere", None).is_ok());
    assert_eq!(alice3.sessions().unwrap().len(), 2);

    // Disabling an agent cuts it off.
    alice.disable_user("ci-bot").unwrap();
    assert_eq!(status(agent.sync()), 401);
    let _ = bsk;

    // The database holds nothing readable.
    let mut raw = std::fs::read(&path).unwrap();
    raw.extend(std::fs::read(path.with_extension("db-wal")).unwrap_or_default());
    assert!(raw.windows(5).any(|w| w == b"alice"), "positive control: usernames are stored");
    for needle in [
        "SuperSecret", "Bank of Nowhere", "Netflix", "n3tfl1x", "shared login", "Family", "Deploy token", "ghp_deploy",
        "after-revoke", "prod DB password", "hunter2", "Wifi", "4711-door", "passport", "alice pw",
    ] {
        assert!(!raw.windows(needle.len()).any(|w| w == needle.as_bytes()), "found {needle:?} in the database");
    }
    let _ = std::fs::remove_file(&path);
}

/// A server that lies: it can serve an old keyring, hide a vault, or replay an
/// old (genuine) vault response.
struct Evil {
    inner: Http,
    old_keyring: std::cell::RefCell<Option<B64>>,
    hide: std::cell::Cell<Option<Hex>>,
    replay: std::cell::RefCell<Option<(String, Vec<u8>)>>,
}

impl Transport for Evil {
    fn send(&self, method: &str, path: &str, token: Option<&str>, body: Option<Vec<u8>>) -> Result<(u16, Vec<u8>)> {
        if let Some((prefix, bytes)) = &*self.replay.borrow()
            && method == "GET"
            && path.starts_with(prefix.as_str())
        {
            return Ok((200, bytes.clone()));
        }
        let (status, bytes) = self.inner.send(method, path, token, body)?;
        if method == "GET" && path == "/v1/account" && status == 200 {
            let mut acct: AccountResponse = serde_json::from_slice(&bytes).unwrap();
            if let Some(k) = &*self.old_keyring.borrow() {
                acct.keyring = k.clone();
            }
            if let Some(h) = self.hide.get() {
                acct.vaults.retain(|v| *v != h);
            }
            return Ok((status, serde_json::to_vec(&acct).unwrap()));
        }
        Ok((status, bytes))
    }
}

fn evil(url: &str) -> Evil {
    Evil { inner: Http::new(url), old_keyring: Default::default(), hide: Default::default(), replay: Default::default() }
}

#[test]
fn lying_server_and_hostile_users() {
    let (url, path) = server();
    let (ask, mut alice) = Session::signup(Http::new(&url), "alice", "alice pw", Some("first-run-code"), "laptop").unwrap();
    let signup_keyring = alice.call::<AccountResponse>("GET", "/v1/account", NONE).unwrap().keyring;
    let code = alice.invite().unwrap();
    let (_, mut bob) = Session::signup(Http::new(&url), "bob", "bob pw", Some(&code), "phone").unwrap();
    alice.sync().unwrap();
    assert!(alice.keyring.contacts["bob"].verified);
    let local = alice.keyring_snapshot();

    // 1. A rolled-back keyring can't erase pins this device saved.
    let mut a2 = Session::login(evil(&url), &derive("alice pw", &ask), "laptop").unwrap();
    *a2.t.old_keyring.borrow_mut() = Some(signup_keyring.clone());
    a2 = Session::login(a2.t, &derive("alice pw", &ask), "laptop").unwrap();
    assert!(!a2.keyring.contacts.contains_key("bob"), "the server served the old keyring");
    a2.merge_local_keyring(&local).unwrap();
    assert!(a2.keyring.contacts["bob"].verified, "the device's own copy restores the pin");

    // 2. Nobody can collect your new items by sharing you a vault called "Personal".
    bob.sync().unwrap();
    let trap = bob.create_vault("Personal").unwrap();
    bob.share_vault(&trap, "alice", Role::Writer, None).unwrap();
    alice.sync().unwrap();
    let mine = alice.default_vault().unwrap();
    assert_ne!(mine, trap);
    assert_eq!(alice.vaults[&mine].creator, "alice");
    assert!(alice.own_vault("personal").is_some_and(|v| v != trap));

    // 3. Hiding a vault and bringing it back with an older copy is caught.
    let mut a3 = Session::login(evil(&url), &derive("alice pw", &ask), "laptop").unwrap();
    a3.sync().unwrap();
    let old: Vec<u8> = a3.t.inner.send("GET", &format!("/v1/vaults/{mine}?since=0"), Some(&a3.token), None).unwrap().1;
    a3.put_item(&mine, plaintext_core::new_item_id(), item("Later", "added-later")).unwrap();
    a3.t.hide.set(Some(mine));
    a3.sync().unwrap();
    assert!(!a3.vaults.contains_key(&mine) && a3.hidden.contains_key(&mine));
    a3.t.hide.set(None);
    *a3.t.replay.borrow_mut() = Some((format!("/v1/vaults/{mine}?"), old));
    assert!(matches!(a3.sync(), Err(Error::Core(plaintext_core::Error::Rollback))));
    let _ = std::fs::remove_file(&path);
}

/// What an app keeps on the device: snapshots that survive a restart (with the
/// rollback guard), an offline open that queues edits, and imports.
#[test]
fn device_state_offline_and_import() {
    let (url, path) = server();
    let dir = std::env::temp_dir().join(format!("plaintext-local-{}", hex::encode(plaintext_core::crypto::random::<8>())));
    let (sk, mut alice) = Session::signup(Http::new(&url), "alice", "alice pw", Some("first-run-code"), "phone").unwrap();
    alice.sync().unwrap();
    let mine = alice.default_vault().unwrap();
    assert_eq!(alice.import(import::onepux(&import::tests::onepux_fixture()).unwrap(), None).unwrap(), 8);
    let shared = alice.own_vault("Shared").expect("the 1PUX vault named Shared was made");
    let (vid, logo_id, logo) = alice.one("KeePassXC Logo", None).unwrap();
    assert_eq!(vid, mine);
    assert_eq!(alice.download_file(&vid, &logo.files[0]).unwrap(), b"\x89PNG logo");
    let old: Vec<u8> = alice.t.send("GET", &format!("/v1/vaults/{mine}?since=0"), Some(&alice.token), None).unwrap().1;
    alice.put_item(&mine, plaintext_core::new_item_id(), item("Later", "added-later")).unwrap();
    alice.save_local(&dir).unwrap();

    // Restart: the snapshots carry the rollback guard, so a replayed old vault is caught.
    let mut again = Session::login(evil(&url), &derive("alice pw", &sk), "phone").unwrap();
    again.load_local(&dir).unwrap();
    assert!(again.vaults[&mine].counter > 0 && again.vaults.contains_key(&shared));
    *again.t.replay.borrow_mut() = Some((format!("/v1/vaults/{mine}?"), old));
    assert!(matches!(again.sync(), Err(Error::Core(plaintext_core::Error::Rollback))));

    // Offline: open from the device's copies with a dead server, edit, sync later.
    let token = alice.token.clone();
    let (aid, akey) = (alice.account.id, alice.account.account_key.clone());
    let account = || plaintext_core::Account { id: aid, account_key: akey.clone() };
    let mut off = Session::offline(Http::new("http://127.0.0.1:9"), token.clone(), account(), &dir).unwrap();
    assert_eq!(off.one("later", None).unwrap().2.password, "added-later");
    assert!(matches!(off.put_item(&mine, logo_id, item("Edited offline", "offline-pw")), Err(Error::Network(_))));
    off.save_local(&dir).unwrap();
    let mut back = Session::offline(Http::new(&url), token, account(), &dir).unwrap();
    back.sync().unwrap();
    alice.sync().unwrap();
    assert_eq!(alice.vaults[&mine].get(&logo_id).unwrap().title, "Edited offline", "the queued edit reached the server");
    assert!(back.admin && back.keyring.default_vault == Some(mine));
    assert!(Session::offline(Http::new(&url), alice.token.clone(), account(), Path::new("/nonexistent")).is_err());
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&path);
}
