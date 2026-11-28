//! End to end over real HTTP: a family, a shared vault, an agent, inbox, links,
//! files, password change, and a database that never holds anything readable.

use super::*;
use plaintext_core::crypto::{AgentKey, derive_agent};
use plaintext_core::item::Item;

fn server() -> (String, std::path::PathBuf) {
    server_with(plaintext_server::Config { setup_code: Some("first-run-code".into()), ..Default::default() })
}

fn server_with(cfg: plaintext_server::Config) -> (String, std::path::PathBuf) {
    let path = std::env::temp_dir().join(format!("plaintext-e2e-{}.db", hex::encode(plaintext_core::crypto::random::<8>())));
    (server_at(&path, cfg), path)
}

/// A server on an existing database (a restart with other settings).
fn server_at(path: &std::path::Path, cfg: plaintext_server::Config) -> String {
    let db = plaintext_server::open_db(path.to_str().unwrap()).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            tx.send(l.local_addr().unwrap()).unwrap();
            plaintext_server::serve(l, db, cfg).await.unwrap();
        });
    });
    format!("http://{}", rx.recv().unwrap())
}

fn login(url: &str, pw: &str, sk: &SecretKey) -> Session<Http> {
    Session::login(Http::new(url), &derive(pw, sk), "test").unwrap()
}

/// Sign up and sign in, both expected to work.
fn join<T: Transport>(t: T, username: &str, pw: &str, invite: Option<&str>, device: &str) -> (SecretKey, Session<T>) {
    let (sk, s) = Session::signup(t, username, pw, invite, device).unwrap();
    let mut s = s.unwrap();
    if let Some(code) = invite {
        s.trust_inviter(code).unwrap();
    }
    (sk, s)
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
    let (ask, mut alice) = join(Http::new(&url), "alice", "alice pw", Some("first-run-code"), "laptop");
    assert!(alice.admin);
    assert_eq!(status(Session::signup(Http::new(&url), "bob", "bob pw", None, "phone")), 403);
    let code = alice.invite().unwrap();
    let (bsk, mut bob) = join(Http::new(&url), "bob", "bob pw", Some(&code), "phone");
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
    agent.sync().unwrap(); // a reader's sync never pushes, and says why
    assert!(agent.problems.iter().any(|p| p.contains("only read")), "{:?}", agent.problems);
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
    let link = alice.create_link(LINK_PAGE, &url, &item("Door code", "4711-door"), now() + 600, Some(1)).unwrap();
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

/// A server that lies: it can serve an old keyring, hide a vault, replay an
/// old (genuine) vault response, or report another time in file listings.
struct Evil {
    inner: Http,
    old_keyring: std::cell::RefCell<Option<B64>>,
    hide: std::cell::Cell<Option<Hex>>,
    replay: std::cell::RefCell<Option<(String, Vec<u8>)>>,
    files_now: std::cell::Cell<Option<u64>>,
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
        if let Some(now) = self.files_now.get()
            && method == "GET"
            && path.ends_with("/files")
            && status == 200
        {
            let mut list: FileList = serde_json::from_slice(&bytes).unwrap();
            list.now = now;
            return Ok((status, serde_json::to_vec(&list).unwrap()));
        }
        Ok((status, bytes))
    }

    fn host(&self) -> String {
        self.inner.host()
    }
}

fn evil(url: &str) -> Evil {
    Evil { inner: Http::new(url), old_keyring: Default::default(), hide: Default::default(), replay: Default::default(), files_now: Default::default() }
}

#[test]
fn lying_server_and_hostile_users() {
    let (url, path) = server();
    let (ask, mut alice) = join(Http::new(&url), "alice", "alice pw", Some("first-run-code"), "laptop");
    let signup_keyring = alice.call::<AccountResponse>("GET", "/v1/account", NONE).unwrap().keyring;
    let code = alice.invite().unwrap();
    let (_, mut bob) = join(Http::new(&url), "bob", "bob pw", Some(&code), "phone");
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
    // It's still named, as a vault you pay for, but without a hint to leave (delete) it.
    assert!(a3.problems.iter().any(|p| p.contains(&format!("vault Personal ({mine}) counts against your storage"))), "{:?}", a3.problems);
    assert!(!a3.problems.iter().any(|p| p.contains("vault leave")), "{:?}", a3.problems);
    assert!(!a3.problems.iter().any(|p| p.leave == Some(mine)), "{:?}", a3.problems);
    // ...and it stays hidden (not editable) when this device opens offline.
    let dir = std::env::temp_dir().join(format!("plaintext-hidden-{}", hex::encode(plaintext_core::crypto::random::<8>())));
    a3.save_local(&dir).unwrap();
    let acct = plaintext_core::Account { id: a3.account.id, account_key: a3.account.account_key.clone() };
    let off = Session::offline(Http::new("http://127.0.0.1:9"), a3.token.clone(), acct, &dir).unwrap();
    assert!(!off.vaults.contains_key(&mine) && off.hidden.contains_key(&mine));
    let _ = std::fs::remove_dir_all(&dir);
    a3.t.hide.set(None);
    *a3.t.replay.borrow_mut() = Some((format!("/v1/vaults/{mine}?"), old.clone()));
    // Caught and reported; the vault keeps its last verified state.
    a3.sync().unwrap();
    assert!(a3.problems.iter().any(|p| p.contains("older or different copy")), "{:?}", a3.problems);
    // Without a hint to leave (delete) the vault the server is attacking.
    assert!(!a3.problems.iter().any(|p| p.contains("vault leave") || p.leave.is_some()), "{:?}", a3.problems);
    assert!(a3.vaults[&mine].items().any(|(_, i)| i.password == "added-later"));

    // The same for a vault of your own besides the default one.
    *a3.t.replay.borrow_mut() = None;
    let work = a3.create_vault("Work").unwrap();
    a3.sync().unwrap();
    let old_work: Vec<u8> = a3.t.inner.send("GET", &format!("/v1/vaults/{work}?since=0"), Some(&a3.token), None).unwrap().1;
    a3.put_item(&work, plaintext_core::new_item_id(), item("Later", "added-later")).unwrap();
    a3.t.hide.set(Some(work));
    a3.sync().unwrap();
    assert!(a3.problems.iter().any(|p| p.contains(&format!("vault Work ({work}) counts against your storage"))), "{:?}", a3.problems);
    assert!(!a3.problems.iter().any(|p| p.contains("vault leave")), "{:?}", a3.problems);
    a3.t.hide.set(None);
    *a3.t.replay.borrow_mut() = Some((format!("/v1/vaults/{work}?"), old_work.clone()));
    a3.sync().unwrap();
    assert!(a3.problems.iter().any(|p| p.contains("vault Work wasn't updated") && p.contains("older or different copy")), "{:?}", a3.problems);
    assert!(!a3.problems.iter().any(|p| p.contains("vault leave")), "{:?}", a3.problems);
    // Dropping a hidden vault's unsent change, as sync suggests, keeps it yours:
    // still no hint while hidden, nor when an old copy of it is served next.
    *a3.t.replay.borrow_mut() = None;
    a3.sync().unwrap();
    a3.vaults.get_mut(&work).unwrap().put(plaintext_core::new_item_id(), item("Unsent", "u"));
    a3.t.hide.set(Some(work));
    a3.sync().unwrap();
    assert!(a3.unsendable.contains(&work), "{:?}", a3.problems);
    // The storage warning goes ahead of the one about its changes, and only the
    // latter offers to drop them; dropping them leaves the former.
    let storage = format!("vault Work ({work}) counts against your storage");
    let at = |s: &Session<_>, f: &dyn Fn(&Problem) -> bool| s.problems.iter().position(f);
    let (st, un) = (at(&a3, &|p| p.starts_with(&storage)), at(&a3, &|p| p.unsent == Some(work)));
    assert!(matches!((st, un), (Some(st), Some(un)) if st < un), "{:?}", a3.problems);
    assert_eq!(a3.problems.iter().filter(|p| p.unsent == Some(work)).count(), 1, "{:?}", a3.problems);
    assert_eq!(a3.discard_changes(&work).unwrap(), 1);
    assert!(a3.problems.iter().any(|p| p.starts_with(&storage)) && !a3.problems.iter().any(|p| p.unsent.is_some()), "{:?}", a3.problems);
    // That it's yours survives on disk.
    let dir = std::env::temp_dir().join(format!("plaintext-reset-{}", hex::encode(plaintext_core::crypto::random::<8>())));
    a3.save_local(&dir).unwrap();
    let acct = plaintext_core::Account { id: a3.account.id, account_key: a3.account.account_key.clone() };
    let off = Session::offline(Http::new("http://127.0.0.1:9"), a3.token.clone(), acct, &dir).unwrap();
    assert!(off.hidden.contains_key(&work) && off.is_own(&work));
    let _ = std::fs::remove_dir_all(&dir);
    a3.sync().unwrap();
    assert!(a3.problems.iter().any(|p| p.contains(&format!("vault {work} counts against your storage"))), "{:?}", a3.problems);
    assert!(!a3.problems.iter().any(|p| p.contains("vault leave")), "{:?}", a3.problems);
    a3.t.hide.set(None);
    *a3.t.replay.borrow_mut() = Some((format!("/v1/vaults/{work}?"), old_work));
    a3.sync().unwrap();
    assert!(a3.problems.iter().any(|p| p.contains(&format!("vault {work} wasn't updated")) && p.contains("older or different copy")), "{:?}", a3.problems);
    assert!(!a3.problems.iter().any(|p| p.contains("vault leave")), "{:?}", a3.problems);
    // Served honestly again, it's downloaded in full.
    *a3.t.replay.borrow_mut() = None;
    a3.sync().unwrap();
    assert_eq!(a3.vaults[&work].meta.name, "Work");
    assert!(a3.vaults[&work].items().any(|(_, i)| i.password == "added-later") && !a3.vaults[&work].items().any(|(_, i)| i.password == "u"));

    // A fresh device has no copy to compare with, but the keyring's roster checkpoint
    // catches the replay, and the default vault isn't hinted at either, nor when hidden.
    *a3.t.replay.borrow_mut() = None;
    a3.share_vault(&mine, "bob", Role::Reader, None).unwrap();
    a3.sync().unwrap();
    let mut a4 = Session::login(evil(&url), &derive("alice pw", &ask), "tablet").unwrap();
    *a4.t.replay.borrow_mut() = Some((format!("/v1/vaults/{mine}?"), old.clone()));
    a4.sync().unwrap();
    assert!(a4.problems.iter().any(|p| p.contains(&format!("vault {mine} wasn't updated")) && p.contains("older or different copy")), "{:?}", a4.problems);
    assert!(!a4.problems.iter().any(|p| p.contains("vault leave") || p.leave.is_some()), "{:?}", a4.problems);
    *a4.t.replay.borrow_mut() = None;
    a4.t.hide.set(Some(mine));
    a4.sync().unwrap();
    assert!(a4.problems.iter().any(|p| p.contains(&format!("vault {mine} counts against your storage"))), "{:?}", a4.problems);
    assert!(!a4.problems.iter().any(|p| p.contains("vault leave") || p.leave.is_some()), "{:?}", a4.problems);
    // Nor another vault of yours a fresh device has never opened, when the server
    // hides it, even before the device that made it syncs again.
    let home = a3.create_vault("Home").unwrap();
    let mut a5 = Session::login(evil(&url), &derive("alice pw", &ask), "phone").unwrap();
    a5.t.hide.set(Some(home));
    a5.sync().unwrap();
    assert!(a5.problems.iter().any(|p| p.contains(&format!("vault {home} counts against your storage"))), "{:?}", a5.problems);
    assert!(!a5.problems.iter().any(|p| p.leave.is_some()), "{:?}", a5.problems);

    // Once a co-owner really demotes you in your own vault (a signed demotion), the hint is back.
    a3.t.hide.set(None);
    a3.share_vault(&mine, "bob", Role::Owner, None).unwrap();
    bob.sync().unwrap();
    bob.share_vault(&mine, "alice", Role::Writer, Some(now() + 3600)).unwrap();
    a3.sync().unwrap();
    a3.vaults.get_mut(&mine).unwrap().put(plaintext_core::new_item_id(), item("Unsent", "u"));
    a3.t.hide.set(Some(mine));
    a3.sync().unwrap();
    assert!(a3.problems.iter().any(|p| p.contains(&format!("plaintext vault leave {mine}")) && p.leave == Some(mine)), "{:?}", a3.problems);
    // Dropping its unsent change doesn't make it yours again, though it's the signup vault.
    assert_eq!(a3.discard_changes(&mine).unwrap(), 1);
    a3.sync().unwrap();
    assert!(a3.problems.iter().any(|p| p.contains(&format!("plaintext vault leave {mine}"))), "{:?}", a3.problems);
    // And when an old copy of it fails to sync.
    a3.t.hide.set(None);
    *a3.t.replay.borrow_mut() = Some((format!("/v1/vaults/{mine}?"), old));
    a3.sync().unwrap();
    assert!(a3.problems.iter().any(|p| p.contains("older or different copy") && p.contains(&format!("plaintext vault leave {mine}"))), "{:?}", a3.problems);
    let _ = std::fs::remove_file(&path);
}

/// A hosted server: anyone signs up, nobody can list the customers, people are
/// found by exact username, and a login signed for another host is refused.
#[test]
fn hosted_server_and_several_servers() {
    let (url, _) = server_with(plaintext_server::Config { open_signup: true, ..Default::default() });
    let info = server_info(&Http::new(&url)).unwrap();
    assert!(info.open && !info.setup && !info.version.is_empty());
    let (_, admin) = join(Http::new(&url), "admin", "admin pw", None, "t");
    assert!(admin.admin);
    let (_, mut carol) = join(Http::new(&url), "carol", "carol pw", None, "t");
    let (_, dave) = join(Http::new(&url), "dave", "dave pw", None, "t");
    assert!(!carol.admin);
    assert_eq!(admin.users().unwrap().len(), 3);
    assert!(carol.users().unwrap().is_empty(), "no customer list on an open server");
    carol.create_agent("carol-bot").unwrap();
    assert_eq!(carol.users().unwrap().len(), 1, "but your own agents are listed");
    carol.pin_user("dave").unwrap();
    assert!(matches!(carol.pin_user("nobody"), Err(Error::NotFound(_))));
    // Anyone may invite there; the invitee is visible to (and verified by) the inviter.
    let code = carol.invite().unwrap();
    let (_, erin) = join(Http::new(&url), "erin", "erin pw", Some(&code), "t");
    assert!(erin.keyring.contacts["carol"].verified);
    carol.sync().unwrap();
    assert_eq!(carol.users().unwrap().len(), 2);
    assert!(carol.keyring.contacts["erin"].verified);
    assert_eq!(status(Session::signup(Http::new(&url), "frank", "pw", Some(&code), "t")), 403, "a used invite is still refused");
    drop(dave);

    // A login relayed from a look-alike server doesn't open a session here.
    let (sk, _) = join(Http::new(&url), "gina", "gina pw", None, "t");
    let d = derive("gina pw", &sk);
    let relayed = plaintext_core::login_request(&d, now_ms(), "t", "vault.examp1e.com");
    assert_eq!(status(call::<_, LoginResponse>(&Http::new(&url), "POST", "/v1/login", None, Some(&relayed))), 401);
    login(&url, "gina pw", &sk);

    // A server that names its public address (behind a proxy) refuses logins
    // signed for any other, such as the address of the machine itself.
    let (url2, _) = server_with(plaintext_server::Config { hosts: vec!["vault.example.com".into()], ..Default::default() });
    let proxied = || Named(Http::new(&url2), "vault.example.com");
    let (sk2, _) = join(proxied(), "gina", "other pw", None, "t");
    assert!(Session::login(proxied(), &derive("other pw", &sk2), "t").is_ok());
    assert_eq!(status(Session::login(Http::new(&url2), &derive("other pw", &sk2), "t")), 401);
}

/// A proxy that rewrites `Host` makes the login after signup fail, but the
/// account exists by then, so its Secret Key still comes back and works.
#[test]
fn secret_key_survives_a_failed_login_after_signup() {
    let (url, _) = server_with(plaintext_server::Config { hosts: vec!["vault.example.com".into()], ..Default::default() });
    let (sk, s) = Session::signup(Http::new(&url), "hana", "hana pw", None, "t").unwrap();
    assert_eq!(status(s), 401, "the login signed for the wrong host is refused");
    let s = Session::login(Named(Http::new(&url), "vault.example.com"), &derive("hana pw", &sk), "t").unwrap();
    assert!(s.admin, "the account was created, as the server's first");
}

#[test]
fn plain_http_only_on_local_networks() {
    for ok in ["https://vault.example.com", "http://localhost:8080", "http://127.0.0.1:1", "http://192.168.1.5", "http://10.0.0.2:8080",
        "http://100.101.102.103", "http://nas.local", "http://vault.tail1234.ts.net", "http://plaintext:8080", "http://[::1]:8080", "http://[fd00::1]"] {
        assert!(!insecure_url(ok), "{ok}");
    }
    for bad in ["http://vault.example.com", "http://8.8.8.8", "http://100.128.0.1", "ftp://x", "vault.example.com", "http://[2001:db8::1]"] {
        assert!(insecure_url(bad), "{bad}");
    }
}

/// What a client behind a reverse proxy sees: its own name for the server.
struct Named(Http, &'static str);

impl Transport for Named {
    fn send(&self, method: &str, path: &str, token: Option<&str>, body: Option<Vec<u8>>) -> Result<(u16, Vec<u8>)> {
        self.0.send(method, path, token, body)
    }

    fn host(&self) -> String {
        self.1.into()
    }
}

fn count(path: &std::path::Path, sql: &str) -> i64 {
    plaintext_server::open_db(path.to_str().unwrap()).unwrap().query_row(sql, [], |r| r.get(0)).unwrap()
}

/// Deleting an account needs the password, takes its agents, inbox, links and
/// unshared vaults with it, and leaves shared vaults to the others, whose owners
/// replace the key.
#[test]
fn account_deletion() {
    let (url, path) = server();
    let (ask, mut alice) = join(Http::new(&url), "alice", "alice pw", Some("first-run-code"), "t");
    let code = alice.invite().unwrap();
    let (bsk, mut bob) = join(Http::new(&url), "bob", "bob pw", Some(&code), "t");
    let code = alice.invite().unwrap();
    let (_, mut carol) = join(Http::new(&url), "carol", "carol pw", Some(&code), "t");
    let code = alice.invite().unwrap();
    let (_, mut dave) = join(Http::new(&url), "dave", "dave pw", Some(&code), "t");

    // Alice's family vault has bob as a writer and bob's agent as a reader.
    let fam = alice.create_vault("Family").unwrap();
    alice.put_item(&fam, plaintext_core::new_item_id(), item("Netflix", "n3tfl1x")).unwrap();
    alice.share_vault(&fam, "bob", Role::Writer, None).unwrap();
    let bot_key = bob.create_agent("bob-bot").unwrap();
    alice.share_vault(&fam, "bob-bot", Role::Reader, None).unwrap();
    // Bob's vault with carol as a second owner, and one only bob and his agent use.
    let kept = bob.create_vault("Shared").unwrap();
    bob.put_item(&kept, plaintext_core::new_item_id(), item("Router", "r0uter")).unwrap();
    bob.share_vault(&kept, "carol", Role::Owner, None).unwrap();
    let solo = bob.create_vault("Solo").unwrap();
    bob.share_vault(&solo, "bob-bot", Role::Reader, None).unwrap();
    let blocked = bob.create_vault("Blocked").unwrap();
    bob.share_vault(&blocked, "carol", Role::Writer, None).unwrap();
    carol.sync().unwrap();
    carol.share_vault(&kept, "alice", Role::Reader, None).unwrap();
    // Dave's club, where bob is only a reader, keeps no owner once dave is disabled.
    let club = dave.create_vault("Club").unwrap();
    dave.share_vault(&club, "bob", Role::Reader, None).unwrap();
    dave.share_vault(&club, "carol", Role::Writer, None).unwrap();
    alice.disable_user("dave").unwrap();
    alice.send("bob", &Content::Request("hi".into()), None).unwrap();
    bob.create_link(LINK_PAGE, &url, &item("Door", "4711"), now() + 600, None).unwrap();
    bob.sync().unwrap();

    // A stolen session token isn't enough, and neither is a wrong password.
    let wrong = plaintext_core::delete_account(&derive("guess", &bsk), now_ms(), &plaintext_core::crypto::server_host(&url));
    assert_eq!(status(bob.call::<()>("DELETE", "/v1/account", Some(&wrong))), 401);
    let stale = plaintext_core::delete_account(&derive("bob pw", &bsk), now_ms() - 300_000, &plaintext_core::crypto::server_host(&url));
    assert_eq!(status(bob.call::<()>("DELETE", "/v1/account", Some(&stale))), 401);
    // Bob is the only owner of a vault carol uses: the client names it, the server refuses too.
    let refused = bob.delete_account(&derive("bob pw", &bsk)).unwrap_err().to_string();
    assert!(refused.contains("Blocked") && !refused.contains("Solo") && !refused.contains("Shared"), "{refused}");
    let signed = plaintext_core::delete_account(&derive("bob pw", &bsk), now_ms(), &plaintext_core::crypto::server_host(&url));
    assert_eq!(status(bob.call::<()>("DELETE", "/v1/account", Some(&signed))), 409);

    bob.revoke(&blocked, "carol").unwrap();
    bob.delete_account(&derive("bob pw", &bsk)).unwrap();
    assert_eq!(status(bob.sessions()), 401);
    assert_eq!(status(Session::login(Http::new(&url), &derive("bob pw", &bsk), "t")), 401);
    let bot = AgentKey::parse(&bot_key.encode()).unwrap();
    assert_eq!(status(Session::login(Http::new(&url), &derive_agent(&bot), "t")), 401, "his agent went with him");
    assert!(matches!(alice.pin_user("bob"), Err(Error::NotFound(_))));
    for (table, n) in [("accounts", 3), ("messages", 0), ("links", 0), ("vaults", 6)] {
        assert_eq!(count(&path, &format!("SELECT COUNT(*) FROM {table}")), n, "{table}");
    }
    assert_eq!(count(&path, "SELECT COUNT(*) FROM vaults WHERE creator = 'carol'"), 2, "carol now carries bob's shared vault");
    assert_eq!(count(&path, "SELECT COUNT(*) FROM vault_keys WHERE username IN ('bob', 'bob-bot')"), 0);

    // Alice's device removes bob and his agent in one new roster with a new key.
    let epoch = alice.vaults[&fam].roster.as_ref().unwrap().epoch;
    alice.sync().unwrap();
    let r = alice.vaults[&fam].roster.as_ref().unwrap();
    assert_eq!(r.epoch, epoch + 1);
    assert_eq!(r.members.iter().map(|m| m.username.as_str()).collect::<Vec<_>>(), ["alice"]);
    // Carol keeps bob's shared vault. Removing someone takes bob out in the same new key.
    carol.revoke(&kept, "alice").unwrap();
    assert_eq!(carol.vaults[&kept].roster.as_ref().unwrap().members.len(), 1);
    carol.sync().unwrap();
    assert_eq!(carol.one("router", None).unwrap().2.password, "r0uter");
    assert_eq!(carol.vaults[&kept].roster.as_ref().unwrap().members.len(), 1);
    carol.share_vault(&kept, "alice", Role::Reader, None).unwrap();
    assert!(!carol.vaults.contains_key(&solo) && !carol.vaults.contains_key(&blocked));
    assert!(carol.vaults.contains_key(&club), "a vault bob only read stays with the others");
    // A creator who is removed stops paying for the vault; the owner who removed them does.
    let vault_creator = |v: &Hex| count(&path, &format!("SELECT COUNT(*) FROM vaults WHERE lower(hex(id)) = '{v}' AND creator = 'alice'"));
    let handoff = carol.create_vault("Handoff").unwrap();
    carol.share_vault(&handoff, "alice", Role::Owner, None).unwrap();
    assert_eq!(vault_creator(&handoff), 0);
    alice.sync().unwrap();
    alice.revoke(&handoff, "carol").unwrap();
    assert_eq!(vault_creator(&handoff), 1);

    // The name is free again, but nobody who pinned the old bob accepts the new one.
    let code = alice.invite().unwrap();
    join(Http::new(&url), "bob", "new bob pw", Some(&code), "t");
    assert!(matches!(alice.pin_user("bob"), Err(Error::Core(plaintext_core::Error::KeyChanged(_)))));

    // An agent may delete itself; its owner's device removes it from the vault.
    let key = alice.create_agent("ci").unwrap();
    alice.share_vault(&fam, "ci", Role::Reader, None).unwrap();
    let mut ci = Session::login(Http::new(&url), &derive_agent(&key), "ci").unwrap();
    ci.delete_account(&derive_agent(&key)).unwrap();
    alice.sync().unwrap();
    assert_eq!(alice.vaults[&fam].roster.as_ref().unwrap().members.len(), 1);

    // The admin can't leave a server others use.
    let err = alice.delete_account(&derive("alice pw", &ask)).unwrap_err();
    assert!(matches!(&err, Error::Server(409, m) if m.contains("admin")), "{err}");

    let _ = std::fs::remove_file(&path);
}

/// `PLAINTEXT_QUOTA_MB` counts items, files, rosters and the latest manifest of
/// the vaults an account created. Writes that would add past it get 507; reads,
/// edits, deletes and key replacement always work.
#[test]
fn storage_quota() {
    let (url, path) = server_with(plaintext_server::Config { open_signup: true, ..Default::default() });
    let (ask, mut alice) = join(Http::new(&url), "alice", "alice pw", None, "t");
    let (bsk, _) = join(Http::new(&url), "bob", "bob pw", None, "t");
    alice.sync().unwrap();
    let personal = alice.default_vault().unwrap();
    let big = alice.upload_file(&personal, "scan.pdf", &vec![7u8; 300_000]).unwrap();
    let id = plaintext_core::new_item_id();
    alice.put_item(&personal, id, Item { files: vec![big.clone()], ..item("Bank", "b4nk") }).unwrap();
    alice.share_vault(&personal, "bob", Role::Writer, None).unwrap();
    // A roster change carrying fields the server doesn't know (say, from a newer client).
    let padded = |s: &mut Session<Http>, role: Role, pad: usize| {
        let u = s.vaults[&personal].grant(&s.me(), &s.keyring, "bob", role, None, now()).unwrap();
        let mut r: serde_json::Value = serde_json::from_slice(&u.roster.body.0).unwrap();
        r["pad"] = "A".repeat(pad).into();
        let u = RosterUpdate { roster: s.me().sign_doc("roster", &r), ..u };
        let code = status(s.call::<()>("POST", &format!("/v1/vaults/{personal}/roster"), Some(&u)));
        s.sync().unwrap();
        code
    };
    assert_eq!(padded(&mut alice, Role::Writer, 1000), 200);
    let acct: AccountResponse = alice.call("GET", "/v1/account", NONE).unwrap();
    assert_eq!(acct.quota, None, "unlimited unless set");
    assert!(acct.usage > 300_000);

    // The same database restarted with a 256 KB quota: alice is already over it.
    let url = server_at(&path, plaintext_server::Config { open_signup: true, quota: Some(256 << 10), ..Default::default() });
    let mut alice = login(&url, "alice pw", &ask);
    let mut bob = login(&url, "bob pw", &bsk);
    alice.sync().unwrap();
    bob.sync().unwrap();
    let acct: AccountResponse = alice.call("GET", "/v1/account", NONE).unwrap();
    assert_eq!(acct.quota, Some(256 << 10));
    assert_eq!(alice.download_file(&personal, &big).unwrap().len(), 300_000, "reads still work");
    assert_eq!(status(alice.upload_file(&personal, "more.pdf", b"more")), 507);
    assert_eq!(status(alice.create_vault("More")), 507, "a vault's roster and manifest count");
    // An edit that takes no more room goes through.
    alice.put_item(&personal, id, Item { files: vec![big.clone()], ..item("Bonk", "b4nk") }).unwrap();
    // A writer's items count against the vault's creator, not the writer.
    let err = bob.put_item(&personal, plaintext_core::new_item_id(), item("Bob's", "x")).unwrap_err();
    assert!(matches!(&err, Error::Server(507, m) if m.contains("out of storage")), "{err}");
    let mine = bob.default_vault().unwrap();
    bob.upload_file(&mine, "bob.pdf", b"bob's own file").unwrap();
    // The refused change waits on bob's device without holding up his other vaults.
    bob.vaults.get_mut(&mine).unwrap().put(plaintext_core::new_item_id(), item("Bob's own", "y"));
    assert_eq!(status(bob.sync()), 507);
    assert!(!bob.vaults[&mine].has_changes());
    // Staged items count too: over the quota only an owner may stage, and only as
    // much as the vault's items (a new key re-seals them).
    let stage = |s: &Session<Http>, v: &Hex, id: Hex, n: usize| {
        let upserts = vec![ItemBlob { id: plaintext_core::new_item_id(), blob: B64(vec![1; n]) }];
        status(s.call::<()>("POST", &format!("/v1/vaults/{v}/stage"), Some(&StageRequest { stage: id, upserts })))
    };
    let st = plaintext_core::new_item_id();
    assert_eq!(stage(&bob, &personal, st, 100), 507);
    assert_eq!(stage(&alice, &personal, st, 100), 200);
    assert_eq!(stage(&alice, &personal, st, 2000), 507);
    // A refused part drops the parts before it, which would otherwise keep counting.
    assert_eq!(stage(&bob, &mine, st, 100_000), 200);
    assert_eq!(stage(&bob, &mine, st, 200_000), 507);
    assert_eq!(count(&path, "SELECT COUNT(*) FROM staged WHERE username IN ('alice', 'bob')"), 0);
    // Removing the creator and adding someone in one roster change: the signer
    // pays from then on, so the signer needs the room.
    let _ = join(Http::new(&url), "carol", "carol pw", None, "t");
    bob.share_vault(&mine, "alice", Role::Owner, None).unwrap();
    alice.sync().unwrap();
    let carol = alice.pin_user("carol").unwrap();
    let take_over = |s: &mut Session<Http>| {
        let u = s.vaults[&mine].revoke(&s.me(), &["bob"], now()).unwrap();
        let mut r: Roster = serde_json::from_slice(&u.roster.body.0).unwrap();
        r.members.push(Member { username: "carol".into(), sign_pk: carol.sign_pk.clone(), enc_pk: carol.enc_pk.clone(), role: Role::Reader, expires: None });
        let u = RosterUpdate { roster: s.me().sign_doc("roster", &r), ..u };
        status(s.call::<()>("POST", &format!("/v1/vaults/{mine}/roster"), Some(&u)))
    };
    assert_eq!(take_over(&mut alice), 507);
    // Over the quota, a roster change (here an unchanged role) may keep its unknown
    // fields but not grow them.
    assert_eq!(padded(&mut alice, Role::Writer, 2000), 507);
    assert_eq!(padded(&mut alice, Role::Writer, 1000), 200);
    // Over the quota, a promotion and removing someone (a new key) still work;
    // adding someone doesn't.
    alice.share_vault(&personal, "bob", Role::Owner, None).unwrap();
    alice.revoke(&personal, "bob").unwrap();
    assert_eq!(status(alice.share_vault(&personal, "bob", Role::Reader, None)), 507);

    // Deleting an item leaves its attachment until the grace has passed, then
    // collecting it makes room.
    alice.delete_item(&personal, id).unwrap();
    // A change refused for lack of room doesn't stop that vault's collection.
    // An import refused for lack of room stays on the device.
    let r = alice.import(vec![import::Imported { name: String::new(), items: vec![(item("Waiting", "w"), vec![])] }], None).unwrap();
    assert!(matches!(r.sync_error, Some(Error::Server(507, _))), "{r:?}");
    assert!(alice.vaults[&personal].has_changes());
    assert_eq!(status(alice.sync()), 507);
    assert_eq!(alice.download_file(&personal, &big).unwrap().len(), 300_000);
    alice.collect_files(&personal, FILE_GRACE).unwrap();
    assert_eq!(status(alice.download_file(&personal, &big)), 404);
    alice.sync().unwrap();
    assert!(!alice.vaults[&personal].has_changes(), "the room went to the refused change");
    let acct: AccountResponse = alice.call("GET", "/v1/account", NONE).unwrap();
    assert!(acct.usage < 20_000, "{}", acct.usage);
    alice.upload_file(&personal, "small.pdf", &vec![1u8; 100_000]).unwrap();
    alice.share_vault(&personal, "bob", Role::Reader, None).unwrap();
    alice.sync().unwrap();
    assert_eq!(take_over(&mut alice), 200, "an owner with room");
    let acct: AccountResponse = alice.call("GET", "/v1/account", NONE).unwrap();
    assert!(acct.paid.contains(&mine), "alice pays for it now");
    // Under the quota, a change that adds nobody still may not grow past it.
    assert_eq!(padded(&mut alice, Role::Reader, 200_000), 507);
    assert_eq!(padded(&mut alice, Role::Reader, 10_000), 200);
    bob.sync().unwrap();
    assert_eq!(stage(&bob, &personal, st, 100), 403, "readers can't stage");
    // Being out of storage doesn't stop anyone deleting their account.
    bob.delete_account(&derive("bob pw", &bsk)).unwrap();
    let _ = std::fs::remove_file(&path);
}

/// Files no item refers to are listed and, after a grace, deleted by a writer's
/// sync; an item another device brings back keeps its attachment.
#[test]
fn file_garbage_collection() {
    let (url, path) = server();
    let (_, mut alice) = join(Http::new(&url), "alice", "alice pw", Some("first-run-code"), "laptop");
    let code = alice.invite().unwrap();
    let (_, mut bob) = join(Http::new(&url), "bob", "bob pw", Some(&code), "phone");
    let (_, mut carol) = join(Http::new(&url), "carol", "carol pw", Some(&alice.invite().unwrap()), "x");
    alice.sync().unwrap();
    let v = alice.create_vault("Shared").unwrap();
    alice.share_vault(&v, "bob", Role::Writer, None).unwrap();
    alice.share_vault(&v, "carol", Role::Reader, None).unwrap();
    bob.sync().unwrap();
    carol.sync().unwrap();
    // An upload whose item never got pushed, one kept only in an earlier version,
    // and one a current item lists.
    let orphan = alice.upload_file(&v, "crash.bin", b"never pushed").unwrap();
    let old = alice.upload_file(&v, "v1.pdf", b"first version").unwrap();
    let kept = alice.upload_file(&v, "deed.pdf", b"the deed").unwrap();
    let id = plaintext_core::new_item_id();
    alice.put_item(&v, id, Item { files: vec![old.clone()], ..item("House", "h") }).unwrap();
    let mut it = alice.vaults[&v].get(&id).unwrap().clone();
    it.edit(Item { files: vec![kept.clone()], ..item("House", "h") }, now_ms());
    alice.put_item(&v, id, it).unwrap();

    let listed = alice.files(&v).unwrap();
    let mut got: Vec<Hex> = listed.files.iter().map(|f| f.id).collect();
    got.sort();
    let mut want = [&orphan, &old, &kept].map(|f| f.id);
    want.sort();
    assert_eq!(got, want);
    assert!(listed.files.iter().all(|f| f.size > 16), "sealed sizes");
    assert!(listed.now.abs_diff(now()) < 60, "the server's clock");
    assert_eq!(status(carol.files(&v)), 403, "only writers list");
    let mine = alice.default_vault().unwrap();
    assert_eq!(status(bob.files(&mine)), 404, "non-members may not (nor learn the vault exists)");
    let count = |s: &Session<Http>| s.files(&v).unwrap().files.len();

    // A sync notes the orphan; short of a week, nothing goes.
    alice.sync().unwrap();
    let snap = alice.vaults[&v].snapshot(&alice.account);
    let restart = |s: &mut Session<Http>| drop(s.vaults.insert(v, Vault::restore(&s.account, v, &snap).unwrap()));
    alice.collect_files(&v, FILE_GRACE - 60).unwrap();
    assert_eq!(count(&alice), 3);
    // A device that hasn't looked for more than two weeks starts the clock over.
    restart(&mut alice);
    alice.collect_files(&v, 2 * FILE_GRACE + 1).unwrap();
    assert_eq!(count(&alice), 3);
    // Readers never collect.
    carol.sync().unwrap();
    carol.collect_files(&v, 4 * FILE_GRACE).unwrap();
    assert_eq!(count(&alice), 3);
    // The note survives a restart (the snapshot): a week on, the orphan goes, and only it.
    restart(&mut alice);
    alice.collect_files(&v, FILE_GRACE).unwrap();
    assert_eq!(status(alice.download_file(&v, &orphan)), 404);
    assert_eq!(alice.download_file(&v, &old).unwrap(), b"first version");
    assert_eq!(alice.download_file(&v, &kept).unwrap(), b"the deed");

    // Bob edits the item without pushing. Alice deletes it, but until that's
    // pushed the server still serves the item, so its files stay.
    alice.sync().unwrap();
    bob.sync().unwrap();
    let mut edit = bob.vaults[&v].get(&id).unwrap().clone();
    edit.notes = "edited offline".into();
    bob.vaults.get_mut(&v).unwrap().put(id, edit);
    alice.vaults.get_mut(&v).unwrap().delete(id);
    alice.collect_files(&v, 0).unwrap();
    alice.collect_files(&v, FILE_GRACE).unwrap();
    assert_eq!(count(&alice), 2);
    // Pushed, the deletion leaves them unreferenced, but bob's edit wins the merge
    // and brings the item back within the grace, attachment and all.
    alice.sync().unwrap();
    bob.sync().unwrap();
    alice.sync().unwrap();
    assert!(alice.vaults[&v].get(&id).is_some());
    alice.collect_files(&v, FILE_GRACE).unwrap();
    assert_eq!(bob.download_file(&v, &kept).unwrap(), b"the deed");
    assert_eq!(count(&alice), 2);

    // A conflict: bob pushes a version with a new attachment while alice has an
    // edit pending. Until alice pushes, the server serves bob's version under the
    // item's id, so its file stays even if she drops her conflict copy.
    let new = bob.upload_file(&v, "deed2.pdf", b"new deed").unwrap();
    let mut mine = alice.vaults[&v].get(&id).unwrap().clone();
    mine.notes = "alice's".into();
    alice.vaults.get_mut(&v).unwrap().put(id, mine);
    bob.put_item(&v, id, Item { files: vec![new.clone()], ..item("House", "h2") }).unwrap();
    alice.pull(&v).unwrap();
    let copy = *alice.vaults[&v].items().find(|(_, i)| i.title.ends_with("(conflict)")).unwrap().0;
    alice.vaults.get_mut(&v).unwrap().delete(copy);
    alice.collect_files(&v, 0).unwrap();
    alice.collect_files(&v, FILE_GRACE).unwrap();
    assert_eq!(alice.download_file(&v, &new).unwrap(), b"new deed");
    // Once her edit replaces it, nothing refers to that file any more.
    alice.sync().unwrap();
    alice.collect_files(&v, 0).unwrap();
    alice.collect_files(&v, FILE_GRACE).unwrap();
    assert_eq!(status(alice.download_file(&v, &new)), 404);

    // A snapshot from before collection existed restores, and with a change
    // pending on a pushed item it collects nothing: it can't tell what the
    // server's copy refers to. Here a pending edit drops both of the House's
    // files and a pending delete takes the Car's.
    let car_file = alice.upload_file(&v, "car.pdf", b"title").unwrap();
    let car = plaintext_core::new_item_id();
    alice.put_item(&v, car, Item { files: vec![car_file.clone()], ..item("Car", "c") }).unwrap();
    let vault = alice.vaults.get_mut(&v).unwrap();
    vault.put(id, item("House", "h3"));
    vault.delete(car);
    let mut j = serde_json::to_value(&*vault).unwrap();
    for k in ["base_files", "orphans", "files_checked"] {
        j.as_object_mut().unwrap().remove(k).unwrap();
    }
    *vault = serde_json::from_value(j).unwrap();
    alice.collect_files(&v, 0).unwrap();
    alice.collect_files(&v, FILE_GRACE).unwrap();
    assert_eq!(alice.download_file(&v, &car_file).unwrap(), b"title");
    assert_eq!(alice.download_file(&v, &old).unwrap(), b"first version");
    assert_eq!(alice.download_file(&v, &kept).unwrap(), b"the deed");
    let _ = std::fs::remove_file(&path);
}

/// Collection goes by the server's clock, however far this device's is ahead.
#[test]
fn file_collection_uses_the_server_clock() {
    let (url, path) = server();
    let (_, mut alice) = join(evil(&url), "alice", "alice pw", Some("first-run-code"), "laptop");
    alice.sync().unwrap();
    let v = alice.default_vault().unwrap();
    let orphan = alice.upload_file(&v, "crash.bin", b"never pushed").unwrap();
    // The server says it's 1970; the device's clock is decades ahead.
    let at = |s: &mut Session<Evil>, t| {
        s.t.files_now.set(Some(t));
        s.collect_files(&v, 0).unwrap();
    };
    at(&mut alice, 1000);
    at(&mut alice, 1000 + FILE_GRACE - 1);
    assert_eq!(alice.download_file(&v, &orphan).unwrap(), b"never pushed");
    at(&mut alice, 1000 + FILE_GRACE);
    assert_eq!(status(alice.download_file(&v, &orphan)), 404);
    let _ = std::fs::remove_file(&path);
}

/// The grace and the gap that starts it over, to the second.
#[test]
fn file_collection_bounds() {
    let (g, f) = (100, plaintext_core::new_item_id());
    let noted = || {
        let mut v = Vault::new(plaintext_core::new_item_id());
        assert!(v.collect_files(&[f], 1000, g).is_empty());
        v
    };
    let mut v = noted();
    assert!(v.collect_files(&[f], 1000 + g - 1, g).is_empty());
    assert_eq!(v.collect_files(&[f], 1000 + g, g), [f]);
    // Looking again two graces later keeps the note; a second more starts over.
    assert_eq!(noted().collect_files(&[f], 1000 + 2 * g, g), [f]);
    assert!(noted().collect_files(&[f], 1000 + 2 * g + 1, g).is_empty());
}

/// Open servers limit signups and failed logins per client address; behind a
/// trusted proxy the address is the last one in X-Forwarded-For.
#[test]
fn signup_and_login_rate_limits() {
    fn post_lines(url: &str, path: &str, xff: &[&str]) -> u16 {
        let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).build().into();
        let mut req = agent.post(format!("{url}{path}")).header("content-type", "application/json");
        for x in xff {
            req = req.header("x-forwarded-for", *x);
        }
        req.send("{}").unwrap().status().as_u16()
    }
    let post = |url: &str, path: &str, xff: Option<&str>| post_lines(url, path, xff.as_slice());
    let open = plaintext_server::Config { open_signup: true, ..Default::default() };

    // Invite-only servers have no limits.
    let (url, _) = server();
    assert!((0..12).all(|_| post(&url, "/v1/signup", None) != 429));

    let (url, _) = server_with(open.clone());
    let (sk, _) = join(Http::new(&url), "alice", "alice pw", None, "t");
    // Successful logins don't count (agents sign in on every run).
    let d = derive("alice pw", &sk);
    for _ in 0..35 {
        Session::login(Http::new(&url), &d, "t").unwrap();
    }
    assert!((0..9).all(|_| post(&url, "/v1/signup", None) != 429));
    assert_eq!(post(&url, "/v1/signup", None), 429);
    assert_eq!(post(&url, "/v1/signup", Some("10.0.0.9")), 429, "the header is ignored unless the proxy is trusted");
    assert!((0..30).all(|_| post(&url, "/v1/login", None) != 429));
    assert_eq!(post(&url, "/v1/login", None), 429);
    // Junk from the same address can't lock out someone who knows the password.
    Session::login(Http::new(&url), &d, "t").unwrap();

    let (url, _) = server_with(plaintext_server::Config { trust_proxy: true, ..open });
    assert!((0..10).all(|_| post(&url, "/v1/signup", Some("203.0.113.1, 198.51.100.7")) != 429));
    assert_eq!(post(&url, "/v1/signup", Some("203.0.113.1, 198.51.100.7")), 429);
    assert_eq!(post(&url, "/v1/signup", Some("203.0.113.99, 198.51.100.7")), 429, "the client can't pick the address");
    assert_ne!(post(&url, "/v1/signup", Some("203.0.113.1, 198.51.100.8")), 429);
    // A proxy that adds its own header line after the client's is read the same way.
    assert!((0..9).all(|i| post_lines(&url, "/v1/signup", &[&format!("10.9.9.{i}"), "198.51.100.8"]) != 429));
    assert_eq!(post_lines(&url, "/v1/signup", &["10.9.9.99", "198.51.100.8"]), 429);
    // Requests in flight together can't all slip through before any is counted.
    let parallel: Vec<_> = (0..40).map(|_| {
        let url = url.clone();
        std::thread::spawn(move || post_lines(&url, "/v1/login", &["192.0.2.1"]))
    }).collect();
    assert_eq!(parallel.into_iter().map(|t| t.join().unwrap()).filter(|s| *s == 429).count(), 10);
    // IPv6 counts per /64.
    assert!((0..10).all(|i| post(&url, "/v1/signup", Some(&format!("2001:db8::{i}"))) != 429));
    assert_eq!(post(&url, "/v1/signup", Some("2001:db8::ffff")), 429);
    assert_ne!(post(&url, "/v1/signup", Some("2001:db8:0:1::1")), 429);
    // A port or brackets from the proxy don't make a new address.
    assert_eq!(post(&url, "/v1/signup", Some("[2001:db8::7]:443")), 429);
    assert_eq!(post(&url, "/v1/signup", Some("[2001:db8::7]")), 429);
    assert!((0..10).all(|i| post(&url, "/v1/signup", Some(&format!("198.51.100.200:{}", 1000 + i))) != 429));
    assert_eq!(post(&url, "/v1/signup", Some("198.51.100.200")), 429);
}

/// Small requests by default; larger ones only with a valid session, checked
/// before the server reads the body.
#[test]
fn request_size_limits() {
    let (url, path) = server_with(plaintext_server::Config { open_signup: true, ..Default::default() });
    // Announces a `len`-byte body and sends only `sent` bytes of it: the answer
    // must come without the rest.
    let send = |method: &str, path: &str, token: Option<&str>, len: usize, sent: usize| -> u16 {
        use std::io::{Read, Write};
        let host = url.trim_start_matches("http://");
        let mut s = std::net::TcpStream::connect(host).unwrap();
        s.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
        let auth = token.map(|t| format!("authorization: Bearer {t}\r\n")).unwrap_or_default();
        write!(s, "{method} {path} HTTP/1.1\r\nhost: {host}\r\ncontent-type: application/json\r\n{auth}content-length: {len}\r\n\r\n").unwrap();
        s.write_all(&vec![b' '; sent]).unwrap();
        let mut head = [0u8; 12];
        s.read_exact(&mut head).unwrap();
        std::str::from_utf8(&head[9..12]).unwrap().parse().unwrap()
    };
    assert_eq!(send("POST", "/v1/signup", None, 1 << 20, 65 << 10), 413);
    let file = format!("/v1/vaults/{}/files/{}", "00".repeat(16), "11".repeat(16));
    assert_eq!(send("PUT", &file, None, 3 << 20, 0), 401);
    assert_eq!(send("PUT", &file, Some("not-a-session"), 3 << 20, 0), 401);
    assert_eq!(send("PUT", &format!("/v1/vaults/{}", "00".repeat(16)), None, 3 << 20, 0), 401);

    let (_, mut alice) = join(Http::new(&url), "alice", "alice pw", None, "t");
    alice.sync().unwrap();
    let personal = alice.default_vault().unwrap();
    let f = alice.upload_file(&personal, "scan.pdf", &vec![7u8; 3 << 20]).unwrap();
    assert_eq!(alice.download_file(&personal, &f).unwrap().len(), 3 << 20);
    // A vault push and a share link well over the small limit.
    let notes = Item { notes: "n".repeat(200_000), ..item("Big", "b") };
    alice.put_item(&personal, plaintext_core::new_item_id(), notes.clone()).unwrap();
    alice.create_link("https://getplaintext.org/s", &url, &notes, now_ms() / 1000 + 3600, None).unwrap();
    let _ = std::fs::remove_file(&path);
}

/// A server reached over HTTPS sends Strict-Transport-Security on every
/// response, including 404s and refused bodies; one without it never does.
#[test]
fn strict_transport_security() {
    let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).build().into();
    let hsts = |url: &str| {
        let get = |path: &str| {
            let r = agent.get(format!("{url}{path}")).call().unwrap();
            (r.status().as_u16(), r.headers().get("strict-transport-security").map(|v| v.to_str().unwrap().to_owned()))
        };
        // Announces a body over the limit and sends only part of it, as `request_size_limits` does.
        let big = {
            use std::io::{Read, Write};
            let host = url.trim_start_matches("http://");
            let mut s = std::net::TcpStream::connect(host).unwrap();
            s.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
            write!(s, "POST /v1/signup HTTP/1.1\r\nhost: {host}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", 1 << 20).unwrap();
            s.write_all(&vec![b' '; 65 << 10]).unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                let mut b = [0u8];
                s.read_exact(&mut b).unwrap();
                head.push(b[0]);
            }
            let head = String::from_utf8(head).unwrap().to_ascii_lowercase();
            let hsts = head.lines().find_map(|l| l.strip_prefix("strict-transport-security: ")).map(String::from);
            (head[9..12].parse().unwrap(), hsts)
        };
        [get("/health"), get("/nope"), big]
    };
    let on = Some("max-age=31536000".to_owned());
    let (url, _) = server_with(plaintext_server::Config { hsts: plaintext_server::https_url("https://vault.example.com"), ..Default::default() });
    assert_eq!(hsts(&url), [(200, on.clone()), (404, on.clone()), (413, on)]);
    let (url, _) = server();
    assert_eq!(hsts(&url), [(200, None), (404, None), (413, None)]);
}

/// A push or key rotation over the 32 MiB request limit goes up in parts (staged),
/// and commits in one request.
#[test]
fn large_pushes() {
    let (url, path) = server_with(plaintext_server::Config { open_signup: true, ..Default::default() });
    let (ask, mut alice) = join(Http::new(&url), "alice", "alice pw", None, "t");
    join(Http::new(&url), "bob", "bob pw", None, "t");
    alice.sync().unwrap();
    let personal = alice.default_vault().unwrap();
    // 30 items of 900 KB: 27 MB sealed, 36 MB in base64.
    let v = alice.vaults.get_mut(&personal).unwrap();
    for i in 0..30 {
        v.put(plaintext_core::new_item_id(), Item { notes: "n".repeat(900_000), ..item(&format!("Scan {i}"), "x") });
    }
    alice.sync_vault(&personal).unwrap();
    let mut alice2 = login(&url, "alice pw", &ask);
    alice2.sync().unwrap();
    assert_eq!(alice2.vaults[&personal].items().count(), 30);
    // Removing someone re-seals every item under a new key.
    alice.share_vault(&personal, "bob", Role::Reader, None).unwrap();
    alice.revoke(&personal, "bob").unwrap();
    alice2.sync().unwrap();
    assert_eq!(alice2.vaults[&personal].roster.as_ref().unwrap().epoch, 1);
    assert_eq!(alice2.vaults[&personal].items().filter(|(_, i)| i.notes.len() == 900_000).count(), 30);
    assert_eq!(count(&path, "SELECT COUNT(*) FROM staged"), 0);

    // A push whose staged items another push from the account replaced is refused.
    let me = alice.me();
    let v = alice.vaults.get_mut(&personal).unwrap();
    v.put(plaintext_core::new_item_id(), item("Late", "l8"));
    let put = v.push(&me, now()).unwrap();
    let (a, b) = (plaintext_core::new_item_id(), plaintext_core::new_item_id());
    let stage = format!("/v1/vaults/{personal}/stage");
    alice.call::<()>("POST", &stage, Some(&StageRequest { stage: a, upserts: put.upserts.clone() })).unwrap();
    alice.call::<()>("POST", &stage, Some(&StageRequest { stage: b, upserts: put.upserts.clone() })).unwrap();
    // A stage expires a day after its first part, and its first part is audited.
    let audited = "SELECT COUNT(*) FROM audit WHERE action = 'staging a big push'";
    let (logged, t) = (count(&path, audited), count(&path, "SELECT created FROM staged"));
    exec(&path, "UPDATE staged SET created = created - 1000");
    alice.call::<()>("POST", &stage, Some(&StageRequest { stage: b, upserts: put.upserts.clone() })).unwrap();
    assert_eq!(count(&path, "SELECT created FROM staged"), t - 1000);
    assert_eq!(count(&path, audited), logged);
    assert!(logged >= 3, "the first push, the new key and each stage above");
    let stale = VaultPut { upserts: vec![], staged: Some(Staged { id: a, count: 1 }), ..put };
    assert_eq!(status(alice.call::<()>("PUT", &format!("/v1/vaults/{personal}"), Some(&stale))), 409);
    assert_eq!(count(&path, "SELECT COUNT(*) FROM staged"), 1, "a failed push drops only the stage it named");
    alice.sync_vault(&personal).unwrap();
    assert_eq!(count(&path, "SELECT COUNT(*) FROM staged"), 0, "and the next push drops what's left over");
    assert!(!alice.vaults[&personal].has_changes());

    // A request over the limit gets 413, unlike a full account (507).
    use std::io::{Read, Write};
    let host = url.trim_start_matches("http://");
    let mut s = std::net::TcpStream::connect(host).unwrap();
    s.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
    write!(s, "PUT /v1/vaults/{personal} HTTP/1.1\r\nhost: {host}\r\nconnection: close\r\ncontent-type: application/json\r\nauthorization: Bearer {}\r\ncontent-length: {}\r\n\r\n", alice.token, 33 << 20).unwrap();
    // The server stops reading once past the limit, so the end may not go through.
    let _ = s.write_all(&vec![b' '; 33 << 20]);
    let (mut resp, mut buf) = (String::new(), [0u8; 4096]);
    while !resp.contains("bigger") {
        match s.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => resp.push_str(&String::from_utf8_lossy(&buf[..n])),
        }
    }
    assert!(resp.starts_with("HTTP/1.1 413") && resp.contains("length limit"), "{resp}");

    // A vault too big to pull is reported on its own; the rest of the sync goes on.
    struct TooBig(Http, Hex);
    impl Transport for TooBig {
        fn send(&self, method: &str, path: &str, token: Option<&str>, body: Option<Vec<u8>>) -> Result<(u16, Vec<u8>)> {
            if method == "GET" && path.starts_with(&format!("/v1/vaults/{}?", self.1)) {
                return Ok((413, b"too big".to_vec()));
            }
            self.0.send(method, path, token, body)
        }
        fn host(&self) -> String {
            self.0.host()
        }
    }
    let mut fresh = Session::login(TooBig(Http::new(&url), personal), &derive("alice pw", &ask), "t").unwrap();
    fresh.sync().unwrap();
    assert!(!fresh.vaults.contains_key(&personal));
    assert!(fresh.problems.iter().any(|p| p.contains("too big to pull")), "{:?}", fresh.problems);
    let _ = std::fs::remove_file(&path);
}

/// Members can leave a vault (their agents leave with them), so nobody is stuck
/// paying for a vault someone handed them.
#[test]
fn leaving_a_vault() {
    let (url, path) = server_with(plaintext_server::Config { open_signup: true, ..Default::default() });
    let (_, mut alice) = join(Http::new(&url), "alice", "alice pw", None, "t");
    let (bsk, mut bob) = join(Http::new(&url), "bob", "bob pw", None, "t");
    let (_, mut carol) = join(Http::new(&url), "carol", "carol pw", None, "t");
    let fam = alice.create_vault("Family").unwrap();
    alice.put_item(&fam, plaintext_core::new_item_id(), item("Netflix", "n3tfl1x")).unwrap();
    alice.share_vault(&fam, "bob", Role::Writer, None).unwrap();
    let bot_key = bob.create_agent("bob-bot").unwrap();
    alice.share_vault(&fam, "bob-bot", Role::Reader, None).unwrap();
    bob.sync().unwrap();
    assert!(bob.vaults.contains_key(&fam));

    // Leaving is signed for the vault it names, so a session token alone can't.
    let other = bob.me().sign_doc("leave", &LeaveVault { vault_id: bob.default_vault().unwrap(), ts: now_ms() });
    assert_eq!(status(bob.call::<()>("POST", &format!("/v1/vaults/{fam}/leave"), Some(&other))), 400);
    // Bob leaves, his agent with him, and alice's device replaces the key.
    bob.leave_vault(&fam).unwrap();
    bob.sync().unwrap();
    assert!(!bob.vaults.contains_key(&fam));
    let bot = Session::login(Http::new(&url), &derive_agent(&bot_key), "t").unwrap();
    assert_eq!(status(bot.call::<VaultResponse>("GET", &format!("/v1/vaults/{fam}"), NONE)), 404);
    // A roster alice's device built before it saw them leave can't bring them back.
    alice.pin_user("carol").unwrap();
    let stale = alice.vaults[&fam].grant(&alice.me(), &alice.keyring, "carol", Role::Reader, None, now()).unwrap();
    assert_eq!(status(alice.call::<()>("POST", &format!("/v1/vaults/{fam}/roster"), Some(&stale))), 409);
    alice.sync().unwrap();
    let r = alice.vaults[&fam].roster.clone().unwrap();
    assert_eq!((r.epoch, r.members.len()), (1, 1));
    // Every roster keeps an owner and a real key check.
    let me = alice.me();
    let tweak = |f: &dyn Fn(&mut Roster)| {
        let u = alice.vaults[&fam].grant(&me, &alice.keyring, "carol", Role::Reader, None, now()).unwrap();
        let mut r: Roster = serde_json::from_slice(&u.roster.body.0).unwrap();
        f(&mut r);
        RosterUpdate { roster: me.sign_doc("roster", &r), ..u }
    };
    let demoted = tweak(&|r| r.members.iter_mut().for_each(|m| m.role = Role::Reader));
    let expiring = tweak(&|r| r.members.iter_mut().filter(|m| m.role == Role::Owner).for_each(|m| m.expires = Some(now() + 3600)));
    for u in [demoted, expiring, tweak(&|r| r.key_check = B64(vec![0; 1000]))] {
        assert_eq!(status(alice.call::<()>("POST", &format!("/v1/vaults/{fam}/roster"), Some(&u))), 400);
    }
    // A creator who leaves hands the vault to an owner who stays.
    let club = carol.create_vault("Club").unwrap();
    carol.share_vault(&club, "alice", Role::Owner, None).unwrap();
    carol.leave_vault(&club).unwrap();
    assert_eq!(count(&path, "SELECT COUNT(*) FROM vaults WHERE creator = 'alice'"), 3);

    // An owner leaves rather than taking themselves out of the roster.
    assert_eq!(status(alice.revoke(&fam, "alice")), 400);
    // Bob makes carol an owner and deletes his account: the vault now counts
    // against carol, who can leave it, which deletes it.
    let gift = bob.create_vault("Gift").unwrap();
    bob.share_vault(&gift, "carol", Role::Owner, None).unwrap();
    bob.delete_account(&derive("bob pw", &bsk)).unwrap();
    assert_eq!(count(&path, "SELECT COUNT(*) FROM vaults WHERE creator = 'carol'"), 2);
    carol.sync().unwrap();
    carol.leave_vault(&gift).unwrap();
    assert_eq!(count(&path, "SELECT COUNT(*) FROM vaults WHERE creator = 'carol'"), 1);
    assert_eq!(count(&path, "SELECT COUNT(*) FROM vaults"), 4, "alice's three and carol's own");
    let _ = std::fs::remove_file(&path);
}

fn exec(path: &std::path::Path, sql: &str) {
    plaintext_server::open_db(path.to_str().unwrap()).unwrap().execute(sql, []).unwrap();
}

/// Whoever a vault ends up counting against can always leave it: even if their
/// device can't open it, as its only owner, once their membership expired, or
/// when only an agent of theirs is in it; and a creator someone else removed stops
/// paying even if an agent of theirs stays.
#[test]
fn nobody_is_stuck_paying_for_a_vault() {
    let (url, path) = server_with(plaintext_server::Config { open_signup: true, quota: Some(4 << 20), ..Default::default() });
    let (_, mut mallory) = join(Http::new(&url), "mallory", "mallory pw", None, "t");
    let (_, mut mallory2) = join(Http::new(&url), "mallory2", "mallory2 pw", None, "t");
    let (_, mut bob) = join(Http::new(&url), "bob", "bob pw", None, "t");
    let creator = |v: &Hex| {
        plaintext_server::open_db(path.to_str().unwrap())
            .unwrap()
            .query_row("SELECT creator FROM vaults WHERE id = ?", [&v.0[..]], |r| r.get::<_, String>(0))
            .ok()
    };

    // Mallory makes bob an owner of a vault his device can't open (a garbage key),
    // with her second account in it too, and leaves: it counts against bob.
    let trap = mallory.create_vault("Trap").unwrap();
    mallory.put_item(&trap, plaintext_core::new_item_id(), item("Junk", "x".repeat(10_000).as_str())).unwrap();
    mallory.share_vault(&trap, "mallory2", Role::Writer, None).unwrap();
    mallory.pin_user("bob").unwrap();
    let me = mallory.me();
    let mut u = mallory.vaults[&trap].grant(&me, &mallory.keyring, "bob", Role::Owner, None, now()).unwrap();
    // Wrapped keys are only for roster members, at the roster's epoch.
    let mut stray = u.clone();
    stray.keys.push(WrappedKey { epoch: 7, ..u.keys[0].clone() });
    assert_eq!(status(mallory.call::<()>("POST", &format!("/v1/vaults/{trap}/roster"), Some(&stray))), 400);
    stray.keys = vec![WrappedKey { username: "nobody".into(), ..u.keys[0].clone() }];
    assert_eq!(status(mallory.call::<()>("POST", &format!("/v1/vaults/{trap}/roster"), Some(&stray))), 400);
    u.keys[0].key = B64(vec![1; 100]);
    mallory.call::<()>("POST", &format!("/v1/vaults/{trap}/roster"), Some(&u)).unwrap();
    mallory.sync().unwrap();
    mallory.leave_vault(&trap).unwrap();
    assert_eq!(creator(&trap).as_deref(), Some("bob"));
    // Bob's sync names the vault by id and how to leave it, and he can, as its only owner.
    bob.sync().unwrap();
    assert!(!bob.vaults.contains_key(&trap));
    let named: Vec<_> = bob.problems.iter().filter(|p| p.contains(&trap.to_string())).collect();
    assert!(named.len() == 1 && named[0].contains(&format!("it counts against your storage (plaintext vault leave {trap} ")) && named[0].leave == Some(trap), "{named:?}");
    bob.leave_vault(&trap).unwrap();
    assert_eq!(creator(&trap).as_deref(), Some("mallory2"));
    // The last one out deletes it.
    mallory2.leave_vault(&trap).unwrap();
    assert_eq!(creator(&trap), None);

    // A creator whose membership expired can still leave.
    let (_, mut carol) = join(Http::new(&url), "carol", "carol pw", None, "t");
    // (Her own roster says so: a server that only stops listing a vault you created
    // and own can't get you hinted to leave it, which deletes it.)
    let old = carol.create_vault("Old").unwrap();
    carol.share_vault(&old, "bob", Role::Owner, None).unwrap();
    bob.sync().unwrap();
    bob.share_vault(&old, "carol", Role::Writer, Some(now() + 3600)).unwrap();
    carol.sync().unwrap();
    exec(&path, &format!("UPDATE members SET expires = 1 WHERE username = 'carol' AND vault_id = x'{old}'"));
    let acct: AccountResponse = carol.call("GET", "/v1/account", NONE).unwrap();
    assert!(acct.paid.contains(&old) && !acct.vaults.contains(&old), "{acct:?}");
    carol.sync().unwrap();
    assert!(carol.problems.iter().any(|p| p.contains(&format!("plaintext vault leave {old}"))), "{:?}", carol.problems);
    carol.leave_vault(&old).unwrap();
    assert_eq!(creator(&old).as_deref(), Some("bob"));

    // Mallory makes bob an owner of a vault he can open and leaves: it counts against
    // him, and his sync names it and how to leave it (his own vaults it doesn't name).
    let big = mallory.create_vault("Big").unwrap();
    mallory.share_vault(&big, "bob", Role::Owner, None).unwrap();
    mallory.leave_vault(&big).unwrap();
    assert_eq!(creator(&big).as_deref(), Some("bob"));
    bob.sync().unwrap();
    assert!(bob.vaults.contains_key(&big));
    let named: Vec<_> = bob.problems.iter().filter(|p| p.contains(&big.to_string())).collect();
    assert!(named.len() == 1 && named[0].contains("vault Big counts against your storage, though mallory created it") && named[0].leave == Some(big), "{named:?}");
    let personal = bob.default_vault().unwrap();
    assert!(!bob.problems.iter().any(|p| p.contains(&personal.to_string()) || p.contains("vault Personal") || p.leave == Some(personal)), "{:?}", bob.problems);
    bob.leave_vault(&big).unwrap();
    assert_eq!(creator(&big), None);

    // A vault bob opened before that no longer checks out is still named with how
    // to leave it and that it counts against him, once.
    let stale = mallory.create_vault("Stale").unwrap();
    mallory.share_vault(&stale, "bob", Role::Owner, None).unwrap();
    bob.sync().unwrap();
    mallory.put_item(&stale, plaintext_core::new_item_id(), item("Later", "x")).unwrap();
    mallory.sync().unwrap();
    mallory.leave_vault(&stale).unwrap();
    exec(&path, &format!("UPDATE manifests SET signed = replace(signed, '\"signer\":\"mallory\"', '\"signer\":\"bob\"') WHERE vault_id = x'{stale}'"));
    bob.sync().unwrap();
    assert!(bob.vaults.contains_key(&stale));
    let named: Vec<_> = bob.problems.iter().filter(|p| p.contains(&stale.to_string())).collect();
    assert!(
        named.len() == 1 && named[0].starts_with("vault Stale wasn't updated") && named[0].contains(&format!("it counts against your storage (plaintext vault leave {stale} ")) && named[0].leave == Some(stale),
        "{named:?}"
    );
    bob.leave_vault(&stale).unwrap();
    assert_eq!(creator(&stale), None);

    // Mallory makes bob's agent the owner of a vault and leaves: it counts against
    // bob, his sync says so, and he takes the agent out, which deletes it.
    bob.create_agent("bob-bot").unwrap();
    let gift = mallory.create_vault("Gift").unwrap();
    mallory.share_vault(&gift, "bob-bot", Role::Owner, None).unwrap();
    mallory.leave_vault(&gift).unwrap();
    assert_eq!(creator(&gift).as_deref(), Some("bob"));
    let acct: AccountResponse = bob.call("GET", "/v1/account", NONE).unwrap();
    assert!(acct.paid.contains(&gift) && !acct.vaults.contains(&gift), "{acct:?}");
    bob.sync().unwrap();
    assert!(bob.problems.iter().any(|p| p.contains(&format!("plaintext vault leave {gift}"))), "{:?}", bob.problems);
    bob.leave_vault(&gift).unwrap();
    assert_eq!(creator(&gift), None);

    // Mallory takes bob out of a vault he made while his agent stays in, with a change
    // his device hadn't sent: it stops counting against him (mallory pays), the
    // change is named by the vault's name, and leaving (which takes bob-bot out) drops it.
    let kept = bob.create_vault("Kept").unwrap();
    bob.share_vault(&kept, "mallory", Role::Owner, None).unwrap();
    bob.share_vault(&kept, "bob-bot", Role::Writer, None).unwrap();
    bob.vaults.get_mut(&kept).unwrap().put(plaintext_core::new_item_id(), item("Unsent", "u"));
    mallory.sync().unwrap();
    mallory.revoke(&kept, "bob").unwrap();
    assert_eq!(creator(&kept).as_deref(), Some("mallory"));
    bob.sync().unwrap();
    assert!(bob.unsendable.contains(&kept));
    assert!(bob.problems.iter().any(|p| p.starts_with("vault Kept isn't listed for you any more")), "{:?}", bob.problems);
    let acct: AccountResponse = bob.call("GET", "/v1/account", NONE).unwrap();
    assert!(!acct.paid.contains(&kept), "{acct:?}");
    assert!(!bob.problems.iter().any(|p| p.contains(&kept.to_string())), "{:?}", bob.problems);
    // Only that warning offers to drop its changes, and dropping them clears it.
    let unsent = |s: &Session<_>| s.problems.iter().filter(|p| p.unsent == Some(kept)).map(|p| p.text.clone()).collect::<Vec<_>>();
    assert!(matches!(&unsent(&bob)[..], [t] if t.contains("Kept isn't listed")), "{:?}", bob.problems);
    assert_eq!(bob.discard_changes(&kept).unwrap(), 1);
    assert!(unsent(&bob).is_empty() && bob.unsendable.is_empty(), "{:?}", bob.problems);
    bob.hidden.get_mut(&kept).unwrap().put(plaintext_core::new_item_id(), item("Unsent", "u"));
    bob.sync().unwrap();
    assert!(bob.unsendable.contains(&kept));
    bob.leave_vault(&kept).unwrap();
    assert!(bob.unsendable.is_empty() && !bob.hidden[&kept].has_changes());
    // Its warning goes too.
    assert!(!bob.problems.iter().any(|p| p.contains("Kept isn't listed")), "{:?}", bob.problems);
    bob.sync().unwrap();
    assert!(!bob.problems.iter().any(|p| p.contains("Kept") || p.contains(&kept.to_string())), "{:?}", bob.problems);

    // Bob removes the creator of a vault but keeps her agent: her device can't see
    // the vault any more, so it counts against bob from then on, not her.
    let (_, mut alice) = join(Http::new(&url), "alice", "alice pw", None, "t");
    alice.create_agent("alice-bot").unwrap();
    let alices = alice.create_vault("Kept").unwrap();
    alice.share_vault(&alices, "alice-bot", Role::Writer, None).unwrap();
    alice.share_vault(&alices, "bob", Role::Owner, None).unwrap();
    bob.sync().unwrap();
    // Taking it on needs room in bob's account when he adds someone in the same
    // change; removing her alone works even when he's full.
    exec(&path, "INSERT INTO links(id, creator, blob, expires, views_left) VALUES(x'00', 'bob', zeroblob(5 << 20), 9999999999, 1)");
    let carol_keys = bob.pin_user("carol").unwrap();
    let u = bob.vaults[&alices].revoke(&bob.me(), &["alice"], now()).unwrap();
    let mut r: Roster = serde_json::from_slice(&u.roster.body.0).unwrap();
    r.members.push(Member { username: "carol".into(), sign_pk: carol_keys.sign_pk.clone(), enc_pk: carol_keys.enc_pk.clone(), role: Role::Reader, expires: None });
    let u = RosterUpdate { roster: bob.me().sign_doc("roster", &r), ..u };
    assert_eq!(status(bob.call::<()>("POST", &format!("/v1/vaults/{alices}/roster"), Some(&u))), 507);
    assert_eq!(creator(&alices).as_deref(), Some("alice"));
    bob.revoke(&alices, "alice").unwrap();
    assert_eq!(creator(&alices).as_deref(), Some("bob"));
    exec(&path, "DELETE FROM links WHERE id = x'00'");
    let members: String = plaintext_server::open_db(path.to_str().unwrap())
        .unwrap()
        .query_row(&format!("SELECT group_concat(username, ' ' ORDER BY username) FROM members WHERE vault_id = x'{alices}'"), [], |r| r.get(0))
        .unwrap();
    assert_eq!(members, "alice-bot bob");
    let acct: AccountResponse = alice.call("GET", "/v1/account", NONE).unwrap();
    assert!(!acct.paid.contains(&alices) && !acct.vaults.contains(&alices), "{acct:?}");
    alice.sync().unwrap();
    assert!(!alice.problems.iter().any(|p| p.contains(&alices.to_string())), "{:?}", alice.problems);

    // A vault bob pays for only through his agent (as when it was handed to bob-bot)
    // stays his when another owner changes its roster without removing him.
    let through = carol.create_vault("Through").unwrap();
    carol.share_vault(&through, "bob-bot", Role::Owner, None).unwrap();
    exec(&path, &format!("UPDATE vaults SET creator = 'bob' WHERE id = x'{through}'"));
    carol.share_vault(&through, "mallory2", Role::Reader, None).unwrap();
    assert_eq!(creator(&through).as_deref(), Some("bob"));
    let _ = std::fs::remove_file(&path);

    // Without a quota, an openable vault someone handed you costs nothing and isn't
    // named, but one only an agent of yours is in still is.
    let (url, path) = server_with(plaintext_server::Config { open_signup: true, ..Default::default() });
    let (_, mut mallory) = join(Http::new(&url), "mallory", "mallory pw", None, "t");
    let (_, mut bob) = join(Http::new(&url), "bob", "bob pw", None, "t");
    bob.create_agent("bob-bot").unwrap();
    let open = mallory.create_vault("Open").unwrap();
    mallory.share_vault(&open, "bob", Role::Owner, None).unwrap();
    mallory.leave_vault(&open).unwrap();
    let gift = mallory.create_vault("Gift").unwrap();
    mallory.share_vault(&gift, "bob-bot", Role::Owner, None).unwrap();
    mallory.leave_vault(&gift).unwrap();
    let acct: AccountResponse = bob.call("GET", "/v1/account", NONE).unwrap();
    assert!(acct.paid.contains(&open) && acct.paid.contains(&gift), "{acct:?}");
    bob.sync().unwrap();
    assert!(bob.vaults.contains_key(&open));
    assert!(!bob.problems.iter().any(|p| p.contains("vault Open") || p.contains(&open.to_string())), "{:?}", bob.problems);
    let named: Vec<_> = bob.problems.iter().filter(|p| p.contains(&gift.to_string())).collect();
    assert!(named.len() == 1 && named[0].contains(&format!("plaintext vault leave {gift}")) && named[0].leave == Some(gift), "{named:?}");
    let _ = std::fs::remove_file(&path);
}

// ---------- Attacks from the 2026-11 security audit, over real HTTP; each must stay fixed ----------

use plaintext_core::api::{Kind, UserInfo, VaultPut};
use plaintext_core::identity::Keyring;

/// A server that lists a vault of its own making in the account (hiding the real ones)
/// and answers for it; pushes to it are kept, not stored.
struct Forge {
    inner: Http,
    id: Hex,
    first: VaultResponse,
    pushed: std::cell::RefCell<Vec<VaultPut>>,
}

impl Transport for Forge {
    fn send(&self, method: &str, path: &str, token: Option<&str>, body: Option<Vec<u8>>) -> Result<(u16, Vec<u8>)> {
        if path.starts_with(&format!("/v1/vaults/{}", self.id)) {
            return Ok(match method {
                "GET" if path.contains("since=0") => (200, serde_json::to_vec(&self.first).unwrap()),
                "GET" => (200, serde_json::to_vec(&VaultResponse { counter: self.first.counter, ..Default::default() }).unwrap()),
                _ => {
                    self.pushed.borrow_mut().push(serde_json::from_slice(&body.unwrap()).unwrap());
                    (204, vec![])
                }
            });
        }
        let (status, bytes) = self.inner.send(method, path, token, body)?;
        if method == "GET" && path == "/v1/account" && status == 200 {
            let mut acct: AccountResponse = serde_json::from_slice(&bytes).unwrap();
            acct.vaults = vec![self.id];
            return Ok((status, serde_json::to_vec(&acct).unwrap()));
        }
        Ok((status, bytes))
    }
    fn host(&self) -> String {
        self.inner.host()
    }
}

#[test]
fn audit_agent_session_trusts_a_vault_the_server_made() {
    let (url, _) = server();
    let (_, mut alice) = join(Http::new(&url), "alice", "alice pw", Some("first-run-code"), "laptop");
    let ci = alice.create_vault("CI").unwrap();
    alice.put_item(&ci, plaintext_core::new_item_id(), item("Deploy token", "real-deploy-token")).unwrap();
    let key = alice.create_agent("ci-bot").unwrap();
    alice.share_vault(&ci, "ci-bot", Role::Writer, None).unwrap();

    // The server builds its own "alice" and its own "CI" vault with the real agent as a writer.
    let agent_id: UserInfo = alice.call("GET", "/v1/users/ci-bot", NONE).unwrap();
    let mut fake = Keyring::new("alice");
    fake.pin_identity(&agent_id.identity).unwrap();
    let fm = fake.me();
    let (mut fv, fnv) = Vault::create(&fm, "CI").unwrap();
    let g = fv.grant(&fm, &fake, "ci-bot", Role::Writer, None, now()).unwrap();
    fv.apply(&VaultResponse { counter: 1, rosters: vec![g.roster.clone()], ..Default::default() }, &mut fake, now()).unwrap();
    fv.put(plaintext_core::new_item_id(), item("Deploy token", "attacker-deploy-token"));
    let p = fv.push(&fm, now()).unwrap();
    fv.pushed(&p);
    let first = VaultResponse {
        counter: 2,
        manifests: vec![fnv.manifest.clone(), p.manifest.clone()],
        rosters: vec![fnv.roster.clone(), g.roster.clone()],
        key: Some(g.keys[0].key.clone()),
        items: p.upserts.clone(),
        gone: vec![],
    };
    let forge = Forge { inner: Http::new(&url), id: fv.id, first, pushed: Default::default() };

    // Exactly the CLI's agent path (state::open with PLAINTEXT_AGENT_KEY): log in, sync, no local state.
    // The agent knows its owner's real keys from the start, so the look-alike vault is refused.
    let mut agent = Session::login(forge, &derive_agent(&key), "agent").unwrap();
    agent.sync().unwrap();
    assert!(agent.problems.iter().any(|p| p.contains("wasn't updated") && p.contains("alice")), "{:?}", agent.problems);
    assert!(agent.vault("CI").is_err(), "nothing named CI is usable");
    assert!(agent.t.pushed.borrow().is_empty(), "nothing was written to the server's vault");
}

#[test]
fn audit_hidden_default_vault_sends_new_items_to_a_shared_vault() {
    let (url, _) = server();
    let (ask, mut alice) = join(Http::new(&url), "alice", "alice pw", Some("first-run-code"), "laptop");
    let code = alice.invite().unwrap();
    let (_, mut bob) = join(Http::new(&url), "bob", "bob pw", Some(&code), "phone");
    alice.sync().unwrap();
    let personal = alice.default_vault().unwrap();
    let fam = alice.create_vault("Family").unwrap();
    alice.share_vault(&fam, "bob", Role::Reader, None).unwrap();

    // The server stops listing alice's Personal vault; she adds a login without naming a vault.
    let mut a2 = Session::login(evil(&url), &derive("alice pw", &ask), "laptop").unwrap();
    a2.t.hide.set(Some(personal));
    a2.sync().unwrap();
    assert!(!a2.problems.iter().any(|p| p.leave == Some(personal)), "{:?}", a2.problems);
    // No silent fallback to Family (shared with bob): the user has to pick a vault.
    assert!(matches!(a2.default_vault(), Err(Error::NotFound(_))), "default_vault() picked {:?} (Family: {fam:?})", a2.default_vault());
    bob.sync().unwrap();
    assert_eq!(alice.default_vault().unwrap(), personal);
}

/// A server that answers a directory lookup with an identity of its own.
struct Lookup(Http, &'static str, plaintext_core::api::Signed);

impl Transport for Lookup {
    fn send(&self, method: &str, path: &str, token: Option<&str>, body: Option<Vec<u8>>) -> Result<(u16, Vec<u8>)> {
        if method == "GET" && path == format!("/v1/users/{}", self.1) {
            let u = UserInfo { identity: self.2.clone(), admin: true, disabled: false, invite: None };
            return Ok((200, serde_json::to_vec(&u).unwrap()));
        }
        self.0.send(method, path, token, body)
    }
    fn host(&self) -> String {
        self.0.host()
    }
}

#[test]
fn audit_signup_drops_secret_key_after_creating_the_account() {
    let (url, _) = server();
    let (_, mut alice) = join(Http::new(&url), "alice", "alice pw", Some("first-run-code"), "laptop");
    let code = alice.invite().unwrap();
    let liar = Lookup(Http::new(&url), "alice", Keyring::new("alice").identity(Kind::Human, None));
    // The account exists either way, so signup hands back the Secret Key; checking the
    // inviter is a separate step that fails without pinning the server's "alice".
    let (sk, bob) = Session::signup(liar, "bob", "bob pw", Some(&code), "phone").unwrap();
    let mut bob = bob.unwrap();
    assert!(matches!(bob.trust_inviter(&code), Err(Error::Core(plaintext_core::Error::KeyChanged(u))) if u == "alice"));
    assert!(!bob.keyring.contacts.contains_key("alice"), "the server's alice was not pinned");
    login(&url, "bob pw", &sk);
}

/// A server's redirect isn't followed (it could point a request, or a share
/// link's fetch, anywhere), and a silent server times out instead of hanging.
#[test]
fn no_redirects() {
    use std::io::{Read, Write};
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    std::thread::spawn(move || {
        for mut c in l.incoming().flatten().take(1) {
            let mut buf = [0u8; 1024];
            let _ = c.read(&mut buf);
            let _ = c.write_all(b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9/admin\r\nContent-Length: 0\r\n\r\n");
        }
    });
    let r = open_link(&Http::new(&url), &Hex([1; 16]), &"00".repeat(32));
    assert!(matches!(r, Err(Error::Server(302, _))), "{r:?}");
}

/// Anyone can share a vault with an agent. It refuses ones its owner didn't
/// sign for, and that refusal mustn't stop it from syncing its owner's vaults.
#[test]
fn a_stranger_s_vault_doesnt_jam_an_agent() {
    let (url, _) = server();
    let (_, mut alice) = join(Http::new(&url), "alice", "alice pw", Some("first-run-code"), "laptop");
    let ci = alice.create_vault("CI").unwrap();
    alice.put_item(&ci, plaintext_core::new_item_id(), item("Deploy token", "real-deploy-token")).unwrap();
    let key = alice.create_agent("ci-bot").unwrap();
    alice.share_vault(&ci, "ci-bot", Role::Reader, None).unwrap();
    let code = alice.invite().unwrap();
    let (_, mut bob) = join(Http::new(&url), "bob", "bob pw", Some(&code), "phone");
    let junk = bob.create_vault("CI").unwrap();
    bob.put_item(&junk, plaintext_core::new_item_id(), item("Deploy token", "bobs-token")).unwrap();
    bob.share_vault(&junk, "ci-bot", Role::Writer, None).unwrap();

    let mut agent = Session::login(Http::new(&url), &derive_agent(&key), "agent").unwrap();
    agent.sync().unwrap();
    assert_eq!(agent.one("deploy token", None).unwrap().2.password, "real-deploy-token");
    assert!(agent.problems.iter().any(|p| p.contains("wasn't updated")), "{:?}", agent.problems);
    assert_eq!(agent.vaults.len(), 1, "the stranger's vault isn't listed as usable");
}

/// Server hardening: logins without PLAINTEXT_URL, document sizes, inbox
/// paging, link views, quotas for links and messages, disabled owners' agents,
/// session lifetimes and response headers.
#[test]
fn server_hardening() {
    use plaintext_core::api::Message;
    let (url, path) = server_with(plaintext_server::Config { setup_code: Some("first-run-code".into()), ..Default::default() });
    let (ask, mut alice) = join(Http::new(&url), "alice", "alice pw", Some("first-run-code"), "t");
    let d = derive("alice pw", &ask);
    let host = url.trim_start_matches("http://").to_string();
    let raw = |method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]| -> (u16, String) {
        use std::io::{Read, Write};
        let mut s = std::net::TcpStream::connect(&host).unwrap();
        let mut req = format!("{method} {path} HTTP/1.1\r\nconnection: close\r\ncontent-length: {}\r\n", body.len());
        for (k, v) in headers {
            req += &format!("{k}: {v}\r\n");
        }
        s.write_all(format!("{req}\r\n").as_bytes()).unwrap();
        s.write_all(body).unwrap();
        let mut resp = String::new();
        s.read_to_string(&mut resp).unwrap();
        (resp[9..12].parse().unwrap(), resp)
    };
    let json = [("content-type", "application/json")];

    // Without PLAINTEXT_URL, only logins signed for this machine work: a look-alike
    // server can't relay one by naming itself in the Host header.
    for name in ["vault.examp1e.com", "localhost.examp1e.com"] {
        let relayed = serde_json::to_vec(&plaintext_core::login_request(&d, now_ms(), "t", name)).unwrap();
        let (st, _) = raw("POST", "/v1/login", &[json[0], ("host", name)], &relayed);
        assert_eq!(st, 403, "{name}");
    }
    let local = format!("localhost:{}", host.rsplit(':').next().unwrap());
    let ok = serde_json::to_vec(&plaintext_core::login_request(&d, now_ms(), "t", &local)).unwrap();
    assert_eq!(raw("POST", "/v1/login", &[json[0], ("host", &local)], &ok).0, 200);

    // Every response says not to cache it; HEAD doesn't use up a link's view.
    let (_, info) = raw("GET", "/v1/info", &[], b"");
    assert!(info.to_ascii_lowercase().contains("cache-control: no-store"), "{info}");
    let link = alice.create_link(LINK_PAGE, &url, &item("Door", "4711"), now() + 600, Some(1)).unwrap();
    let lid = link.split('#').nth(1).unwrap().rsplit('/').nth(1).unwrap().to_string();
    assert_eq!(raw("HEAD", &format!("/v1/links/{lid}"), &[], b"").0, 405);
    assert_eq!(raw("GET", &format!("/v1/links/{lid}"), &[], b"").0, 200);
    assert_eq!(raw("GET", &format!("/v1/links/{lid}"), &[], b"").0, 404, "one view");
    assert_eq!(count(&path, "SELECT COUNT(*) FROM links"), 0, "used up links go right away");

    // Signed documents are capped as a whole, not just their sealed part.
    let code = alice.invite().unwrap();
    let (bsk, mut bob) = join(Http::new(&url), "bob", "bob pw", Some(&code), "t");
    let me = bob.me();
    alice.pin_user("bob").unwrap();
    bob.pin_user("alice").unwrap();
    let msg = plaintext_core::send(&me, &bob.keyring, "alice", &Content::Request("hi".into()), None).unwrap();
    let mut padded: serde_json::Value = serde_json::from_slice(&msg.body.0).unwrap();
    padded["pad"] = "A".repeat(1_480_000).into();
    assert_eq!(status(bob.call::<()>("POST", "/v1/messages", Some(&me.sign_doc("message", &padded)))), 400);
    let (_, mut carol) = {
        let code = alice.invite().unwrap();
        join(Http::new(&url), "carol", "carol pw", Some(&code), "t")
    };
    let (_, mut agent) = plaintext_core::create_agent(&mut carol.keyring, "carol-bot").unwrap();
    let am = agent.keyring.me();
    let id = serde_json::json!({ "username": "carol-bot", "kind": "agent", "owner": "carol", "sign_pk": am.sign_pk(), "enc_pk": am.enc_pk(), "pad": "A".repeat(4000) });
    agent.request.identity = am.sign_doc("identity", &id);
    assert_eq!(status(carol.call::<()>("POST", "/v1/agents", Some(&agent.request))), 400, "identity too large");
    // Rosters: no duplicates, at most 1000 members.
    for n in [2, 1001] {
        let (_, mut nv) = plaintext_core::Vault::create(&bob.me(), "x").unwrap();
        let mut r: Roster = serde_json::from_slice(&nv.roster.body.0).unwrap();
        let me = r.members[0].clone();
        r.members = vec![me.clone(); n];
        if n > 2 {
            // Different names, so this is the member cap rather than the duplicate check.
            r.members.iter_mut().enumerate().skip(1).for_each(|(i, m)| m.username = format!("user{i}"));
        }
        nv.roster = bob.me().sign_doc("roster", &r);
        let err = bob.call::<()>("POST", "/v1/vaults", Some(&nv)).unwrap_err();
        assert!(matches!(&err, Error::Server(400, m) if m.contains("up to 1000 different members")), "{err}");
    }

    // A large inbox comes in pages, oldest first; deleting them brings the rest.
    for _ in 0..20 {
        bob.send("alice", &Content::Request("A".repeat(1_000_000)), None).unwrap();
    }
    let mut seen = 0;
    loop {
        let page: Vec<Signed> = alice.call("GET", "/v1/messages", NONE).unwrap();
        if page.is_empty() {
            break;
        }
        assert!(page.len() < 20, "{}", page.len());
        for s in &page {
            alice.delete_message(&serde_json::from_slice::<Message>(&s.body.0).unwrap().id).unwrap();
        }
        seen += page.len();
    }
    assert_eq!(seen, 20);

    let bob_ci = bob.create_agent("bob-ci").unwrap();

    // Disabling a person disables their agents, whose keys they still hold.
    let key = carol.create_agent("carol-ci").unwrap();
    let ci = Session::login(Http::new(&url), &derive_agent(&key), "ci").unwrap();
    alice.disable_user("carol").unwrap();
    assert_eq!(status(ci.sessions()), 401);
    assert_eq!(status(Session::login(Http::new(&url), &derive_agent(&key), "ci")), 401);

    // Sessions end on the server: a login may ask for less than 30 days.
    let mut short = plaintext_core::login_request(&d, now_ms(), "t", &host);
    // 3 s, not 1: expiry is in whole seconds, so a 1 s session can lapse before
    // the first check on a slow runner.
    short.ttl = Some(3);
    let token = call::<_, LoginResponse>(&Http::new(&url), "POST", "/v1/login", None, Some(&short)).unwrap().token;
    assert_eq!(status(call::<_, AccountResponse>(&Http::new(&url), "GET", "/v1/account", Some(&token), NONE)), 200);
    std::thread::sleep(std::time::Duration::from_millis(4100));
    assert_eq!(status(call::<_, AccountResponse>(&Http::new(&url), "GET", "/v1/account", Some(&token), NONE)), 401);

    // Links and messages count against the sender's quota.
    let url = server_at(&path, plaintext_server::Config { setup_code: Some("first-run-code".into()), quota: Some(512 << 10), ..Default::default() });
    let mut bob = login(&url, "bob pw", &bsk);
    let err = bob.send("alice", &Content::Request("A".repeat(1_000_000)), None).unwrap_err();
    assert!(matches!(&err, Error::Server(507, m) if m.contains("out of storage")), "{err}");
    let big = Item { notes: "n".repeat(900_000), ..item("Big", "b") };
    assert_eq!(status(bob.create_link(LINK_PAGE, &url, &big, now() + 600, None)), 507);
    bob.send("alice", &Content::Request("small".into()), None).unwrap();
    // An agent's links count against its owner; a sender can take back an unread message.
    let msg = plaintext_core::send(&bob.me(), &bob.keyring, "alice", &Content::Request("A".repeat(250_000)), None).unwrap();
    bob.call::<()>("POST", "/v1/messages", Some(&msg)).unwrap();
    let ci = Session::login(Http::new(&url), &derive_agent(&bob_ci), "ci").unwrap();
    let mid = Item { notes: "n".repeat(200_000), ..item("Mid", "m") };
    assert_eq!(status(ci.create_link(LINK_PAGE, &url, &mid, now() + 600, None)), 507);
    bob.delete_message(&serde_json::from_slice::<Message>(&msg.body.0).unwrap().id).unwrap();
    ci.create_link(LINK_PAGE, &url, &mid, now() + 600, None).unwrap();
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_reader_s_writes_are_refused_not_kept_on_the_device() {
    let (url, _) = server();
    let (_, mut alice) = join(Http::new(&url), "alice", "alice pw", Some("first-run-code"), "laptop");
    let code = alice.invite().unwrap();
    let (_, mut bob) = join(Flaky(Http::new(&url), Default::default(), Default::default()), "bob", "bob pw", Some(&code), "phone");
    alice.sync().unwrap();
    let fam = alice.create_vault("Family").unwrap();
    let nid = plaintext_core::new_item_id();
    alice.put_item(&fam, nid, item("Netflix", "n3tfl1x-pass")).unwrap();
    alice.share_vault(&fam, "bob", Role::Writer, None).unwrap();
    bob.sync().unwrap();
    bob.put_item(&fam, plaintext_core::new_item_id(), item("Bob's", "while-a-writer")).unwrap();

    // Alice makes bob a reader; his device still thinks he's a writer.
    alice.share_vault(&fam, "bob", Role::Reader, None).unwrap();
    let read_only = |r: Result<()>| matches!(r, Err(Error::Core(plaintext_core::Error::ReadOnly)));
    assert!(read_only(bob.put_item(&fam, plaintext_core::new_item_id(), item("Disney", "d1sney"))));
    assert!(read_only(bob.put_item(&fam, nid, item("Netflix", "changed"))));
    assert!(read_only(bob.delete_item(&fam, nid)));
    // The roster that refused him stays: offline, he's still told so.
    bob.t.1.set(true);
    assert!(read_only(bob.put_item(&fam, nid, item("Netflix", "offline"))));
    bob.t.1.set(false);
    let mut meta = bob.vaults[&fam].meta.clone();
    meta.name = "Bob's now".into();
    assert!(read_only(bob.rename_vault(&fam, meta)));
    let imp = |name: &str| import::Imported { name: name.into(), items: vec![(item("Imported", "i"), vec![])] };
    assert!(read_only(bob.import(vec![imp("")], Some(fam)).map(drop)));
    let v = &bob.vaults[&fam];
    assert!(!v.has_changes(), "nothing is left waiting on bob's device");
    assert_eq!(v.items().count(), 2);
    assert_eq!(v.get(&nid).unwrap().password, "n3tfl1x-pass");
    assert_eq!(v.meta.name, "Family");
    assert!(read_only(bob.writable(&fam)));

    // A vault he made counts as his for imports, even once he only reads it:
    // the whole import is refused before any vault is made or filled.
    let his = bob.create_vault("Bob's").unwrap();
    bob.share_vault(&his, "alice", Role::Owner, None).unwrap();
    alice.sync().unwrap();
    alice.share_vault(&his, "bob", Role::Reader, None).unwrap();
    let before = bob.vaults.len();
    assert!(read_only(bob.import(vec![imp("New one"), imp("bob's")], None).map(drop)));
    assert_eq!(bob.vaults.len(), before, "no vault was made");
    assert!(!bob.vaults[&his].has_changes() && bob.vaults[&his].items().count() == 0);

    // A writer again, he can.
    alice.share_vault(&fam, "bob", Role::Writer, None).unwrap();
    bob.delete_item(&fam, nid).unwrap();
    alice.sync().unwrap();
    assert!(alice.vaults[&fam].get(&nid).is_none());

    // Offline, an edit waits on the device and goes out with the next sync...
    let offline = |bob: &mut Session<Flaky>, title: &str| {
        bob.t.1.set(true);
        assert!(matches!(bob.put_item(&fam, plaintext_core::new_item_id(), item(title, "o")), Err(Error::Network(_))));
        bob.t.1.set(false);
        assert!(bob.vaults[&fam].has_changes());
    };
    offline(&mut bob, "Offline");
    bob.sync().unwrap();
    alice.sync().unwrap();
    assert_eq!(alice.vaults[&fam].items().filter(|(_, i)| i.title == "Offline").count(), 1);
    // ...but if he's made a reader meanwhile, every sync says it can't be sent.
    offline(&mut bob, "Too late");
    alice.share_vault(&fam, "bob", Role::Reader, None).unwrap();
    bob.sync().unwrap();
    assert!(bob.problems.iter().any(|p| p.contains("only read")), "{:?}", bob.problems);
    // Offline as a known reader, he's told so, not that his edit is waiting.
    bob.t.1.set(true);
    assert!(read_only(bob.put_item(&fam, plaintext_core::new_item_id(), item("Refused", "r"))));
    assert!(read_only(bob.writable(&fam)));
    // An offline writer may go ahead (import saves for the next sync).
    bob.t.1.set(false);
    alice.share_vault(&fam, "bob", Role::Writer, None).unwrap();
    bob.sync().unwrap();
    bob.t.1.set(true);
    bob.writable(&fam).unwrap();
    bob.t.1.set(false);

    // He can drop what he can't send: an edit, a delete and a rename.
    let (keep, gone) = (plaintext_core::new_item_id(), plaintext_core::new_item_id());
    bob.put_item(&fam, keep, item("Keep", "k")).unwrap();
    bob.put_item(&fam, gone, item("Gone?", "g")).unwrap();
    bob.t.1.set(true);
    assert!(matches!(bob.put_item(&fam, keep, item("Keep", "edited offline")), Err(Error::Network(_))));
    assert!(matches!(bob.delete_item(&fam, gone), Err(Error::Network(_))));
    let mut meta = bob.vaults[&fam].meta.clone();
    meta.name = "Renamed offline".into();
    assert!(matches!(bob.rename_vault(&fam, meta), Err(Error::Network(_))));
    bob.t.1.set(false);
    alice.share_vault(&fam, "bob", Role::Reader, None).unwrap();
    bob.sync().unwrap();
    // The apps show problems as they are: no CLI command in them, the id goes in a list.
    assert!(bob.problems.iter().any(|p| p.ends_with("this device's changes to it can't be sent")), "{:?}", bob.problems);
    assert_eq!(bob.unsendable, [fam]);
    assert!(bob.problems.iter().any(|p| p.unsent == Some(fam) && p.ends_with("this device's changes to it can't be sent")), "{:?}", bob.problems);
    // What `vault reset` lists before dropping anything.
    let v = &bob.vaults[&fam];
    assert_eq!(v.changed().map(|(_, i)| i.title.as_str()).collect::<Vec<_>>(), ["Keep"]);
    assert_eq!((v.deleted(), v.meta_changed()), (1, true));
    assert_eq!(bob.vault(&fam.to_string()).unwrap(), fam);
    // The fresh download must be the version his device verified, not an older one.
    let from_scratch = format!("/v1/vaults/{fam}?since=0&latest=true");
    let old = bob.t.0.send("GET", &from_scratch, Some(&bob.token), None).unwrap().1;
    alice.put_item(&fam, plaintext_core::new_item_id(), item("Newer", "n")).unwrap();
    *bob.t.2.borrow_mut() = Some((from_scratch, old));
    let rollback = bob.discard_changes(&fam);
    assert!(matches!(rollback, Err(Error::Core(plaintext_core::Error::Rollback))), "{rollback:?}");
    *bob.t.2.borrow_mut() = None;
    assert_eq!(bob.vaults[&fam].changes(), 3);
    // A download that fails drops nothing.
    bob.t.1.set(true);
    assert!(matches!(bob.discard_changes(&fam), Err(Error::Network(_))));
    bob.t.1.set(false);
    assert_eq!(bob.vaults[&fam].changes(), 3);
    // The apps act on an earlier sync's warning: their drop asks the server
    // first, so offline, or made a writer again since, it drops nothing.
    assert!(!bob.unsendable_changes(&fam).unwrap().1);
    bob.t.1.set(true);
    assert!(matches!(bob.discard_unsendable(&fam), Err(Error::Network(_))));
    bob.t.1.set(false);
    // Made a writer between the drop's two downloads, the first still saying he
    // may only read: a promotion leaves the head as it was, only the roster changes.
    let pull = format!("/v1/vaults/{fam}?{}", bob.vaults[&fam].pull_query());
    let as_reader = bob.t.0.send("GET", &pull, Some(&bob.token), None).unwrap().1;
    alice.share_vault(&fam, "bob", Role::Writer, None).unwrap();
    *bob.t.2.borrow_mut() = Some((pull, as_reader));
    let raced = bob.discard_unsendable(&fam);
    assert!(matches!(raced, Err(Error::Refused(_))), "{raced:?}");
    *bob.t.2.borrow_mut() = None;
    assert_eq!(bob.vaults[&fam].changes(), 3);
    assert_eq!(bob.unsendable.len(), 1, "its warning stays");
    assert!(matches!(bob.discard_unsendable(&fam), Err(Error::Refused(_))));
    assert!(matches!(bob.unsendable_changes(&fam), Err(Error::Refused(_))), "the drop's pull brought the new roster");
    assert_eq!(bob.vaults[&fam].changes(), 3);
    alice.share_vault(&fam, "bob", Role::Reader, None).unwrap();
    // A problem reported after it (as the apps add their own) stays.
    bob.problems.push("later".into());
    let warnings = bob.problems.len();
    assert_eq!(bob.discard_changes(&fam).unwrap(), 3);
    assert_eq!(bob.problems.last().map(|p| &p.text[..]), Some("later"));
    // Its warning goes with the changes, so the apps stop showing it before the next sync.
    assert!(bob.unsendable.is_empty());
    assert_eq!(bob.problems.len(), warnings - 1, "{:?}", bob.problems);
    assert!(!bob.problems.iter().any(|p| p.ends_with("can't be sent")), "{:?}", bob.problems);
    // Nothing left to drop (say, another app's discard got there first): its warning still goes.
    bob.problems.push(Problem { unsent: Some(fam), .."stale".into() });
    bob.unsendable.push(fam);
    assert_eq!(bob.discard_changes(&fam).unwrap(), 0);
    assert!(bob.unsendable.is_empty() && bob.problems.last().map(|p| &p.text[..]) == Some("later"), "{:?}", bob.problems);
    let v = &bob.vaults[&fam];
    assert_eq!(v.get(&keep).unwrap().password, "k");
    assert!(v.get(&gone).is_some());
    assert_eq!(v.meta.name, "Family");
    assert_eq!(v.items().count(), alice.vaults[&fam].items().count());
    bob.sync().unwrap();
    assert!(bob.problems.is_empty(), "{:?}", bob.problems);

    // Made a writer again, what he pushes keeps every item as the server has it.
    alice.share_vault(&fam, "bob", Role::Writer, None).unwrap();
    bob.put_item(&fam, plaintext_core::new_item_id(), item("Later", "l")).unwrap();
    alice.sync().unwrap();
    let v = &alice.vaults[&fam];
    assert_eq!(v.get(&keep).unwrap().password, "k");
    assert!(v.get(&gone).is_some());
    assert!(v.items().any(|(_, i)| i.title == "Later"));
}

#[test]
fn an_edit_or_delete_keeps_another_device_s_newer_change() {
    let (url, _) = server();
    let (_, mut alice) = join(Http::new(&url), "alice", "alice pw", Some("first-run-code"), "laptop");
    let code = alice.invite().unwrap();
    let (_, mut bob) = join(Http::new(&url), "bob", "bob pw", Some(&code), "phone");
    alice.sync().unwrap();
    let fam = alice.create_vault("Family").unwrap();
    let (n, d) = (plaintext_core::new_item_id(), plaintext_core::new_item_id());
    alice.put_item(&fam, n, item("Netflix", "v1")).unwrap();
    alice.put_item(&fam, d, item("Disney", "v1")).unwrap();
    alice.share_vault(&fam, "bob", Role::Writer, None).unwrap();
    bob.sync().unwrap();

    // Alice edits an item; bob, who hasn't seen that, edits it too...
    alice.put_item(&fam, n, item("Netflix", "alice-v2")).unwrap();
    bob.put_item(&fam, n, item("Netflix", "bob-v2")).unwrap();
    // ...and deletes one she has just edited.
    alice.put_item(&fam, d, item("Disney", "alice-v2")).unwrap();
    bob.delete_item(&fam, d).unwrap();
    alice.sync().unwrap();
    let v = &alice.vaults[&fam];
    let mut netflix: Vec<_> = v.items().filter(|(_, i)| i.title.starts_with("Netflix")).map(|(_, i)| i.password.as_str()).collect();
    netflix.sort();
    assert_eq!(v.get(&d).map(|i| i.password.as_str()), Some("alice-v2"), "alice's edit brings Disney back");
    assert_eq!(netflix, ["alice-v2", "bob-v2"], "alice's edit is kept as a conflict copy");
}

#[test]
fn a_vault_no_longer_listed_can_drop_its_unsent_changes() {
    let (url, path) = server();
    let (ask, mut alice) = join(Http::new(&url), "alice", "alice pw", Some("first-run-code"), "laptop");
    let code = alice.invite().unwrap();
    let (_, mut bob) = join(Flaky(Http::new(&url), Default::default(), Default::default()), "bob", "bob pw", Some(&code), "phone");
    alice.sync().unwrap();
    let fam = alice.create_vault("Family").unwrap();
    let (nid, did) = (plaintext_core::new_item_id(), plaintext_core::new_item_id());
    alice.put_item(&fam, nid, item("Netflix", "n3tfl1x-pass")).unwrap();
    alice.put_item(&fam, did, item("Disney", "d1sney")).unwrap();
    alice.share_vault(&fam, "bob", Role::Writer, None).unwrap();
    bob.sync().unwrap();

    // Offline, bob edits, deletes and adds; meanwhile alice removes him.
    bob.t.1.set(true);
    let offline = |r: Result<()>| assert!(matches!(r, Err(Error::Network(_))), "{r:?}");
    offline(bob.put_item(&fam, nid, item("Netflix", "edited offline")));
    offline(bob.delete_item(&fam, did));
    offline(bob.put_item(&fam, plaintext_core::new_item_id(), item("Offline", "o")));
    bob.t.1.set(false);
    alice.revoke(&fam, "bob").unwrap();
    bob.sync().unwrap();
    assert!(bob.hidden.contains_key(&fam) && !bob.vaults.contains_key(&fam));
    // The CLI turns `unsendable` into its `vault reset` hint.
    let warned = |s: &Session<Flaky>| s.unsendable == [fam] && s.problems.iter().any(|p| p.unsent == Some(fam) && p.contains("Family isn't listed"));
    assert!(warned(&bob), "{:?}", bob.problems);
    bob.sync().unwrap();
    assert!(warned(&bob), "every sync says so");
    // Only the reset looks among vaults the server stopped listing.
    assert!(bob.vault("Family").is_err());
    assert_eq!(bob.vault_or_hidden(&fam.to_string()[..8]).unwrap(), fam);
    assert_eq!(bob.vault_or_hidden("family").unwrap(), fam);
    assert_eq!(bob.vault_or_hidden(&fam.to_string()).unwrap(), fam);
    // The apps' drop asks the server first: offline, or shared again since, it drops nothing.
    assert!(bob.unsendable_changes(&fam).unwrap().1);
    bob.t.1.set(true);
    assert!(matches!(bob.discard_unsendable(&fam), Err(Error::Network(_))));
    bob.t.1.set(false);
    alice.share_vault(&fam, "bob", Role::Reader, None).unwrap();
    assert!(matches!(bob.discard_unsendable(&fam), Err(Error::Refused(_))));
    assert_eq!(bob.hidden[&fam].changes(), 3);
    alice.revoke(&fam, "bob").unwrap();
    assert_eq!(bob.discard_unsendable(&fam).unwrap(), 3);
    assert!(bob.unsendable.is_empty() && bob.problems.is_empty(), "{:?}", bob.problems);
    assert_eq!(bob.discard_changes(&fam).unwrap(), 0);
    bob.sync().unwrap();
    assert!(bob.problems.is_empty(), "{:?}", bob.problems);
    assert!(bob.hidden[&fam].counter > 0, "the rollback guard stays");

    // Shared again, he gets the vault as the server has it; nothing he dropped reaches alice.
    alice.share_vault(&fam, "bob", Role::Writer, None).unwrap();
    bob.sync().unwrap();
    assert!(bob.problems.is_empty(), "{:?}", bob.problems);
    let v = &bob.vaults[&fam];
    assert_eq!(v.get(&nid).unwrap().password, "n3tfl1x-pass");
    assert!(v.get(&did).is_some());
    assert_eq!(v.items().count(), 2);
    bob.put_item(&fam, plaintext_core::new_item_id(), item("Later", "l")).unwrap();
    alice.sync().unwrap();
    let v = &alice.vaults[&fam];
    assert_eq!(v.get(&nid).unwrap().password, "n3tfl1x-pass");
    assert!(v.get(&did).is_some());
    assert!(v.items().any(|(_, i)| i.title == "Later") && !v.items().any(|(_, i)| i.title == "Offline"));

    // A vault the server merely hides (no new key, nothing resent) comes back
    // whole after a reset, and still can't be swapped for an older copy.
    let mut a2 = Session::login(evil(&url), &derive("alice pw", &ask), "tablet").unwrap();
    a2.sync().unwrap();
    let old = a2.t.inner.send("GET", &format!("/v1/vaults/{fam}?since=0&latest=true"), Some(&a2.token), None).unwrap().1;
    alice.put_item(&fam, nid, item("Netflix", "newer")).unwrap();
    a2.sync().unwrap();
    a2.t.hide.set(Some(fam));
    a2.sync().unwrap();
    let hidden = a2.hidden.get_mut(&fam).unwrap();
    hidden.put(nid, item("Netflix", "dropped"));
    hidden.delete(did);
    a2.sync().unwrap();
    assert!(a2.problems.iter().any(|p| p.contains("isn't listed")), "{:?}", a2.problems);
    assert_eq!(a2.discard_changes(&fam).unwrap(), 2);
    a2.t.hide.set(None);
    *a2.t.replay.borrow_mut() = Some((format!("/v1/vaults/{fam}?"), old));
    for _ in 0..2 {
        a2.sync().unwrap();
        assert!(a2.problems.iter().any(|p| p.contains("older or different copy")), "{:?}", a2.problems);
        assert!(!a2.vaults.contains_key(&fam) && a2.hidden[&fam].counter > 0, "the guard survives a refused copy");
    }
    *a2.t.replay.borrow_mut() = None;
    a2.sync().unwrap();
    assert!(a2.problems.is_empty(), "{:?}", a2.problems);
    let (mine, theirs) = (&a2.vaults[&fam], &alice.vaults[&fam]);
    assert_eq!(mine.get(&nid).unwrap().password, "newer");
    assert!(mine.get(&did).is_some());
    assert_eq!(mine.items().count(), theirs.items().count());
    assert!(mine.same_head(theirs));
    let _ = std::fs::remove_file(&path);
}


/// A transport whose network can be switched off, or a GET answered with an old reply.
struct Flaky(Http, std::cell::Cell<bool>, std::cell::RefCell<Option<(String, Vec<u8>)>>);

impl Transport for Flaky {
    fn send(&self, method: &str, path: &str, token: Option<&str>, body: Option<Vec<u8>>) -> Result<(u16, Vec<u8>)> {
        if self.1.get() {
            return Err(Error::Network("offline".into()));
        }
        if let Some((p, bytes)) = &*self.2.borrow()
            && method == "GET"
            && path == p
        {
            return Ok((200, bytes.clone()));
        }
        self.0.send(method, path, token, body)
    }
    fn host(&self) -> String {
        self.0.host()
    }
}

#[test]
fn restored_session_catches_up_with_the_keyring() {
    let (url, _db) = server_with(Default::default());
    let (sk, a) = join(Http::new(&url), "alice", "pw", None, "a");
    let old = a.keyring_snapshot();
    // Another device changes the keyring meanwhile.
    login(&url, "pw", &sk).invite().unwrap();
    let account = Account { id: a.account.id, account_key: a.account.account_key.clone() };
    let mut r = Session::restore(Http::new(&url), a.token.clone(), account, &old).unwrap();
    assert!(r.keyring.invites.is_empty(), "opened from this device's copy, offline");
    r.sync().unwrap();
    assert_eq!(r.keyring.invites.len(), 1);
    let bad = Account { id: a.account.id, account_key: zeroize::Zeroizing::new([7; 32]) };
    assert!(Session::restore(Http::new(&url), a.token.clone(), bad, &old).is_err());
}

#[test]
fn restored_session_pushes_pins_it_never_sent() {
    let (url, _db) = server_with(Default::default());
    let (sk, a) = join(Http::new(&url), "alice", "pw", None, "a");
    // This device pulled its vault and made a pin, and neither reached the server: its keyring counter is still 0.
    let id = a.call::<AccountResponse>("GET", "/v1/account", NONE).unwrap().vaults[0];
    let mut a = a;
    a.vaults.insert(id, Vault::new(id));
    block_on(a.pull_async(&id)).unwrap();
    a.keyring.new_invite();
    assert_eq!(a.call::<AccountResponse>("GET", "/v1/account", NONE).unwrap().keyring_counter, 0);
    // Picked up again as the browser extension does: the keyring and the vault from this device.
    let account = Account { id: a.account.id, account_key: a.account.account_key.clone() };
    let mut r = Session::restore(Http::new(&url), a.token.clone(), account, &a.keyring_snapshot()).unwrap();
    r.vaults.insert(id, Vault::restore(&r.account, id, &a.vaults[&id].snapshot(&a.account)).unwrap());
    r.sync().unwrap();
    assert_eq!(login(&url, "pw", &sk).keyring.invites.len(), 1, "the restored pin reached the server");
}

#[test]
fn restored_session_saves_its_keyring_before_any_sync() {
    let (url, _db) = server_with(Default::default());
    let (sk, mut a) = join(Http::new(&url), "alice", "pw", None, "a");
    // A pin this device never sent, and another device's pin the restored copy doesn't have.
    a.keyring.new_invite();
    login(&url, "pw", &sk).invite().unwrap();
    let account = Account { id: a.account.id, account_key: a.account.account_key.clone() };
    let mut r = Session::restore(Http::new(&url), a.token.clone(), account, &a.keyring_snapshot()).unwrap();
    r.invite().unwrap();
    assert_eq!(r.keyring.invites.len(), 3);
    assert_eq!(login(&url, "pw", &sk).keyring.invites.len(), 3, "all three pins are on the server");
}

/// What an app keeps on the device: snapshots that survive a restart (with the
/// rollback guard), an offline open that queues edits, and imports.
#[test]
fn device_state_offline_and_import() {
    let (url, path) = server();
    let dir = std::env::temp_dir().join(format!("plaintext-local-{}", hex::encode(plaintext_core::crypto::random::<8>())));
    let (sk, alice) = Session::signup(Http::new(&url), "alice", "alice pw", Some("first-run-code"), "phone").unwrap();
    let mut alice = alice.unwrap();
    alice.sync().unwrap();
    let mine = alice.default_vault().unwrap();
    assert_eq!(alice.import(import::onepux(&import::tests::onepux_fixture()).unwrap(), None).unwrap().items, 8);
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
    again.sync().unwrap();
    assert!(again.problems.iter().any(|p| p.contains("older or different copy")), "{:?}", again.problems);

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

/// Leaving a vault the server stopped listing drops this device's unsent changes
/// to it too, so sync stops reporting them.
#[test]
fn leaving_an_unlisted_vault_drops_its_unsent_changes() {
    let (url, path) = server_with(plaintext_server::Config { open_signup: true, quota: Some(64 << 20), ..Default::default() });
    let (_, mut alice) = join(Http::new(&url), "alice", "alice pw", None, "t");
    let (_, mut bob) = join(evil(&url), "bob", "bob pw", None, "t");
    let fam = alice.create_vault("Family").unwrap();
    alice.share_vault(&fam, "bob", Role::Owner, None).unwrap();
    alice.leave_vault(&fam).unwrap();
    bob.sync().unwrap();
    bob.vaults.get_mut(&fam).unwrap().put(plaintext_core::new_item_id(), item("Unsent", "x"));
    bob.t.hide.set(Some(fam));
    bob.sync().unwrap();
    assert!(bob.problems.iter().any(|p| p.contains("isn't listed for you any more")), "{:?}", bob.problems);
    // The one that offers to leave comes first, for an app's one-problem banner.
    assert!(bob.problems[0].leave == Some(fam), "{:?}", bob.problems);

    bob.leave_vault(&fam).unwrap();
    assert!(!bob.hidden[&fam].has_changes() && bob.unsendable.is_empty() && bob.problems.is_empty(), "{:?}", bob.problems);
    bob.t.hide.set(None);
    bob.sync().unwrap();
    assert!(bob.problems.is_empty(), "{:?}", bob.problems);
    let _ = std::fs::remove_file(&path);
}
