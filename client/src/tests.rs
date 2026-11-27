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

    fn host(&self) -> String {
        self.inner.host()
    }
}

fn evil(url: &str) -> Evil {
    Evil { inner: Http::new(url), old_keyring: Default::default(), hide: Default::default(), replay: Default::default() }
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
    a3.t.hide.set(None);
    *a3.t.replay.borrow_mut() = Some((format!("/v1/vaults/{mine}?"), old));
    // Caught and reported; the vault keeps its last verified state.
    a3.sync().unwrap();
    assert!(a3.problems.iter().any(|p| p.contains("older or different copy")), "{:?}", a3.problems);
    assert!(a3.vaults[&mine].items().any(|(_, i)| i.password == "added-later"));
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
    carol.pin_user("dave").unwrap();
    assert!(matches!(carol.pin_user("nobody"), Err(Error::NotFound(_))));
    // Anyone may invite there; the invitee is visible to (and verified by) the inviter.
    let code = carol.invite().unwrap();
    let (_, erin) = join(Http::new(&url), "erin", "erin pw", Some(&code), "t");
    assert!(erin.keyring.contacts["carol"].verified);
    carol.sync().unwrap();
    assert_eq!(carol.users().unwrap().len(), 1);
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
    // Over the quota, a promotion and removing someone (a new key) still work;
    // adding someone doesn't.
    alice.share_vault(&personal, "bob", Role::Owner, None).unwrap();
    alice.revoke(&personal, "bob").unwrap();
    assert_eq!(status(alice.share_vault(&personal, "bob", Role::Reader, None)), 507);

    // Deleting an item deletes its attachment too, which makes room.
    alice.delete_item(&personal, id).unwrap();
    assert_eq!(status(alice.download_file(&personal, &big)), 404);
    let acct: AccountResponse = alice.call("GET", "/v1/account", NONE).unwrap();
    assert!(acct.usage < 20_000, "{}", acct.usage);
    alice.upload_file(&personal, "small.pdf", &vec![1u8; 100_000]).unwrap();
    alice.share_vault(&personal, "bob", Role::Reader, None).unwrap();
    bob.sync().unwrap();
    assert_eq!(stage(&bob, &personal, st, 100), 403, "readers can't stage");
    // Being out of storage doesn't stop anyone deleting their account.
    bob.delete_account(&derive("bob pw", &bsk)).unwrap();
    let _ = std::fs::remove_file(&path);
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
    let stale = VaultPut { upserts: vec![], staged: Some(Staged { id: a, count: 1 }), ..put };
    assert_eq!(status(alice.call::<()>("PUT", &format!("/v1/vaults/{personal}"), Some(&stale))), 409);
    assert_eq!(count(&path, "SELECT COUNT(*) FROM staged"), 0, "a failed push drops what its member staged");
    alice.sync_vault(&personal).unwrap();
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
    // A creator who leaves hands the vault to an owner who stays.
    let club = carol.create_vault("Club").unwrap();
    carol.share_vault(&club, "alice", Role::Owner, None).unwrap();
    carol.leave_vault(&club).unwrap();
    assert_eq!(count(&path, "SELECT COUNT(*) FROM vaults WHERE creator = 'alice'"), 3);

    // An owner leaves rather than taking themselves out of the roster.
    assert_eq!(status(alice.revoke(&fam, "alice")), 400);
    // The only owner can't leave a vault others use.
    let gift = bob.create_vault("Gift").unwrap();
    bob.share_vault(&gift, "carol", Role::Reader, None).unwrap();
    assert_eq!(status(bob.leave_vault(&gift)), 409);
    // Bob makes carol an owner and deletes his account: the vault now counts
    // against carol, who can leave it, which deletes it.
    bob.share_vault(&gift, "carol", Role::Owner, None).unwrap();
    bob.delete_account(&derive("bob pw", &bsk)).unwrap();
    assert_eq!(count(&path, "SELECT COUNT(*) FROM vaults WHERE creator = 'carol'"), 2);
    carol.sync().unwrap();
    carol.leave_vault(&gift).unwrap();
    assert_eq!(count(&path, "SELECT COUNT(*) FROM vaults WHERE creator = 'carol'"), 1);
    assert_eq!(count(&path, "SELECT COUNT(*) FROM vaults"), 4, "alice's three and carol's own");
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
    short.ttl = Some(1);
    let token = call::<_, LoginResponse>(&Http::new(&url), "POST", "/v1/login", None, Some(&short)).unwrap().token;
    assert_eq!(status(call::<_, AccountResponse>(&Http::new(&url), "GET", "/v1/account", Some(&token), NONE)), 200);
    std::thread::sleep(std::time::Duration::from_millis(2100));
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
