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
    let db = plaintext_server::open_db(path.to_str().unwrap()).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            tx.send(l.local_addr().unwrap()).unwrap();
            axum::serve(l, plaintext_server::app(db, cfg)).await.unwrap();
        });
    });
    (format!("http://{}", rx.recv().unwrap()), path)
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
