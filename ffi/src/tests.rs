//! The app API end to end over real HTTP, the way the iPhone and Mac apps use it.

use super::*;
use plaintext_client::Problem;

fn server() -> String {
    server_with(plaintext_server::Config { setup_code: Some("setup-code".into()), ..Default::default() })
}

fn server_with(cfg: plaintext_server::Config) -> String {
    let path = std::env::temp_dir().join(format!("plaintext-ffi-{}.db", hex::encode(core::crypto::random::<8>())));
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

/// The 1PUX fixture zipped the way 1Password exports it.
fn onepux_fixture() -> Vec<u8> {
    use std::io::Write;
    let mut buf = std::io::Cursor::new(Vec::new());
    let mut z = zip::ZipWriter::new(&mut buf);
    let o = zip::write::SimpleFileOptions::default();
    z.start_file("export.attributes", o).unwrap();
    z.write_all(br#"{"version":3,"description":"1Password Unencrypted Export","createdAt":1700000000}"#).unwrap();
    z.start_file("files/oakiw7lqbp53fgqrxrk63su2gu__keepassxc.png", o).unwrap();
    z.write_all(b"\x89PNG logo").unwrap();
    z.start_file("export.data", o).unwrap();
    z.write_all(include_bytes!("../../client/tests/fixtures/export.data")).unwrap();
    z.finish().unwrap();
    buf.into_inner()
}

fn app() -> (PlaintextApp, PathBuf) {
    let dir = std::env::temp_dir().join(format!("plaintext-app-{}", hex::encode(core::crypto::random::<8>())));
    (PlaintextApp::new(dir.to_string_lossy().into(), "test".into()), dir)
}

#[test]
fn formats_round_trip() {
    let sk = SecretKey::generate().encode();
    let code = device_code("https://vault.example.com:8443".into(), "alice.b".into(), sk.to_lowercase());
    assert_eq!(parse_device_code(code), Some(DeviceCode { server: "https://vault.example.com:8443".into(), username: "alice.b".into(), secret_key: sk.clone() }));
    assert_eq!(parse_device_code("plaintext:device:alice:A1-nope:https://x".into()), None);
    assert_eq!(parse_device_code(device_code("http://evil.example".into(), "alice".into(), sk.clone())), None, "no plain http to public hosts");
    assert!(parse_device_code(device_code("http://192.168.1.5:8080".into(), "alice".into(), sk.clone())).is_some());
    let link = invite_link("http://10.0.0.2:8080".into(), "ab.cd.alice.123456".into());
    assert_eq!(parse_invite_link(link), Some(InviteLink { server: Some("http://10.0.0.2:8080".into()), code: "ab.cd.alice.123456".into() }));
    assert_eq!(parse_invite_link(" setup-code ".into()).unwrap().code, "setup-code");
    let t = item_template("card".into());
    assert!(t.sections[0].fields.iter().any(|f| f.label == "Number" && f.kind == "card_number"));
    assert_eq!(item_kinds()[0].id, "login");
    let totp = totp_code("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=60".into()).unwrap();
    assert_eq!((totp.code.len(), totp.period), (6, 60));
    assert!(password_strength("hunter2".into()).level == 0 && password_strength(generate_password(Recipe::Random { length: 20, digits: true, symbols: true })).level == 3);
}

#[test]
fn server_addresses() {
    let ok = |a: &str, url: &str, insecure: bool| assert_eq!(server_address(a.into()).unwrap(), ServerAddress { url: url.into(), insecure }, "{a}");
    ok("vault.example.com", "https://vault.example.com", false);
    ok(" HTTPS://Vault.Example.com:8443/ ", "https://vault.example.com:8443", false);
    ok("http://localhost:7878", "http://localhost:7878", true);
    ok("http://192.168.1.20", "http://192.168.1.20", true);
    ok("http://100.101.102.103:8080", "http://100.101.102.103:8080", true);
    ok("http://nas.local", "http://nas.local", true);
    ok("http://vault.tail1234.ts.net", "http://vault.tail1234.ts.net", true);
    ok("http://[::1]:7878", "http://[::1]:7878", true);
    ok("203.0.113.5:8443", "https://203.0.113.5:8443", false);
    for bad in ["http://vault.example.com", "http://8.8.8.8", "ftp://x", "", "user@host", "two words"] {
        assert!(server_address(bad.into()).is_err(), "{bad}");
    }
}

#[test]
fn app_end_to_end() {
    let url = server();
    assert_eq!(server_info(format!("{url}/")).unwrap(), ServerInfo { version: server_info(url.clone()).unwrap().version, open: false, setup: true });
    assert!(matches!(server_info("http://127.0.0.1:9".into()), Err(PlaintextError::Network { .. })));

    // Signup with the setup code; the account and its default vault are ready.
    let (alice, adir) = app();
    let r = alice.signup(url.clone(), "alice".into(), "alice pw".into(), Some("setup-code".into())).unwrap();
    let a = r.account.id.clone();
    assert!(r.account.admin && !r.account.pending && r.account.username == "alice");
    assert!(!server_info(url.clone()).unwrap().setup);
    let personal = alice.vaults().into_iter().find(|v| v.is_default).unwrap().id;

    // A login with a field carrying properties from a newer app: edits keep them.
    let mut login = item_template("login".into());
    login.title = "GitHub".into();
    login.username = "alice".into();
    login.password = "first-password-123".into();
    login.sections = vec![SectionData {
        title: "Extra".into(),
        fields: vec![FieldData { label: "Recovery".into(), kind: "concealed".into(), value: "r-code".into(), extra_json: r#"{"future":1}"#.into() }],
    }];
    let id = alice.put_item(a.clone(), personal.clone(), None, login).unwrap();
    let mut edit = alice.item(a.clone(), personal.clone(), id.clone()).unwrap();
    assert_eq!(edit.sections[0].fields[0].extra_json, r#"{"future":1}"#);
    edit.password = "second-password-456".into();
    alice.put_item(a.clone(), personal.clone(), Some(id.clone()), edit).unwrap();
    let got = alice.item(a.clone(), personal.clone(), id.clone()).unwrap();
    assert_eq!((got.password_history.len(), got.history.len()), (1, 1));
    assert_eq!(got.sections[0].fields[0].extra_json, r#"{"future":1}"#);
    alice.set_flags(a.clone(), personal.clone(), id.clone(), true, false).unwrap();
    assert_eq!(alice.item(a.clone(), personal.clone(), id.clone()).unwrap().history.len(), 1, "favoriting makes no version");
    alice.keep_password(a.clone(), personal.clone(), id.clone(), "generated-789".into()).unwrap();
    let kept = alice.item(a.clone(), personal.clone(), id.clone()).unwrap();
    assert_eq!((kept.password.as_str(), kept.password_history[0].password.as_str()), ("second-password-456", "generated-789"));
    assert_eq!(kept.history.len(), 1, "keeping a password makes no version");
    alice.restore_version(a.clone(), personal.clone(), id.clone(), 0).unwrap();
    assert_eq!(alice.item(a.clone(), personal.clone(), id.clone()).unwrap().password, "first-password-123");
    assert_eq!(alice.items(None, None, "git".into(), false).len(), 1);
    assert!(alice.items(None, None, "first-password".into(), false).is_empty(), "search never matches secrets");

    // Attachments, and moving an item re-encrypts them for the new vault.
    let stale = alice.item(a.clone(), personal.clone(), id.clone()).unwrap();
    alice.attach_file(a.clone(), personal.clone(), id.clone(), "codes.txt".into(), b"recovery codes".to_vec()).unwrap();
    alice.attach_file(a.clone(), personal.clone(), id.clone(), "../../evil.plist".into(), b"x".to_vec()).unwrap();
    // An editor opened before the attach saves: the files stay.
    alice.put_item(a.clone(), personal.clone(), Some(id.clone()), stale).unwrap();
    let files = alice.item(a.clone(), personal.clone(), id.clone()).unwrap().files;
    assert_eq!(files.len(), 2, "an edit keeps files attached meanwhile");
    assert!(!files[1].name.contains('/'), "{}", files[1].name);
    alice.remove_file(a.clone(), personal.clone(), id.clone(), files[1].id.clone()).unwrap();
    assert_eq!(alice.item(a.clone(), personal.clone(), id.clone()).unwrap().files.len(), 1);
    let work = alice.create_vault(a.clone(), "Work".into()).unwrap();
    let moved = alice.move_item(a.clone(), personal.clone(), id.clone(), a.clone(), work.clone()).unwrap();
    let f = alice.item(a.clone(), work.clone(), moved.clone()).unwrap().files[0].id.clone();
    assert_eq!(alice.download_file(a.clone(), work.clone(), moved.clone(), f).unwrap(), b"recovery codes");

    // 1PUX import.
    assert_eq!(alice.import_items(a.clone(), ImportFormat::OnePux, onepux_fixture(), None).unwrap().items, 8);
    assert!(alice.vaults().iter().any(|v| v.name == "Shared"));

    // Invite bob with a link: both sides end up verified.
    let link = alice.invite(a.clone()).unwrap();
    let (bob, _) = app();
    let b = bob.signup(url.clone(), "bob".into(), "bob pw".into(), Some(link)).unwrap().account.id;
    alice.sync(a.clone()).unwrap();
    assert!(alice.is_verified(a.clone(), "bob".into()) && bob.is_verified(b.clone(), "alice".into()));
    alice.share_vault(a.clone(), work.clone(), "Bob".into(), Role::Writer, None).unwrap();
    bob.sync(b.clone()).unwrap();
    assert_eq!(bob.items(None, Some(work.clone()), "".into(), false)[0].title, "GitHub");
    // A vault bob can only view: his edits are refused instead of queueing forever.
    let view = alice.create_vault(a.clone(), "View".into()).unwrap();
    alice.share_vault(a.clone(), view.clone(), "bob".into(), Role::Reader, None).unwrap();
    bob.sync(b.clone()).unwrap();
    assert!(matches!(bob.put_item(b.clone(), view.clone(), None, item_template("login".into())), Err(PlaintextError::ReadOnly)));
    let members = alice.members(a.clone(), work.clone()).unwrap();
    assert!(members[0].is_me && members.iter().any(|m| m.username == "bob" && m.verified && m.role == Role::Writer));

    // A third user verifies alice by scanning her QR.
    let carol_invite = alice.invite(a.clone()).unwrap();
    let code = parse_invite_link(carol_invite).unwrap().code;
    let (carol, _) = app();
    let c = carol.signup(url.clone(), "carol".into(), "carol pw".into(), Some(code.split('.').take(2).collect::<Vec<_>>().join("."))).unwrap().account.id;
    assert!(!carol.is_verified(c.clone(), "alice".into()));
    assert_eq!(carol.verify_scanned(c.clone(), alice.my_verify_code(a.clone()).unwrap()).unwrap(), "alice");
    assert!(carol.is_verified(c.clone(), "alice".into()));
    assert!(matches!(carol.verify_scanned(c.clone(), format!("{VERIFY}bob:000000000000000000000000")), Err(PlaintextError::KeyChanged { .. })));
    assert!(!carol.acct(&c).unwrap().session.lock().unwrap().keyring.contacts.contains_key("bob"), "a mismatched scan pins nothing");

    // Inbox and links.
    alice.send_item(a.clone(), work.clone(), moved.clone(), "bob".into(), None).unwrap();
    let inbox = bob.inbox(b.clone()).unwrap();
    assert!(matches!(&inbox[0].content, InboxContent::Item { item } if item.title == "GitHub"));
    assert!(matches!(bob.save_from_inbox(b.clone(), inbox[0].id.clone(), Some(view.clone())), Err(PlaintextError::ReadOnly)));
    assert!(!bob.acct(&b).unwrap().session.lock().unwrap().vaults[&hex_id(&view).unwrap()].has_changes(), "a refused save queues nothing");
    bob.save_from_inbox(b.clone(), inbox[0].id.clone(), None).unwrap();
    assert!(bob.inbox(b.clone()).unwrap().is_empty());
    let link = alice.create_link(a.clone(), work.clone(), moved.clone(), "https://vault.family.org/s/".into(), 3600, true).unwrap();
    assert!(link.starts_with(&format!("https://vault.family.org/s/#{url}/")), "{link}");
    assert!(alice.create_link(a.clone(), work.clone(), moved.clone(), "".into(), 3600, true).unwrap().starts_with("https://getplaintext.org/s/#"));

    // An agent made from the app, and its request in the owner's inbox.
    let made = alice.create_agent(a.clone(), "Deploy-Bot".into(), work.clone(), Role::Reader, Some(now() + 3600)).unwrap();
    assert!(made.key.starts_with("ptk_") && made.warning.is_none());
    let agents = alice.agents(a.clone()).unwrap();
    assert_eq!((agents[0].name.as_str(), agents[0].access[0].role), ("deploy-bot", Role::Reader));

    // Restart: unlock from the keychain data, also with the server unreachable.
    alice.lock(false);
    assert!(!alice.is_unlocked() && alice.vaults().is_empty() && matches!(alice.sync(a.clone()), Err(PlaintextError::Locked)));
    alice.resume(url.clone(), r.unlock.clone()).unwrap();
    assert!(alice.items(None, None, "github".into(), false).len() == 1);
    alice.lock(false);
    alice.resume("http://127.0.0.1:9".into(), r.unlock.clone()).unwrap();
    assert_eq!(alice.items(None, Some(work.clone()), "".into(), false).len(), 1, "offline from the device's copies");
    // A move that can't reach the server leaves no copy in the target to go out later.
    let plain = alice.items(Some(a.clone()), Some(personal.clone()), "".into(), false).into_iter().find(|i| alice.item(a.clone(), personal.clone(), i.id.clone()).unwrap().files.is_empty()).unwrap();
    assert!(matches!(alice.move_item(a.clone(), personal.clone(), plain.id.clone(), a.clone(), work.clone()), Err(PlaintextError::Network { .. })));
    assert_eq!(alice.items(None, Some(work.clone()), "".into(), false).len(), 1);
    assert!(alice.item(a.clone(), personal.clone(), plain.id).is_ok());
    alice.set_flags(a.clone(), work.clone(), moved.clone(), false, true).unwrap();
    assert!(alice.accounts()[0].pending);
    alice.lock(false);
    alice.resume(url.clone(), r.unlock.clone()).unwrap();
    assert!(!alice.accounts()[0].pending, "the offline edit went out");
    bob.sync(b.clone()).unwrap();
    assert!(bob.items(None, Some(work.clone()), "".into(), true)[0].archived);

    // A new device signs in with the Secret Key; the wrong password says so.
    let (phone, _) = app();
    assert!(matches!(phone.login(url.clone(), r.secret_key.clone(), "nope".into()), Err(PlaintextError::WrongPassword)));
    let p = phone.login(url.clone(), r.secret_key.clone(), "alice pw".into()).unwrap().account.id;
    assert_eq!(p, a, "the same account");
    assert!(phone.is_verified(p.clone(), "bob".into()));
    assert_eq!(phone.sessions(p.clone()).unwrap().len(), 2, "the first device and this one");
    // Signed out by the server: forget keeps the device's copies; resume says so and stays locked.
    let unlock = phone.unlock_data(p.clone()).unwrap();
    phone.forget(p.clone());
    assert!(!phone.is_unlocked());
    phone.resume(url.clone(), unlock.clone()).unwrap();
    phone.lock(true);
    for _ in 0..50 {
        if alice.sessions(a.clone()).unwrap().len() == 1 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert_eq!(alice.sessions(a.clone()).unwrap().len(), 1, "locking with nothing to resume from ends the session");
    assert!(matches!(phone.resume(url.clone(), unlock), Err(PlaintextError::SignedOut)));
    assert!(!phone.is_unlocked());
    let p = phone.login(url.clone(), r.secret_key.clone(), "alice pw".into()).unwrap().account.id;
    phone.sign_out(p, url.clone(), None);
    assert!(!phone.is_unlocked());
    let _ = std::fs::remove_dir_all(adir);
}

/// One app with accounts on two servers: a family server and a hosted one.
#[test]
fn several_accounts() {
    let family = server();
    let hosted = server_with(plaintext_server::Config { open_signup: true, ..Default::default() });
    assert!(server_info(hosted.clone()).unwrap().open);
    let (operator, _) = app();
    operator.signup(hosted.clone(), "operator".into(), "op pw".into(), None).unwrap();
    let (app, dir) = app();
    let home = app.signup(family.clone(), "alice".into(), "family pw".into(), Some("setup-code".into())).unwrap();
    let cloud = app.signup(hosted.clone(), "alice".into(), "cloud pw".into(), None).unwrap();
    let (h, c) = (home.account.id.clone(), cloud.account.id.clone());
    assert_ne!(h, c);
    assert_eq!(app.accounts().iter().map(|a| a.server.clone()).collect::<Vec<_>>(), [family.clone(), hosted.clone()]);

    // Both accounts' vaults together, each account's default first.
    let vaults = app.vaults();
    assert_eq!(vaults.iter().map(|v| (v.account_id.clone(), v.is_default)).collect::<Vec<_>>(), [(h.clone(), true), (c.clone(), true)]);
    let mut it = item_template("login".into());
    it.title = "Router".into();
    app.put_item(h.clone(), vaults[0].id.clone(), None, it.clone()).unwrap();
    it.title = "Work mail".into();
    let mail = app.put_item(c.clone(), vaults[1].id.clone(), None, it).unwrap();
    assert_eq!(app.items(None, None, "".into(), false).len(), 2);
    assert_eq!(app.items(Some(c.clone()), None, "".into(), false)[0].title, "Work mail");

    // Moving an item to the other account re-encrypts it there.
    let moved = app.move_item(c.clone(), vaults[1].id.clone(), mail, h.clone(), vaults[0].id.clone()).unwrap();
    assert_eq!(app.item(h.clone(), vaults[0].id.clone(), moved).unwrap().title, "Work mail");
    assert!(app.items(Some(c.clone()), None, "".into(), false).is_empty());

    // On the hosted server nobody browses the customers, but your agents show up.
    assert!(app.users(c.clone()).unwrap().is_empty());
    app.create_agent(c.clone(), "ci".into(), vaults[1].id.clone(), Role::Reader, None).unwrap();
    assert_eq!(app.agents(c.clone()).unwrap()[0].name, "ci");
    // People are found by exact username, within one server.
    assert!(matches!(app.fingerprint(c.clone(), "nobody".into()), Err(PlaintextError::NotFound { .. })));

    // Locking forgets both; each unlocks from its own keychain entry. Signing
    // out of one leaves the other.
    app.lock(false);
    app.resume(family.clone(), home.unlock).unwrap();
    app.resume(hosted.clone(), cloud.unlock).unwrap();
    assert_eq!(app.items(None, None, "".into(), false).len(), 2);
    app.sign_out(c.clone(), String::new(), None);
    assert_eq!(app.accounts().len(), 1);
    assert!(app.vaults().iter().all(|v| v.account_id == h));
    let _ = std::fs::remove_dir_all(dir);
}

/// Leaving a vault, also one only a sync problem names: an owner who left
/// hands bob a vault that counts against his storage.
#[test]
fn leaving_a_vault() {
    let url = server_with(plaintext_server::Config { setup_code: Some("setup-code".into()), quota: Some(64 << 20), ..Default::default() });
    let (alice, _) = app();
    let a = alice.signup(url.clone(), "alice".into(), "alice pw".into(), Some("setup-code".into())).unwrap().account.id;
    let (bob, _) = app();
    let br = bob.signup(url.clone(), "bob".into(), "bob pw".into(), Some(alice.invite(a.clone()).unwrap())).unwrap();
    let (b, unlock) = (br.account.id, br.unlock);
    alice.sync(a.clone()).unwrap();

    // Alice is the only owner of a vault bob writes to: she's warned.
    let team = alice.create_vault(a.clone(), "Team".into()).unwrap();
    alice.share_vault(a.clone(), team.clone(), "bob".into(), Role::Writer, None).unwrap();
    let c = alice.leave_check(a.clone(), team.clone()).unwrap();
    assert!(c.only_owner && !c.unsent && c.name.as_deref() == Some("Team"));

    // She makes bob an owner and leaves; the vault now counts against him.
    alice.share_vault(a.clone(), team.clone(), "bob".into(), Role::Owner, None).unwrap();
    assert!(!alice.leave_check(a.clone(), team.clone()).unwrap().only_owner);
    alice.leave_vault(a.clone(), team.clone()).unwrap();
    assert!(alice.vaults().iter().all(|v| v.id != team));
    bob.sync(b.clone()).unwrap();
    let problems = bob.accounts()[0].problems.clone();
    assert!(problems.iter().any(|p| p.contains("counts against your storage, though alice created it")), "{problems:?}");
    assert_eq!(bob.accounts()[0].problem_vaults.iter().flatten().collect::<Vec<_>>(), [&team]);

    // He has a change to it that wasn't sent, and a problem about it that offers
    // no leave (as when the server stops listing it): he's warned of the change.
    let tid = hex_id(&team).unwrap();
    {
        let acct = bob.acct(&b).unwrap();
        let mut s = acct.session.lock().unwrap();
        s.vaults.get_mut(&tid).unwrap().put(core::new_item_id(), Item { title: "Unsent".into(), ..Default::default() });
        s.problems.push(Problem { text: "vault Team isn't listed for you any more".into(), leave: None, vault: Some(tid) });
        bob.persist(&acct, &s).unwrap();
    }
    let c = bob.leave_check(b.clone(), team.clone()).unwrap();
    assert!(!c.only_owner && c.unsent && c.name.as_deref() == Some("Team"));

    // Bob leaves it from the problem; nobody else uses it, so it's gone, with
    // the change and everything the last sync said about it.
    bob.leave_vault(b.clone(), team.clone()).unwrap();
    assert!(bob.accounts()[0].problems.is_empty() && bob.vaults().iter().all(|v| v.id != team));
    assert!(!bob.leave_check(b.clone(), team.clone()).unwrap().unsent);
    bob.sync(b.clone()).unwrap();
    assert!(bob.accounts()[0].problems.is_empty());

    // A vault only bob's agent is in: his device can't open it, so the problem
    // names it by id, and he leaves it by that id.
    let bob_default = bob.vaults().into_iter().find(|v| v.is_default).unwrap().id;
    bob.create_agent(b.clone(), "bob-bot".into(), bob_default, Role::Reader, None).unwrap();
    let gift = alice.create_vault(a.clone(), "Gift".into()).unwrap();
    alice.share_vault(a.clone(), gift.clone(), "bob-bot".into(), Role::Owner, None).unwrap();
    alice.leave_vault(a.clone(), gift.clone()).unwrap();
    bob.sync(b.clone()).unwrap();
    let problems = bob.accounts()[0].problems.clone();
    assert!(problems.len() == 1 && problems[0].contains("only an agent of yours is in it"), "{problems:?}");
    assert_eq!(bob.accounts()[0].problem_vaults, [Some(gift.clone())]);
    let c = bob.leave_check(b.clone(), gift.clone()).unwrap();
    assert!(c.name.is_none() && !c.only_owner && !c.unsent);

    // A server's error text can carry a hint of its own: only sync's choice of
    // vault counts, and never one of your own. Leaving the vault it names leaves
    // the problem alone.
    {
        let acct = bob.acct(&b).unwrap();
        let mut s = acct.session.lock().unwrap();
        s.problems.push(Problem { text: format!("vault Personal wasn't updated: server said 404: x (plaintext vault leave {gift} if you don't want it)"), leave: None, vault: None });
        bob.persist(&acct, &s).unwrap();
    }
    assert_eq!(bob.accounts()[0].problem_vaults, [Some(gift.clone()), None]);
    bob.leave_vault(b.clone(), gift.clone()).unwrap();
    assert_eq!(bob.accounts()[0].problem_vaults, [None]);
    assert!(bob.accounts()[0].problems[0].starts_with("vault Personal wasn't updated"));
    bob.sync(b.clone()).unwrap();
    assert!(bob.accounts()[0].problems.is_empty(), "{:?}", bob.accounts()[0].problems);
    // Still gone after a restart, from the device's copy.
    bob.lock(false);
    bob.resume(url.clone(), unlock).unwrap();
    assert!(bob.vaults().iter().all(|v| v.id != gift && v.id != team));
}

/// DESIGN "Signing in with a security key": the app opens the approval page,
/// then finishes; the device isn't asked again.
#[test]
fn security_key_sign_in() {
    use plaintext_client::plaintext_core::api::{B64, SigninKeyAction};
    let url = server();
    let (laptop, _dir) = app();
    let r = laptop.signup(url.clone(), "alice".into(), "pw".into(), Some("setup-code".into())).unwrap();
    let sk = SecretKey::parse(&r.secret_key).unwrap();
    let d = derive("pw", &sk);
    let cli = Session::login(Http::new(&url), &d, "cli").unwrap();
    let rp = core::crypto::rp_id(&Http::new(&url).host());
    let mut key = plaintext_server::SoftKey::new();
    let ts = now_ms();
    let proof = key.assert(&rp, &core::crypto::signin_key_add_challenge(&d.account_id, ts), &url);
    let codes = cli.change_signin_keys(&d, ts, &SigninKeyAction::Add { name: "blue".into(), rp_id: rp.clone(), registration: B64(key.register(&rp)), proof }).unwrap().codes;

    let (phone, _pdir) = app();
    assert!(matches!(phone.login(url.clone(), r.secret_key.clone(), "pw".into()), Err(PlaintextError::KeyNeeded)));
    let page = phone.pending_key_page().unwrap();
    let c = page.rsplit_once('#').unwrap().1.to_string();
    assert!(page.starts_with(&format!("{url}/v1/login/key#")));
    assert!(matches!(phone.finish_login(None), Err(PlaintextError::Invalid { .. })), "not approved yet");
    assert!(matches!(phone.finish_login(Some("nope".into())), Err(PlaintextError::Invalid { .. })));
    let challenge = hex::decode(&c).unwrap();
    let a = serde_json::to_vec(&key.assert(&rp, &challenge, &url)).unwrap();
    assert_eq!(Http::new(&url).send("POST", &format!("/v1/login/approve/{c}"), None, Some(a)).unwrap().0, 204);
    assert_eq!(phone.finish_login(None).unwrap().account.username, "alice");
    assert!(phone.pending_key_page().is_none());
    // Remembered: the next sign-in here needs no key.
    phone.login(url.clone(), r.secret_key.clone(), "pw".into()).unwrap();
    // Another device uses a recovery code.
    let (tablet, _tdir) = app();
    assert!(matches!(tablet.login(url.clone(), r.secret_key.clone(), "pw".into()), Err(PlaintextError::KeyNeeded)));
    tablet.finish_login(Some(codes[0].clone())).unwrap();
}
