//! The app API end to end over real HTTP, the way the iPhone and Mac apps use it.

use super::*;

fn server() -> String {
    let path = std::env::temp_dir().join(format!("plaintext-ffi-{}.db", hex::encode(core::crypto::random::<8>())));
    let db = plaintext_server::open_db(path.to_str().unwrap()).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            tx.send(l.local_addr().unwrap()).unwrap();
            axum::serve(l, plaintext_server::app(db, Some("setup-code".into()))).await.unwrap();
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
    assert_eq!(parse_device_code(code), Some(DeviceCode { server: "https://vault.example.com:8443".into(), username: "alice.b".into(), secret_key: sk }));
    assert_eq!(parse_device_code("plaintext:device:alice:A1-nope:https://x".into()), None);
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
fn app_end_to_end() {
    let url = server();
    check_server(format!("{url}/")).unwrap();
    assert!(matches!(check_server("http://127.0.0.1:9".into()), Err(PlaintextError::Network { .. })));

    // Signup with the setup code; the account and its default vault are ready.
    let (alice, adir) = app();
    let r = alice.signup(url.clone(), "alice".into(), "alice pw".into(), Some("setup-code".into())).unwrap();
    let info = alice.account().unwrap();
    assert!(info.admin && !info.pending);
    let personal = alice.vaults().unwrap().into_iter().find(|v| v.is_default).unwrap().id;

    // A login with a field carrying properties from a newer app: edits keep them.
    let mut login = item_template("login".into());
    login.title = "GitHub".into();
    login.username = "alice".into();
    login.password = "first-password-123".into();
    login.sections = vec![SectionData {
        title: "Extra".into(),
        fields: vec![FieldData { label: "Recovery".into(), kind: "concealed".into(), value: "r-code".into(), extra_json: r#"{"future":1}"#.into() }],
    }];
    let id = alice.put_item(personal.clone(), None, login).unwrap();
    let mut edit = alice.item(personal.clone(), id.clone()).unwrap();
    assert_eq!(edit.sections[0].fields[0].extra_json, r#"{"future":1}"#);
    edit.password = "second-password-456".into();
    alice.put_item(personal.clone(), Some(id.clone()), edit).unwrap();
    let got = alice.item(personal.clone(), id.clone()).unwrap();
    assert_eq!((got.password_history.len(), got.history.len()), (1, 1));
    assert_eq!(got.sections[0].fields[0].extra_json, r#"{"future":1}"#);
    alice.set_flags(personal.clone(), id.clone(), true, false).unwrap();
    assert_eq!(alice.item(personal.clone(), id.clone()).unwrap().history.len(), 1, "favoriting makes no version");
    alice.restore_version(personal.clone(), id.clone(), 0).unwrap();
    assert_eq!(alice.item(personal.clone(), id.clone()).unwrap().password, "first-password-123");
    assert_eq!(alice.items(None, "git".into(), false).len(), 1);
    assert!(alice.items(None, "first-password".into(), false).is_empty(), "search never matches secrets");

    // Attachments, and moving an item re-encrypts them for the new vault.
    alice.attach_file(personal.clone(), id.clone(), "codes.txt".into(), b"recovery codes".to_vec()).unwrap();
    let work = alice.create_vault("Work".into()).unwrap();
    let moved = alice.move_item(personal.clone(), id.clone(), work.clone()).unwrap();
    let f = alice.item(work.clone(), moved.clone()).unwrap().files[0].id.clone();
    assert_eq!(alice.download_file(work.clone(), moved.clone(), f).unwrap(), b"recovery codes");

    // 1PUX import.
    assert_eq!(alice.import_items(ImportFormat::OnePux, onepux_fixture(), None).unwrap(), 8);
    assert!(alice.vaults().unwrap().iter().any(|v| v.name == "Shared"));

    // Invite bob with a link: both sides end up verified.
    let link = alice.invite().unwrap();
    let (bob, _) = app();
    bob.signup(url.clone(), "bob".into(), "bob pw".into(), Some(link)).unwrap();
    alice.sync().unwrap();
    assert!(alice.is_verified("bob".into()) && bob.is_verified("alice".into()));
    alice.share_vault(work.clone(), "bob".into(), Role::Writer, None).unwrap();
    bob.sync().unwrap();
    assert_eq!(bob.items(Some(work.clone()), "".into(), false)[0].title, "GitHub");
    let members = alice.members(work.clone()).unwrap();
    assert!(members[0].is_me && members.iter().any(|m| m.username == "bob" && m.verified && m.role == Role::Writer));

    // A third user verifies alice by scanning her QR.
    let carol_invite = alice.invite().unwrap();
    let code = parse_invite_link(carol_invite).unwrap().code;
    let (carol, _) = app();
    carol.signup(url.clone(), "carol".into(), "carol pw".into(), Some(code.split('.').take(2).collect::<Vec<_>>().join("."))).unwrap();
    assert!(!carol.is_verified("alice".into()));
    assert_eq!(carol.verify_scanned(alice.my_verify_code().unwrap()).unwrap(), "alice");
    assert!(carol.is_verified("alice".into()));
    assert!(matches!(carol.verify_scanned(format!("{VERIFY}bob:000000000000000000000000")), Err(PlaintextError::KeyChanged { .. })));

    // Inbox and links.
    alice.send_item(work.clone(), moved.clone(), "bob".into(), None).unwrap();
    let inbox = bob.inbox().unwrap();
    assert!(matches!(&inbox[0].content, InboxContent::Item { item } if item.title == "GitHub"));
    bob.save_from_inbox(inbox[0].id.clone(), None).unwrap();
    assert!(bob.inbox().unwrap().is_empty());
    assert!(alice.create_link(work.clone(), moved.clone(), 3600, true).unwrap().starts_with("https://getplaintext.org/s/#"));

    // An agent made from the app, and its request in the owner's inbox.
    let key = alice.create_agent("Deploy-Bot".into(), work.clone(), Role::Reader, Some(now() + 3600)).unwrap();
    assert!(key.starts_with("ptk_"));
    let agents = alice.agents().unwrap();
    assert_eq!((agents[0].name.as_str(), agents[0].access[0].role), ("deploy-bot", Role::Reader));

    // Restart: unlock from the keychain data, also with the server unreachable.
    alice.lock();
    assert!(matches!(alice.account(), Err(PlaintextError::Locked)));
    alice.resume(url.clone(), r.unlock.clone()).unwrap();
    assert!(alice.items(None, "github".into(), false).len() == 1);
    alice.lock();
    alice.resume("http://127.0.0.1:9".into(), r.unlock.clone()).unwrap();
    assert_eq!(alice.items(Some(work.clone()), "".into(), false).len(), 1, "offline from the device's copies");
    alice.set_flags(work.clone(), moved.clone(), false, true).unwrap();
    assert!(alice.account().unwrap().pending);
    alice.lock();
    alice.resume(url.clone(), r.unlock.clone()).unwrap();
    assert!(!alice.account().unwrap().pending, "the offline edit went out");
    bob.sync().unwrap();
    assert!(bob.items(Some(work.clone()), "".into(), true)[0].archived);

    // A new device signs in with the Secret Key; the wrong password says so.
    let (phone, _) = app();
    assert!(matches!(phone.login(url.clone(), r.secret_key.clone(), "nope".into()), Err(PlaintextError::WrongPassword)));
    phone.login(url.clone(), r.secret_key.clone(), "alice pw".into()).unwrap();
    assert!(phone.is_verified("bob".into()));
    assert_eq!(phone.sessions().unwrap().len(), 2, "the first device and this one");
    phone.sign_out();
    assert!(!phone.is_unlocked());
    let _ = std::fs::remove_dir_all(adir);
}
