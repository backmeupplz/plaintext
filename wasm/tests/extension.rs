//! The built extension WebAssembly (extension/pkg, from `wasm/build.sh
//! extension`) under Node, through the extension's own fetch glue, against a
//! real server. Skipped when pkg/ isn't built, unless PLAINTEXT_REQUIRE_PKG is
//! set (CI sets it after building).

#![cfg(feature = "extension")]

use plaintext_client::plaintext_core::item::Item;
use plaintext_client::{Http, Session};

#[test]
fn wasm_bridge_under_node() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../extension");
    if !root.join("pkg/plaintext_wasm_bg.wasm").exists() {
        assert!(std::env::var_os("PLAINTEXT_REQUIRE_PKG").is_none(), "extension/pkg isn't built");
        eprintln!("skipped: run wasm/build.sh extension first");
        return;
    }
    let path = std::env::temp_dir().join(format!("plaintext-node-{}.db", std::process::id()));
    let db = plaintext_server::open_db(path.to_str().unwrap()).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        tokio::runtime::Runtime::new().unwrap().block_on(async move {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            tx.send(l.local_addr().unwrap()).unwrap();
            plaintext_server::serve(l, db, Default::default()).await.unwrap();
        });
    });
    let url = format!("http://{}", rx.recv().unwrap());
    let (sk, s) = Session::signup(Http::new(&url), "alice", "pw", None, "cli").unwrap();
    let mut s = s.unwrap();
    s.sync().unwrap();
    let vault = s.default_vault().unwrap();
    let gh = Item { kind: "login".into(), title: "GitHub".into(), username: "alice".into(), password: "hunter2".into(), urls: vec!["https://github.com".into()], ..Default::default() };
    s.put_item(&vault, plaintext_client::plaintext_core::new_item_id(), gh).unwrap();

    let out = std::process::Command::new("node").arg(root.join("test/bridge.mjs")).args([&url, "pw", &sk.encode()]).output().expect("node");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let r: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(r["username"], "alice");
    assert_eq!(r["problems"], serde_json::json!([]));
    assert_eq!((r["first"]["title"].as_str(), r["first"]["here"].as_bool()), (Some("GitHub"), Some(true)));
    assert!(r["first"].get("password").is_none());
    assert_eq!(r["fill"]["password"], "hunter2");
    assert_eq!(r["crossSite"], "refused");
    assert_eq!(r["offer"], "new");
    assert_eq!(r["overlap"], "busy");
    assert_eq!(r["afterResume"], 1);
    assert_eq!(r["wrongPassword"], "tampered");
    assert_eq!(r["unlocked"], "alice");
    assert_eq!(r["generated"], 24);
    assert_eq!(r["strong"], true);
    assert_eq!(r["restored"], "GitHub");
    assert_eq!(r["logout"], 204);

    // What the extension saved is a normal item to every other client.
    s.sync().unwrap();
    let (_, _, it) = s.one("new@example.com", None).unwrap();
    assert_eq!((it.title.as_str(), it.password.as_str(), it.urls[0].as_str()), ("example.com", "pw1", "https://example.com"));
}

/// A demo account for trying the extension against a local server:
///   PLAINTEXT_SEED=http://localhost:8080 cargo test -p plaintext-wasm --test extension seed -- --ignored --nocapture
/// Prints the Secret Key. `PLAINTEXT_SEED_SITE` (default http://localhost:8090)
/// is where the demo login is saved.
#[test]
#[ignore]
fn seed() {
    let url = std::env::var("PLAINTEXT_SEED").expect("PLAINTEXT_SEED=<server address>");
    let site = std::env::var("PLAINTEXT_SEED_SITE").unwrap_or_else(|_| "http://localhost:8090".into());
    let pw = std::env::var("PLAINTEXT_SEED_PASSWORD").unwrap_or_else(|_| "correct horse battery staple".into());
    let (sk, s) = Session::signup(Http::new(&url), "alice", &pw, std::env::var("PLAINTEXT_SEED_SETUP").ok().as_deref(), "seed").unwrap();
    let mut s = s.unwrap();
    s.sync().unwrap();
    let vault = s.default_vault().unwrap();
    let login = |title: &str, user: &str, pass: &str, url: &str| Item { kind: "login".into(), title: title.into(), username: user.into(), password: pass.into(), urls: vec![url.into()], ..Default::default() };
    for it in [
        login("Demo shop", "alice@example.com", "hunter2-demo", &site),
        login("GitHub", "alice", "gh-demo-password", "https://github.com"),
        Item { totp: "JBSWY3DPEHPK3PXP".into(), notes: "Recovery codes are in the safe.".into(), ..login("Google", "alice@gmail.com", "g-demo-password", "https://accounts.google.com") },
    ] {
        s.put_item(&vault, plaintext_client::plaintext_core::new_item_id(), it).unwrap();
    }
    // A second account, with a password of its own.
    let code = s.invite().unwrap();
    let (bob_sk, bob) = Session::signup(Http::new(&url), "bob", "bob's own password", Some(&code), "seed").unwrap();
    let mut bob = bob.unwrap();
    bob.trust_inviter(&code).unwrap();
    bob.sync().unwrap();
    let bv = bob.default_vault().unwrap();
    bob.put_item(&bv, plaintext_client::plaintext_core::new_item_id(), login("Bob's shop", "bob@example.com", "bob-demo", &site)).unwrap();
    println!("server {url}\nusername alice\npassword {pw}\nsecret key {}\nbob secret key {}", sk.encode(), bob_sk.encode());
}
