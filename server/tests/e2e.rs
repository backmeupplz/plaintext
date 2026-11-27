//! Two devices sync one account through the real router, and the database file
//! never contains anything readable.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use plaintext_core::api::*;
use plaintext_core::crypto::{SecretKey, derive};
use plaintext_core::*;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tower::ServiceExt;

struct Client {
    app: Router,
    token: String,
}

impl Client {
    async fn call(&self, method: &str, uri: &str, body: Option<impl Serialize>, hdr: (&str, &str)) -> (StatusCode, Vec<u8>) {
        let mut req = Request::builder().method(method).uri(uri).header("content-type", "application/json");
        if !self.token.is_empty() {
            req = req.header("authorization", format!("Bearer {}", self.token));
        }
        if !hdr.0.is_empty() {
            req = req.header(hdr.0, hdr.1);
        }
        let body = body.map(|b| Body::from(serde_json::to_vec(&b).unwrap())).unwrap_or_default();
        let resp = self.app.clone().oneshot(req.body(body).unwrap()).await.unwrap();
        (resp.status(), resp.into_body().collect().await.unwrap().to_bytes().to_vec())
    }

    async fn json<T: DeserializeOwned>(&self, method: &str, uri: &str, body: Option<impl Serialize>) -> T {
        let (st, b) = self.call(method, uri, body, ("", "")).await;
        assert!(st.is_success(), "{method} {uri}: {st} {}", String::from_utf8_lossy(&b));
        serde_json::from_slice(&b).unwrap()
    }

    /// Log in, unlock, and pull the account's only vault.
    async fn device(app: &Router, password: &str, sk: &SecretKey, ts: u64) -> (Client, Vault) {
        let d = derive(password, sk);
        let mut c = Client { app: app.clone(), token: String::new() };
        let login: LoginResponse = c.json("POST", "/v1/login", Some(login_request(&d, ts, "test"))).await;
        c.token = login.token;
        let acct: AccountResponse = c.json("GET", "/v1/account", None::<()>).await;
        let (_, mut vaults) = Account::unlock(&d, &acct).unwrap();
        let mut v = vaults.remove(0);
        c.pull(&mut v).await;
        (c, v)
    }

    async fn pull(&self, v: &mut Vault) {
        let resp: VaultResponse = self.json("GET", &format!("/v1/vaults/{}?since={}", hex::encode(v.id.0), v.counter), None::<()>).await;
        v.apply(&resp).unwrap();
    }

    async fn push(&self, v: &mut Vault) -> StatusCode {
        let put = v.push();
        let (st, _) = self.call("PUT", &format!("/v1/vaults/{}", hex::encode(v.id.0)), Some(&put), ("", "")).await;
        if st.is_success() {
            v.pushed(&put);
        }
        st
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

#[tokio::test]
async fn two_devices_sync_and_server_sees_nothing() {
    let path = std::env::temp_dir().join(format!("plaintext-e2e-{}.db", hex::encode(plaintext_core::crypto::random::<8>())));
    let app = plaintext_server::app(plaintext_server::open_db(path.to_str().unwrap()).unwrap(), None);
    let anon = Client { app: app.clone(), token: String::new() };

    let pw = "correct horse battery staple";
    let s = signup(pw);
    assert_eq!(anon.call("POST", "/v1/signup", Some(&s.request), ("", "")).await.0, StatusCode::CREATED);
    // Only the first account can sign up without an invite.
    let other = signup("other");
    assert_eq!(anon.call("POST", "/v1/signup", Some(&other.request), ("", "")).await.0, StatusCode::FORBIDDEN);

    // The Secret Key travels as text (Emergency Kit / QR) to the second device.
    let sk = SecretKey::parse(&s.secret_key.encode()).unwrap();
    let t = now();
    let (a, mut va) = Client::device(&app, pw, &s.secret_key, t).await;
    let id = new_item_id();
    va.put(id, Item { kind: "login".into(), title: "Bank of Nowhere".into(), username: "alice".into(), password: "SuperSecret-9431".into(), urls: vec!["https://bank.example".into()], ..Default::default() });
    assert_eq!(a.push(&mut va).await, StatusCode::NO_CONTENT);

    let (b, mut vb) = Client::device(&app, pw, &sk, t + 1).await;
    assert_eq!(vb.get(&id).unwrap().password, "SuperSecret-9431");

    // Concurrent edits: B wins the race, A gets 409, pulls, merges, retries.
    let mut edited = vb.get(&id).unwrap().clone();
    edited.notes = "from B".into();
    vb.put(id, edited);
    assert_eq!(b.push(&mut vb).await, StatusCode::NO_CONTENT);
    let id2 = new_item_id();
    va.put(id2, Item { title: "Wifi".into(), password: "hunter2hunter2".into(), ..Default::default() });
    assert_eq!(a.push(&mut va).await, StatusCode::CONFLICT);
    a.pull(&mut va).await;
    assert_eq!(a.push(&mut va).await, StatusCode::NO_CONTENT);
    b.pull(&mut vb).await;
    assert_eq!(vb.get(&id).unwrap().notes, "from B");
    assert_eq!(vb.get(&id2).unwrap().password, "hunter2hunter2");
    assert_eq!(va.get(&id).unwrap().notes, "from B");

    // Deletes propagate.
    va.delete(id2);
    assert_eq!(a.push(&mut va).await, StatusCode::NO_CONTENT);
    b.pull(&mut vb).await;
    assert!(vb.get(&id2).is_none());

    // A replayed login is refused; so are a wrong password and a stranger's token.
    let d = derive(pw, &sk);
    assert_eq!(anon.call("POST", "/v1/login", Some(login_request(&d, t + 1, "x")), ("", "")).await.0, StatusCode::UNAUTHORIZED);
    let wrong = derive("wrong", &sk);
    assert_eq!(anon.call("POST", "/v1/login", Some(login_request(&wrong, t + 2, "x")), ("", "")).await.0, StatusCode::UNAUTHORIZED);
    let stranger = Client { app: app.clone(), token: "00".repeat(32) };
    assert_eq!(stranger.call("GET", "/v1/account", None::<()>, ("", "")).await.0, StatusCode::UNAUTHORIZED);

    // Logout kills the session.
    assert_eq!(b.call("POST", "/v1/logout", None::<()>, ("", "")).await.0, StatusCode::NO_CONTENT);
    assert_eq!(b.call("GET", "/v1/account", None::<()>, ("", "")).await.0, StatusCode::UNAUTHORIZED);

    // The database holds nothing readable: no secrets, titles, usernames or URLs.
    drop(app);
    let mut raw = std::fs::read(&path).unwrap();
    raw.extend(std::fs::read(path.with_extension("db-wal")).unwrap_or_default());
    // Positive control: device names are stored in clear, so the scan really reads the data.
    assert!(raw.windows(4).any(|w| w == b"test"));
    for needle in ["SuperSecret", "hunter2", "Bank of Nowhere", "alice", "bank.example", "Wifi", "from B", pw] {
        assert!(!raw.windows(needle.len()).any(|w| w == needle.as_bytes()), "found {needle:?} in the database");
    }
    let _ = std::fs::remove_file(&path);
}
