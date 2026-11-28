//! The bridge end to end against a real server, through an `AsyncTransport`
//! that yields before every response the way `fetch` does, so nothing relies on
//! requests finishing synchronously.

use super::*;
use plaintext_client::{Http, Transport};
use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

/// Like the browser: every request is still pending on the first poll.
struct Later(Http);

impl AsyncTransport for Later {
    async fn fetch(&self, method: &str, path: &str, token: Option<&str>, body: Option<Vec<u8>>) -> Result<(u16, Vec<u8>), Error> {
        let mut yielded = false;
        std::future::poll_fn(|cx| {
            if yielded {
                return Poll::Ready(());
            }
            yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        })
        .await;
        self.0.send(method, path, token, body)
    }
    fn login_host(&self) -> String {
        self.0.host()
    }
}

fn run<F: Future>(f: F) -> F::Output {
    let mut f = pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
    }
}

fn server() -> String {
    server_with(Default::default())
}

fn server_with(cfg: plaintext_server::Config) -> String {
    let path = std::env::temp_dir().join(format!("plaintext-wasm-{}.db", hex::encode(crypto::random::<8>())));
    let db = plaintext_server::open_db(path.to_str().unwrap()).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        tokio::runtime::Runtime::new().unwrap().block_on(async move {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            tx.send(l.local_addr().unwrap()).unwrap();
            plaintext_server::serve(l, db, cfg).await.unwrap();
        });
    });
    format!("http://{}", rx.recv().unwrap())
}

#[test]
fn sign_in_save_fill_and_come_back() {
    let url = server();
    // The account comes from the CLI's code path (blocking).
    let (sk, cli) = Session::signup(Http::new(&url), "alice", "pw", None, "cli").unwrap();
    let mut cli = cli.unwrap();
    cli.sync().unwrap();
    let vault = cli.default_vault().unwrap();
    let it = Item { kind: "login".into(), title: "GitHub".into(), username: "alice".into(), password: "old".into(), urls: vec!["https://github.com".into()], ..Default::default() };
    cli.put_item(&vault, core::new_item_id(), it).unwrap();

    // The extension: Secret Key typed once, then only the password.
    let (mut s, sealed) = run(add(Later(Http::new(&url)), "pw", &sk.encode(), "Chrome")).unwrap();
    assert_eq!(code(&run(add(Later(Http::new(&url)), "pw", "A1-not-a-key", "x")).err().unwrap()), "bad_secret_key");
    assert_eq!(code(&run(unlock(Later(Http::new(&url)), "nope", &sealed, "x")).err().unwrap()), "tampered");
    run(s.sync_async()).unwrap();

    // The site's login first; another site's never fills.
    let page = "https://github.com/login";
    let rows = list(&s, Some(page), "");
    assert_eq!(rows[0]["title"], "GitHub");
    assert_eq!(rows[0]["here"], true);
    assert!(rows[0].get("password").is_none(), "lists carry no secrets");
    let (v, i) = (rows[0]["vault"].as_str().unwrap(), rows[0]["id"].as_str().unwrap());
    assert_eq!(fill(&s, v, i, page).unwrap()["password"], "old");
    assert_eq!(code(&fill(&s, v, i, "https://github.com.evil.example/login").unwrap_err()), "refused");
    assert_eq!(code(&fill(&s, v, i, "http://github.com/login").unwrap_err()), "refused");

    // Saving after a submit: known, a changed password, a new login.
    assert_eq!(save_offer(&s, page, "alice", "old"), "known");
    assert_eq!(save_offer(&s, page, "alice", "new"), "update");
    assert_eq!(save_offer(&s, "https://example.com/signup", "a@b.c", "pw1"), "new");
    run(save_login(&mut s, page, "alice", "new")).unwrap();
    let saved = run(save_login(&mut s, "https://www.example.com/signup?next=/#x", "a@b.c", "pw1")).unwrap();
    assert_eq!(save_offer(&s, "https://example.com/login", "a@b.c", "pw1"), "known");
    let new_item = item(&s, saved["vault"].as_str().unwrap(), saved["id"].as_str().unwrap()).unwrap();
    assert_eq!((new_item["title"].as_str(), new_item["urls"][0].as_str()), (Some("example.com"), Some("https://www.example.com")));

    // Exact host: the same login stops matching the site's other hosts.
    let (v, i) = (rows[0]["vault"].as_str().unwrap().to_string(), rows[0]["id"].as_str().unwrap().to_string());
    assert!(fill(&s, &v, &i, "https://gist.github.com/").is_ok());
    run(set_exact_host(&mut s, &v, &i, true)).unwrap();
    assert!(fill(&s, &v, &i, "https://gist.github.com/").is_err());
    assert!(fill(&s, &v, &i, "https://github.com/login").is_ok());

    // The CLI sees both, and the update kept the old password in history.
    cli.sync().unwrap();
    let (_, _, gh) = cli.one("GitHub", None).unwrap();
    assert_eq!((gh.password.as_str(), gh.password_history[0].password.as_str(), gh.exact_host), ("new", "old", true));
    assert_eq!(cli.one("example.com", None).unwrap().2.password, "pw1");

    // The background is suspended: pick the session up from storage.session,
    // the vaults and keyring from storage.local, then sync again.
    let (session, local) = (session_state(&s), local_state(&s));
    let mut back = run(resume(Later(Http::new(&url)), &session)).unwrap();
    run(load_local(&mut back, &local)).unwrap();
    assert_eq!(list(&back, None, "github").len(), 1, "readable before any sync");
    run(back.sync_async()).unwrap();
    assert_eq!(list(&back, None, "").len(), 2);

    // Or with no network at all, from storage.session and storage.local alone.
    let offline = restore(Later(Http::new("http://127.0.0.1:9")), &session, &local).unwrap();
    assert_eq!(list(&offline, Some(page), "")[0]["title"], "GitHub");
    assert!(restore(Later(Http::new(&url)), &session, &json!({})).is_err());

    // Unlocking later needs only the password.
    let again = run(unlock(Later(Http::new(&url)), "pw", &sealed, "Chrome")).unwrap();
    assert_eq!(again.username(), "alice");

    // Locking ends the session on the server.
    run(back.logout_async()).unwrap();
    assert_eq!(code(&run(resume(Later(Http::new(&url)), &session)).err().unwrap()), "signed_out");
}

#[test]
fn password_changed_on_another_device() {
    let url = server();
    let (sk, cli) = Session::signup(Http::new(&url), "bob", "old", None, "cli").unwrap();
    let cli = cli.unwrap();
    let (_, sealed) = run(add(Later(Http::new(&url)), "old", &sk.encode(), "Chrome")).unwrap();
    cli.change_password(&crypto::derive("old", &sk), &sk, "new").unwrap();
    // The new password can't open the Secret Key sealed under the old one.
    assert_eq!(code(&run(unlock(Later(Http::new(&url)), "new", &sealed, "Chrome")).err().unwrap()), "tampered");
    // The old one opens it, but the server refuses it: `Account.unlock` names this `password_changed`.
    assert!(matches!(run(unlock(Later(Http::new(&url)), "old", &sealed, "Chrome")).err().unwrap(), Error::Server(401, _)));
    // Adding the account again with the new password works.
    assert!(run(add(Later(Http::new(&url)), "new", &sk.encode(), "Chrome")).is_ok());
}

#[test]
fn saving_picks_the_right_login() {
    let url = server();
    let (sk, cli) = Session::signup(Http::new(&url), "dan", "pw", None, "cli").unwrap();
    let mut cli = cli.unwrap();
    cli.sync().unwrap();
    let vault = cli.default_vault().unwrap();
    let login = |u: &str| Item { kind: "login".into(), title: u.into(), username: "dan".into(), password: "old".into(), urls: vec![u.into()], ..Default::default() };
    let (a, b) = (core::new_item_id(), core::new_item_id());
    cli.put_item(&vault, a, login("https://a.example.com")).unwrap();
    cli.put_item(&vault, b, login("https://b.example.com")).unwrap();
    let (mut s, _) = run(add(Later(Http::new(&url)), "pw", &sk.encode(), "x")).unwrap();
    run(s.sync_async()).unwrap();
    // Both match the site; the one saved for this host is the one updated.
    run(save_login(&mut s, "https://b.example.com/login", "dan", "new")).unwrap();
    assert_eq!((s.vaults[&vault].get(&a).unwrap().password.as_str(), s.vaults[&vault].get(&b).unwrap().password.as_str()), ("old", "new"));
    let rows = list(&s, None, "");
    assert!(rows.iter().all(|r| r["writable"] == true));
}

#[test]
fn local_state_round_trips() {
    let url = server();
    let (sk, s) = Session::signup(Http::new(&url), "bob", "pw", None, "cli").unwrap();
    let mut s = s.unwrap();
    s.sync().unwrap();
    let vault = s.default_vault().unwrap();
    s.put_item(&vault, core::new_item_id(), Item { title: "one".into(), ..Default::default() }).unwrap();

    // The verified counter (the rollback guard) and the items come back as saved.
    let (mut ext, _) = run(add(Later(Http::new(&url)), "pw", &sk.encode(), "Firefox")).unwrap();
    run(load_local(&mut ext, &local_state(&s))).unwrap();
    assert_eq!(ext.vaults[&vault].counter, s.vaults[&vault].counter);
    assert_eq!(list(&ext, None, "one").len(), 1);
    // A vault the server stopped listing comes back hidden, not listed.
    let v = ext.vaults.remove(&vault).unwrap();
    ext.hidden.insert(vault, v);
    let mut again = run(add(Later(Http::new(&url)), "pw", &sk.encode(), "Firefox")).unwrap().0;
    run(load_local(&mut again, &local_state(&ext))).unwrap();
    assert!(again.vaults.is_empty() && again.hidden.contains_key(&vault));

    // Damaged or foreign copies are skipped, never trusted.
    let (mut fresh, _) = run(add(Later(Http::new(&url)), "pw", &sk.encode(), "Firefox")).unwrap();
    run(load_local(&mut fresh, &json!({ "vaults": { vault.to_string(): "AAAA", "zz": "??" } }))).unwrap();
    assert!(fresh.vaults.is_empty());
    let other = Session::signup(Http::new(&server()), "carol", "pw", None, "cli").unwrap().1.unwrap();
    assert!(run(load_local(&mut fresh, &json!({ "keyring": local_state(&other)["keyring"] }))).is_err());
}

#[test]
fn a_full_vault_is_a_warning_not_a_failed_sync() {
    let url = server_with(plaintext_server::Config { quota: Some(64 << 10), ..Default::default() });
    let (sk, cli) = Session::signup(Http::new(&url), "erin", "pw", None, "cli").unwrap();
    let mut cli = cli.unwrap();
    cli.sync().unwrap();
    let vault = cli.default_vault().unwrap();
    let (mut s, _) = run(add(Later(Http::new(&url)), "pw", &sk.encode(), "x")).unwrap();
    run(sync(&mut s)).unwrap();

    // Too big for the quota: kept here, refused by the server.
    let big = Item { title: "Big".into(), notes: "x".repeat(200 << 10), ..Default::default() };
    assert!(matches!(run(s.put_item_async(&vault, core::new_item_id(), big)), Err(Error::Server(507, _))));
    cli.put_item(&vault, core::new_item_id(), Item { title: "From the CLI".into(), ..Default::default() }).unwrap();

    // The sync still counts: the other device's item arrives and the warning is a problem.
    let problems = run(sync(&mut s)).unwrap();
    assert!(problems.iter().any(|p| p.contains("until there's room")), "{problems:?}");
    assert_eq!(list(&s, None, "From the CLI").len(), 1);
    // The refused change is in this device's copy, for the next sync.
    let back = restore(Later(Http::new(&url)), &session_state(&s), &local_state(&s)).unwrap();
    assert_eq!(list(&back, None, "Big").len(), 1);
}

#[test]
fn a_submit_without_a_username() {
    let url = server();
    let (sk, cli) = Session::signup(Http::new(&url), "fay", "pw", None, "cli").unwrap();
    let mut cli = cli.unwrap();
    cli.sync().unwrap();
    let vault = cli.default_vault().unwrap();
    let login = |u: &str, name: &str| Item { kind: "login".into(), title: name.into(), username: name.into(), password: "old".into(), urls: vec![u.into()], ..Default::default() };
    let one = core::new_item_id();
    cli.put_item(&vault, one, login("https://one.example", "fay")).unwrap();
    cli.put_item(&vault, core::new_item_id(), login("https://two.example", "fay")).unwrap();
    cli.put_item(&vault, core::new_item_id(), login("https://two.example", "fay2")).unwrap();
    let (mut s, _) = run(add(Later(Http::new(&url)), "pw", &sk.encode(), "x")).unwrap();
    run(sync(&mut s)).unwrap();

    // The site's only login: its password, or an update of it, never a duplicate.
    assert_eq!(save_offer(&s, "https://one.example/step2", "", "old"), "known");
    assert_eq!(save_offer(&s, "https://one.example/change", "", "new"), "update");
    assert_eq!(save_target(&s, "https://one.example/change", "").as_deref(), Some("fay"));
    run(save_login(&mut s, "https://one.example/change", "", "new")).unwrap();
    assert_eq!(s.vaults[&vault].get(&one).unwrap().password, "new");
    assert_eq!(list(&s, None, "").len(), 3);

    // Two logins there, or none: nothing to offer, nothing saved.
    assert_eq!(save_offer(&s, "https://two.example/", "", "old"), "known");
    assert_eq!(save_offer(&s, "https://two.example/", "", "other"), "none");
    assert_eq!(save_offer(&s, "https://three.example/", "", "other"), "none");
    assert_eq!(code(&run(save_login(&mut s, "https://two.example/", "", "other")).unwrap_err()), "refused");
    assert_eq!(list(&s, None, "").len(), 3);
}

#[test]
fn changes_a_reader_cant_send_are_shown_and_dropped() {
    let url = server();
    let (_, alice) = Session::signup(Http::new(&url), "gus", "pw", None, "cli").unwrap();
    let mut alice = alice.unwrap();
    let invite = alice.invite().unwrap();
    let (sk, bob) = Session::signup(Http::new(&url), "hal", "pw", Some(&invite), "cli").unwrap();
    bob.unwrap().trust_inviter(&invite).unwrap();
    alice.sync().unwrap();
    let fam = alice.create_vault("Family").unwrap();
    alice.share_vault(&fam, "hal", Role::Writer, None).unwrap();
    let (mut s, _) = run(add(Later(Http::new(&url)), "pw", &sk.encode(), "x")).unwrap();
    run(sync(&mut s)).unwrap();

    // Saved here while he could write, but not sent before he became a reader.
    let mut v = s.vaults.remove(&fam).unwrap();
    v.put(core::new_item_id(), Item { title: "Bank".into(), ..Default::default() });
    s.vaults.insert(fam, v);
    // A writer's changes go out with the next sync: nothing to offer to drop.
    assert_eq!(code(&unsent_changes(&s, &fam.to_string()).unwrap_err()), "refused");
    alice.share_vault(&fam, "hal", Role::Reader, None).unwrap();
    let problems = run(sync(&mut s)).unwrap();
    let p = problems.iter().find(|p| p.unsent == Some(fam)).unwrap_or_else(|| panic!("{problems:?}"));
    assert!(p.ends_with("can't be sent"), "{p}");

    // The browser suspended the background meanwhile: picked up from this device's copy.
    let mut back = restore(Later(Http::new(&url)), &session_state(&s), &local_state(&s)).unwrap();
    assert_eq!(unsent_changes(&back, &fam.to_string()).unwrap(), json!({ "name": "Family", "unlisted": false, "changed": ["Bank"], "deleted": 0, "renamed": false }));
    // Made a writer again after the preview: the drop asks the server and keeps it.
    alice.share_vault(&fam, "hal", Role::Writer, None).unwrap();
    assert_eq!(code(&run(discard_changes(&mut back, &fam.to_string())).unwrap_err()), "refused");
    assert_eq!(back.vaults[&fam].changes(), 1);
    alice.share_vault(&fam, "hal", Role::Reader, None).unwrap();
    assert_eq!(run(discard_changes(&mut back, &fam.to_string())).unwrap(), 1);
    assert_eq!(unsent_changes(&back, &fam.to_string()).unwrap()["changed"], json!([]));
    assert!(run(sync(&mut back)).unwrap().is_empty());
    assert_eq!(code(&run(discard_changes(&mut back, "nope")).unwrap_err()), "not_found");
}

#[test]
fn changes_to_a_vault_no_longer_shared_are_dropped_once_the_server_agrees() {
    let url = server();
    let (_, alice) = Session::signup(Http::new(&url), "ida", "pw", None, "cli").unwrap();
    let mut alice = alice.unwrap();
    let invite = alice.invite().unwrap();
    let (sk, bob) = Session::signup(Http::new(&url), "jon", "pw", Some(&invite), "cli").unwrap();
    bob.unwrap().trust_inviter(&invite).unwrap();
    alice.sync().unwrap();
    let fam = alice.create_vault("Family").unwrap();
    alice.share_vault(&fam, "jon", Role::Writer, None).unwrap();
    let (mut s, _) = run(add(Later(Http::new(&url)), "pw", &sk.encode(), "x")).unwrap();
    run(sync(&mut s)).unwrap();

    // Saved here, but not sent before she removed him.
    let mut v = s.vaults.remove(&fam).unwrap();
    v.put(core::new_item_id(), Item::default());
    s.vaults.insert(fam, v);
    alice.revoke(&fam, "jon").unwrap();
    let problems = run(sync(&mut s)).unwrap();
    assert!(problems.iter().any(|p| p.unsent == Some(fam) && p.contains("isn't listed")), "{problems:?}");

    // Picked up from this device's copy, it's still out of sight.
    let mut back = restore(Later(Http::new(&url)), &session_state(&s), &local_state(&s)).unwrap();
    let want = json!({ "name": "Family", "unlisted": true, "changed": ["(untitled)"], "deleted": 0, "renamed": false });
    assert_eq!(unsent_changes(&back, &fam.to_string()).unwrap(), want);
    // Shared again after the preview: the drop asks the server and keeps it.
    alice.share_vault(&fam, "jon", Role::Reader, None).unwrap();
    assert_eq!(code(&run(discard_changes(&mut back, &fam.to_string())).unwrap_err()), "refused");
    assert_eq!(unsent_changes(&back, &fam.to_string()).unwrap(), want);
    alice.revoke(&fam, "jon").unwrap();
    assert_eq!(run(discard_changes(&mut back, &fam.to_string())).unwrap(), 1);
    let back = restore(Later(Http::new(&url)), &session_state(&back), &local_state(&back)).unwrap();
    assert_eq!(unsent_changes(&back, &fam.to_string()).unwrap()["changed"], json!([]));
}

/// Leaving a vault a sync problem names: an owner who left hands bob a vault
/// that counts against his storage, and the popup offers to leave it.
#[test]
fn leaving_a_vault_a_problem_names() {
    let url = server_with(plaintext_server::Config { open_signup: true, quota: Some(64 << 20), ..Default::default() });
    let mut alice = Session::signup(Http::new(&url), "alice", "pw", None, "cli").unwrap().1.unwrap();
    alice.sync().unwrap();
    let (sk, bob) = Session::signup(Http::new(&url), "bob", "pw", None, "cli").unwrap();
    bob.unwrap().sync().unwrap();
    let (mut s, _) = run(add(Later(Http::new(&url)), "pw", &sk.encode(), "x")).unwrap();
    run(sync(&mut s)).unwrap();

    // Alice is the only owner of a vault bob writes to: she's warned.
    let team = alice.create_vault("Team").unwrap();
    alice.share_vault(&team, "bob", Role::Writer, None).unwrap();
    assert_eq!(run(leave_check(&alice, &team.to_string())).unwrap(), json!({ "name": "Team", "only_owner": true, "unsent": false }));

    // She makes bob an owner and leaves: his sync names the vault, with its id to leave.
    alice.share_vault(&team, "bob", Role::Owner, None).unwrap();
    alice.leave_vault(&team).unwrap();
    let problems = run(sync(&mut s)).unwrap();
    let named: Vec<_> = problems.iter().filter(|p| p.leave == Some(team)).collect();
    assert!(named.len() == 1 && named[0].contains("counts against your storage, though alice created it"), "{problems:?}");
    assert!(problems.iter().all(|p| p.leave == Some(team)), "{problems:?}");
    let sent = json!(problems);
    assert_eq!(sent[0]["leave"], team.to_string());

    // A change to it wasn't sent, and a problem about it offers no leave (as when
    // the server stops listing it): the change is warned about.
    s.vaults.get_mut(&team).unwrap().put(plaintext_client::plaintext_core::new_item_id(), Item { title: "Unsent".into(), ..Default::default() });
    s.problems.push(plaintext_client::Problem { text: "vault Team isn't listed for you any more".into(), leave: None, vault: Some(team), unsent: None });
    assert_eq!(run(leave_check(&s, &team.to_string())).unwrap(), json!({ "name": "Team", "only_owner": false, "unsent": true }));

    // Nobody else uses it: leaving deletes it with the change and every problem
    // about it, and the next sync is clean.
    run(leave(&mut s, &team.to_string())).unwrap();
    assert!(!s.vaults.contains_key(&team) && s.problems.is_empty());
    assert_eq!(run(leave_check(&s, &team.to_string())).unwrap()["unsent"], false);
    assert!(run(sync(&mut s)).unwrap().is_empty());
    assert_eq!(code(&run(leave(&mut s, "not a vault")).unwrap_err()), "not_found");
}
