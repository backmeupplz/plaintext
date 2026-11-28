//! The browser extension's side of Plaintext: one signed-in account, synced
//! with `plaintext-client`'s own `Session` (the same verification, rollback
//! guards, keyring merge and problems as the CLI and apps), over `fetch`.
//!
//! JavaScript does the requests and storage; Rust does every key, seal,
//! signature and sync decision. The plain functions take any `AsyncTransport`,
//! so they're tested natively against a real server; the `Account` export wraps
//! them for JavaScript.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use base64::{Engine, engine::general_purpose::STANDARD};
use plaintext_client::plaintext_core::api::{Hex, Role};
use plaintext_client::plaintext_core::crypto::{self, SecretKey};
use plaintext_client::plaintext_core::item::Item;
use plaintext_client::plaintext_core::{self as core, Account as Keys, Vault, site};
use plaintext_client::{AsyncTransport, Error, Problem, Session, now, now_ms};
use serde_json::{Value, json};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

// ---------- Plain functions (tested natively) ----------

/// Sign in with the password and Secret Key, giving the Secret Key sealed under
/// the password, which is all the extension keeps between unlocks.
pub async fn add<T: AsyncTransport>(t: T, password: &str, secret_key: &str, device: &str) -> Result<(Session<T>, Vec<u8>), Error> {
    let sk = SecretKey::parse(secret_key)?;
    let s = Session::login_async(t, &crypto::derive(password, &sk), device).await?;
    Ok((s, crypto::seal_secret_key(password, &sk)))
}

/// Unlock with just the password. `Tampered` means it didn't match; a 401
/// means it opened the Secret Key but was changed on another device since.
pub async fn unlock<T: AsyncTransport>(t: T, password: &str, sealed_secret_key: &[u8], device: &str) -> Result<Session<T>, Error> {
    let sk = crypto::open_secret_key(password, sealed_secret_key)?;
    Session::login_async(t, &crypto::derive(password, &sk), device).await
}

/// What `storage.session` holds while unlocked, so the background can pick the
/// session up again after the browser suspends it. Never written to disk.
pub fn session_state<T: AsyncTransport>(s: &Session<T>) -> Value {
    json!({ "token": s.token, "account_id": hex::encode(s.account.id), "account_key": hex::encode(&s.account.account_key[..]) })
}

fn stored(state: &Value) -> Result<(String, Keys), Error> {
    let bad = || Error::Refused("the stored session is damaged; unlock again".into());
    let field = |k: &str| state[k].as_str().ok_or_else(bad);
    let id: [u8; 16] = hex::decode(field("account_id")?).ok().and_then(|v| v.try_into().ok()).ok_or_else(bad)?;
    let key: [u8; 32] = hex::decode(field("account_key")?).ok().and_then(|v| v.try_into().ok()).ok_or_else(bad)?;
    Ok((field("token")?.into(), Keys { id, account_key: Zeroizing::new(key) }))
}

pub async fn resume<T: AsyncTransport>(t: T, state: &Value) -> Result<Session<T>, Error> {
    let (token, keys) = stored(state)?;
    Session::resume_async(t, token, keys).await
}

/// Pick the session up with no network, from `session_state` and this
/// device's `local_state`; the next sync checks it with the server.
pub fn restore<T: AsyncTransport>(t: T, state: &Value, local: &Value) -> Result<Session<T>, Error> {
    let (token, keys) = stored(state)?;
    let keyring = local["keyring"].as_str().and_then(|b| STANDARD.decode(b).ok()).ok_or(Error::NotFound("this device's copy".into()))?;
    let mut s = Session::restore(t, token, keys, &keyring)?;
    load_vaults(&mut s, local);
    Ok(s)
}

/// This device's own copies, sealed with the Account Key, as `cli/src/state.rs`
/// keeps them: every vault (hidden ones too) for the rollback guard, and the
/// keyring so a server can't erase pins. `storage.local` holds this.
pub fn local_state<T: AsyncTransport>(s: &Session<T>) -> Value {
    let vaults: BTreeMap<String, String> = s.vaults.iter().chain(&s.hidden).map(|(id, v)| (id.to_string(), STANDARD.encode(v.snapshot(&s.account)))).collect();
    let hidden: Vec<String> = s.hidden.keys().map(|id| id.to_string()).collect();
    json!({ "keyring": STANDARD.encode(s.keyring_snapshot()), "vaults": vaults, "hidden": hidden })
}

/// Load `local_state` after signing in, before the first sync. Copies that
/// don't open (another account's, damaged) are skipped.
pub async fn load_local<T: AsyncTransport>(s: &mut Session<T>, state: &Value) -> Result<(), Error> {
    load_vaults(s, state);
    match state["keyring"].as_str().map(|b| STANDARD.decode(b)) {
        Some(Ok(blob)) => s.merge_local_keyring_async(&blob).await,
        _ => Ok(()),
    }
}

fn load_vaults<T: AsyncTransport>(s: &mut Session<T>, state: &Value) {
    for (id, blob) in state["vaults"].as_object().into_iter().flatten() {
        if let (Ok(id), Some(Ok(blob))) = (id.parse::<Hex>(), blob.as_str().map(|b| STANDARD.decode(b)))
            && let Ok(v) = Vault::restore(&s.account, id, &blob)
        {
            // Vaults the server had stopped listing stay out of sight (and keep their guard).
            let hidden = state["hidden"].as_array().is_some_and(|h| h.iter().any(|x| x.as_str() == Some(&id.to_string())));
            if hidden { s.hidden.insert(id, v) } else { s.vaults.insert(id, v) };
        }
    }
}

fn writable<T: AsyncTransport>(s: &Session<T>, v: &Vault) -> bool {
    v.role(s.username(), now()).is_some_and(|r| r >= Role::Writer)
}

/// The popup's list: no secrets, the page's logins first, then favorites, then
/// by title. `query` filters as the apps' search does.
pub fn list<T: AsyncTransport>(s: &Session<T>, page: Option<&str>, query: &str) -> Vec<Value> {
    let mut out: Vec<(bool, &Item, Value)> = Vec::new();
    for (vid, v) in &s.vaults {
        let writable = writable(s, v);
        for (iid, it) in v.items() {
            if it.archived || (!query.is_empty() && !it.matches(query)) {
                continue;
            }
            let here = page.is_some_and(|p| it.matches_page(p));
            let row = json!({
                "vault": vid.to_string(), "id": iid.to_string(), "vault_name": v.meta.name, "kind": it.kind,
                "title": it.title, "username": it.username, "url": it.urls.first(), "favorite": it.favorite,
                "here": here, "has_password": !it.password.is_empty(), "has_totp": !it.totp.is_empty(), "writable": writable,
            });
            out.push((here, it, row));
        }
    }
    out.sort_by_cached_key(|(here, it, _)| (!here, !it.favorite, it.title.to_lowercase()));
    out.into_iter().map(|(_, _, v)| v).collect()
}

fn find<'a, T: AsyncTransport>(s: &'a Session<T>, vault: &str, id: &str) -> Result<(Hex, Hex, &'a Item), Error> {
    let nf = || Error::NotFound("item".into());
    let (vid, iid): (Hex, Hex) = (vault.parse().map_err(|_| nf())?, id.parse().map_err(|_| nf())?);
    let it = s.vaults.get(&vid).and_then(|v| v.get(&iid)).ok_or_else(nf)?;
    Ok((vid, iid, it))
}

/// The username and password to fill into `page`, only if the item is saved
/// for that site (or that exact host). The caller has already checked the page
/// is the tab's top frame.
pub fn fill<T: AsyncTransport>(s: &Session<T>, vault: &str, id: &str, page: &str) -> Result<Value, Error> {
    let (_, _, it) = find(s, vault, id)?;
    if !it.matches_page(page) {
        return Err(Error::Refused(format!("{} isn't saved for this site", it.title)));
    }
    Ok(json!({ "username": it.username, "password": it.password }))
}

/// A whole item, for the item view and copy buttons in the extension's own pages.
pub fn item<T: AsyncTransport>(s: &Session<T>, vault: &str, id: &str) -> Result<Value, Error> {
    let (_, _, it) = find(s, vault, id)?;
    Ok(serde_json::to_value(it).expect("serializable"))
}

/// The writable login a submit on `page` would update: the same username's
/// (of several, the one saved for this very host), or with no username (a
/// password-only step, a change-password form) the site's only writable login.
fn target<'a, T: AsyncTransport>(s: &'a Session<T>, page: &str, username: &str) -> Option<(Hex, Hex, &'a Item)> {
    let host = site::host(page);
    let mut found = s
        .vaults
        .iter()
        .filter(|(_, v)| writable(s, v))
        .flat_map(|(vid, v)| v.items().map(move |(iid, it)| (*vid, *iid, it)))
        .filter(|(_, _, it)| !it.archived && it.matches_page(page) && (username.is_empty() || it.username == username));
    if username.is_empty() {
        let one = found.next()?;
        return found.next().is_none().then_some(one);
    }
    found.max_by_key(|(_, _, it)| it.urls.iter().any(|u| site::host(u) == host))
}

/// What to offer after a login form was submitted on `page`: `known` (saved
/// already), `update` (another password for a saved login), `new`, or `none`
/// (no username and no single login it could be for).
pub fn save_offer<T: AsyncTransport>(s: &Session<T>, page: &str, username: &str, password: &str) -> &'static str {
    let known = s.vaults.values().flat_map(|v| v.items()).any(|(_, it)| !it.archived && it.matches_page(page) && (username.is_empty() || it.username == username) && it.password == password);
    match (known, target(s, page, username)) {
        (true, _) => "known",
        (_, Some(_)) => "update",
        _ if username.is_empty() => "none",
        _ => "new",
    }
}

/// The username of the login `save_login` would update, for the confirm.
pub fn save_target<T: AsyncTransport>(s: &Session<T>, page: &str, username: &str) -> Option<String> {
    target(s, page, username).map(|(_, _, it)| it.username.clone())
}

/// Save a login submitted on `page`: a new password for the login `target`
/// picks; otherwise a new item in this account's default vault (never one
/// someone else shared with us). With no username there must be a target.
pub async fn save_login<T: AsyncTransport>(s: &mut Session<T>, page: &str, username: &str, password: &str) -> Result<Value, Error> {
    let existing = target(s, page, username).map(|(v, i, it)| (v, i, it.clone()));
    let (vid, iid, item) = match existing {
        Some((vid, iid, mut it)) => {
            let next = Item { password: password.into(), ..it.clone() };
            it.edit(next, now_ms());
            (vid, iid, it)
        }
        None if username.is_empty() => {
            return Err(Error::Refused("there's no single saved login on this site for that password".into()));
        }
        None => {
            let host = site::host(page).ok_or_else(|| Error::Refused("this page has no web address to save".into()))?;
            let origin = page.split(['?', '#']).next().unwrap_or(page);
            let origin = origin.match_indices('/').nth(2).map_or(origin, |(i, _)| &origin[..i]);
            let now = now_ms();
            let it = Item { kind: "login".into(), title: host, username: username.into(), password: password.into(), urls: vec![origin.into()], created: now, updated: now, ..Default::default() };
            (s.default_vault()?, core::new_item_id(), it)
        }
    };
    s.put_item_async(&vid, iid, item).await?;
    Ok(json!({ "vault": vid.to_string(), "id": iid.to_string() }))
}

/// Offer a login only on its URLs' exact hosts (or again on their whole site).
pub async fn set_exact_host<T: AsyncTransport>(s: &mut Session<T>, vault: &str, id: &str, exact: bool) -> Result<(), Error> {
    let (vid, iid, it) = find(s, vault, id)?;
    if !writable(s, &s.vaults[&vid]) {
        return Err(Error::Refused("you can only view this vault, so this login can't be changed".into()));
    }
    let mut it = it.clone();
    let next = Item { exact_host: exact, ..it.clone() };
    it.edit(next, now_ms());
    s.put_item_async(&vid, iid, it).await
}

/// Pull, verify, merge and push every vault, giving the problems the user
/// should see. As in the CLI, a vault that couldn't push (out of storage, or
/// another device got there first) is a warning, not a failed sync: its change
/// stays on this device and goes at the next sync, and the rest still count.
/// A problem's `leave` names the vault it offers to leave with `leave`, never one of your own;
/// its `unsent` names the vault whose changes it says can't be sent (you may
/// only read it now, or it isn't shared with you any more), for
/// `unsent_changes` and `discard_changes`.
pub async fn sync<T: AsyncTransport>(s: &mut Session<T>) -> Result<Vec<Problem>, Error> {
    let r = s.sync_async().await;
    let mut problems = s.problems.clone();
    match r {
        Ok(()) => {}
        Err(Error::Server(507, msg)) => problems.push(format!("A change is kept on this device until there's room: {msg}").into()),
        Err(Error::Server(413, msg)) => problems.push(format!("A change is kept on this device, but it's too big to send: {msg}").into()),
        Err(Error::Server(409, msg)) => problems.push(format!("A change is kept on this device and sent at the next sync: {msg}").into()),
        Err(e) => return Err(e),
    }
    Ok(problems)
}

fn vault_id(vault: &str) -> Result<Hex, Error> {
    vault.parse().map_err(|_| Error::NotFound("vault".into()))
}

/// This device's changes to a vault that haven't reached the server, to show
/// before `discard_changes` drops them: `{name, unlisted, changed: [title],
/// deleted, renamed}`. `unlisted`: it isn't shared with you any more, so this
/// device has the only copy and the popup can't show its items.
pub fn unsent_changes<T: AsyncTransport>(s: &Session<T>, vault: &str) -> Result<Value, Error> {
    let (v, unlisted) = s.unsendable_changes(&vault_id(vault)?)?;
    let name = if v.meta.name.is_empty() { vault } else { &v.meta.name };
    let changed: Vec<&str> = v.changed().map(|(_, i)| if i.title.is_empty() { "(untitled)" } else { &i.title }).collect();
    Ok(json!({ "name": name, "unlisted": unlisted, "changed": changed, "deleted": v.deleted(), "renamed": v.meta_changed() }))
}

/// Drop them (the vault is downloaded again) and the sync problem about them. Returns how many.
pub async fn discard_changes<T: AsyncTransport>(s: &mut Session<T>, vault: &str) -> Result<usize, Error> {
    // Only if the server still says they can't be sent.
    s.discard_unsendable_async(&vault_id(vault)?).await
}

/// What leaving a vault would do, to say before it happens: its name (null for
/// one this device can't open), whether you're its only owner (the others keep
/// it, but nobody can add people or replace its key any more), and whether it
/// has changes that haven't reached the server, which are lost.
pub async fn leave_check<T: AsyncTransport>(s: &Session<T>, vault: &str) -> Result<Value, Error> {
    let id = vault_id(vault)?;
    let v = s.vaults.get(&id).or_else(|| s.hidden.get(&id));
    Ok(json!({
        "name": v.filter(|v| v.roster.is_some() && !v.meta.name.is_empty()).map(|v| &v.meta.name),
        "only_owner": s.leaves_ownerless_async(&id).await?,
        "unsent": v.is_some_and(|v| v.has_changes()),
    }))
}

/// Stop using a vault, with your agents, also one this device can't open (by
/// the id a sync problem gave). It's deleted if nobody else uses it.
pub async fn leave<T: AsyncTransport>(s: &mut Session<T>, vault: &str) -> Result<(), Error> {
    let id = vault_id(vault)?;
    s.leave_vault_async(&id).await
}

/// A short code JavaScript can branch on, next to the message for people.
pub fn code(e: &Error) -> &'static str {
    match e {
        Error::Core(core::Error::Tampered) => "tampered",
        Error::Core(core::Error::BadSecretKey) => "bad_secret_key",
        Error::Core(_) => "core",
        Error::Server(401, _) => "signed_out",
        Error::Server(..) => "server",
        Error::Network(_) => "network",
        Error::NotFound(_) => "not_found",
        Error::Refused(_) => "refused",
    }
}

// ---------- JavaScript ----------

/// Requests go through one JavaScript function, `fetch(method, url, token, body)`
/// resolving to `[status, Uint8Array]`, which uses the browser's `fetch` with
/// redirects refused, no cookies, a timeout and a size cap (extension/lib/net.js).
struct Fetch {
    base: String,
    f: js_sys::Function,
}

impl AsyncTransport for Fetch {
    async fn fetch(&self, method: &str, path: &str, token: Option<&str>, body: Option<Vec<u8>>) -> Result<(u16, Vec<u8>), Error> {
        let args = js_sys::Array::new();
        args.push(&method.into());
        args.push(&format!("{}{path}", self.base).into());
        args.push(&token.map_or(JsValue::NULL, JsValue::from));
        args.push(&body.map_or(JsValue::UNDEFINED, |b| js_sys::Uint8Array::from(&b[..]).into()));
        let net = |e: JsValue| Error::Network(e.dyn_ref::<js_sys::Error>().map_or_else(|| "request failed".into(), |e| String::from(e.message())));
        let promise = self.f.apply(&JsValue::NULL, &args).map_err(net)?;
        let resp = wasm_bindgen_futures::JsFuture::from(js_sys::Promise::from(promise)).await.map_err(net)?;
        let resp = js_sys::Array::from(&resp);
        let status = resp.get(0).as_f64().ok_or_else(|| Error::Network("no status".into()))? as u16;
        Ok((status, js_sys::Uint8Array::new(&resp.get(1)).to_vec()))
    }

    fn login_host(&self) -> String {
        crypto::server_host(&self.base)
    }
}

fn js_err(e: Error) -> JsValue {
    let err = js_sys::Error::new(&e.to_string());
    err.set_name(code(&e));
    err.into()
}

type Cell = Rc<RefCell<Option<Session<Fetch>>>>;

/// One signed-in account. Calls must not overlap (the extension queues them);
/// one that does fails with `busy` instead of corrupting state.
#[wasm_bindgen]
pub struct Account(Cell);

fn transport(server: &str, fetch: js_sys::Function) -> Fetch {
    Fetch { base: server.trim().trim_end_matches('/').into(), f: fetch }
}

fn busy() -> JsValue {
    let e = js_sys::Error::new("another call is still running");
    e.set_name("busy");
    e.into()
}

fn parse(json: &str) -> Result<Value, JsValue> {
    serde_json::from_str(json).map_err(|_| js_err(Error::Refused("bad JSON from the extension".into())))
}

#[wasm_bindgen]
impl Account {
    /// Sign in for the first time on this browser. Resolves to the account;
    /// `sealedSecretKey()` then gives what to keep in `storage.local`.
    pub async fn add(fetch: js_sys::Function, server: String, password: String, secret_key: String, device: String) -> Result<AddResult, JsValue> {
        let (s, sealed) = add(transport(&server, fetch), &password, &secret_key, &device).await.map_err(js_err)?;
        Ok(AddResult { account: Some(Account(Rc::new(RefCell::new(Some(s))))), sealed: STANDARD.encode(sealed) })
    }

    pub async fn unlock(fetch: js_sys::Function, server: String, password: String, sealed_secret_key: String, device: String) -> Result<Account, JsValue> {
        let sealed = STANDARD.decode(sealed_secret_key).map_err(|_| js_err(core::Error::Tampered.into()))?;
        let s = unlock(transport(&server, fetch), &password, &sealed, &device).await.map_err(|e| match e {
            // The password opened the Secret Key, so it's the one this browser
            // knew, but the server refused it: most likely changed on another
            // device (a clock that's off or a disabled account look the same).
            Error::Server(401, _) => {
                let err = js_sys::Error::new("The server didn't accept this password. If you changed it on another device, open Settings and add the account again with the new password and your Secret Key, without signing out first, so changes on this device are kept. Otherwise check that this computer's clock is right.");
                err.set_name("password_changed");
                err.into()
            }
            e => js_err(e),
        })?;
        Ok(Account(Rc::new(RefCell::new(Some(s)))))
    }

    pub async fn resume(fetch: js_sys::Function, server: String, session_state: String) -> Result<Account, JsValue> {
        let s = resume(transport(&server, fetch), &parse(&session_state)?).await.map_err(js_err)?;
        Ok(Account(Rc::new(RefCell::new(Some(s)))))
    }

    /// Pick up a session with no network (see `restore`).
    pub fn restore(fetch: js_sys::Function, server: String, session_state: String, local_state: String) -> Result<Account, JsValue> {
        let s = restore(transport(&server, fetch), &parse(&session_state)?, &parse(&local_state)?).map_err(js_err)?;
        Ok(Account(Rc::new(RefCell::new(Some(s)))))
    }

    fn take(&self) -> Result<Session<Fetch>, JsValue> {
        self.0.borrow_mut().take().ok_or_else(busy)
    }

    fn with<R>(&self, f: impl FnOnce(&Session<Fetch>) -> R) -> Result<R, JsValue> {
        self.0.borrow().as_ref().map(f).ok_or_else(busy)
    }

    pub fn username(&self) -> Result<String, JsValue> {
        self.with(|s| s.username().to_string())
    }

    #[wasm_bindgen(js_name = sessionState)]
    pub fn session_state(&self) -> Result<String, JsValue> {
        self.with(|s| session_state(s).to_string())
    }

    #[wasm_bindgen(js_name = localState)]
    pub fn local_state(&self) -> Result<String, JsValue> {
        self.with(|s| local_state(s).to_string())
    }

    #[wasm_bindgen(js_name = loadLocal)]
    pub async fn load_local(&self, state: String) -> Result<(), JsValue> {
        let state = parse(&state)?;
        let mut s = self.take()?;
        let r = load_local(&mut s, &state).await;
        *self.0.borrow_mut() = Some(s);
        r.map_err(js_err)
    }

    /// See `sync`: resolves to the problems, a JSON list of `{text, leave, vault, unsent}`
    /// (`leave`: the id of the vault it offers to leave, `vault`: the one it's
    /// about, `unsent`: the one whose changes it says can't be sent; any may be
    /// null).
    pub async fn sync(&self) -> Result<String, JsValue> {
        let mut s = self.take()?;
        let r = sync(&mut s).await;
        *self.0.borrow_mut() = Some(s);
        r.map(|p| json!(p).to_string()).map_err(js_err)
    }

    #[wasm_bindgen(js_name = unsentChanges)]
    pub fn unsent_changes(&self, vault: String) -> Result<String, JsValue> {
        self.with(|s| unsent_changes(s, &vault).map(|v| v.to_string()))?.map_err(js_err)
    }

    #[wasm_bindgen(js_name = discardChanges)]
    pub async fn discard_changes(&self, vault: String) -> Result<u32, JsValue> {
        let mut s = self.take()?;
        let r = discard_changes(&mut s, &vault).await;
        *self.0.borrow_mut() = Some(s);
        r.map(|n| n as u32).map_err(js_err)
    }

    pub fn list(&self, page: Option<String>, query: String) -> Result<String, JsValue> {
        self.with(|s| json!(list(s, page.as_deref(), &query)).to_string())
    }

    pub fn fill(&self, vault: String, id: String, page: String) -> Result<String, JsValue> {
        self.with(|s| fill(s, &vault, &id, &page).map(|v| v.to_string()))?.map_err(js_err)
    }

    pub fn item(&self, vault: String, id: String) -> Result<String, JsValue> {
        self.with(|s| item(s, &vault, &id).map(|v| v.to_string()))?.map_err(js_err)
    }

    #[wasm_bindgen(js_name = saveOffer)]
    pub fn save_offer(&self, page: String, username: String, password: String) -> Result<String, JsValue> {
        self.with(|s| save_offer(s, &page, &username, &password).to_string())
    }

    #[wasm_bindgen(js_name = saveTarget)]
    pub fn save_target(&self, page: String, username: String) -> Result<Option<String>, JsValue> {
        self.with(|s| save_target(s, &page, &username))
    }

    #[wasm_bindgen(js_name = saveLogin)]
    pub async fn save_login(&self, page: String, username: String, password: String) -> Result<String, JsValue> {
        let mut s = self.take()?;
        let r = save_login(&mut s, &page, &username, &password).await;
        *self.0.borrow_mut() = Some(s);
        r.map(|v| v.to_string()).map_err(js_err)
    }

    /// See `leave_check`: resolves to `{name, only_owner, unsent}` as JSON.
    #[wasm_bindgen(js_name = leaveCheck)]
    pub async fn leave_check(&self, vault: String) -> Result<String, JsValue> {
        let s = self.take()?;
        let r = leave_check(&s, &vault).await;
        *self.0.borrow_mut() = Some(s);
        r.map(|v| v.to_string()).map_err(js_err)
    }

    /// See `leave`.
    #[wasm_bindgen(js_name = leaveVault)]
    pub async fn leave_vault(&self, vault: String) -> Result<(), JsValue> {
        let mut s = self.take()?;
        let r = leave(&mut s, &vault).await;
        *self.0.borrow_mut() = Some(s);
        r.map_err(js_err)
    }

    #[wasm_bindgen(js_name = setExactHost)]
    pub async fn set_exact_host(&self, vault: String, id: String, exact: bool) -> Result<(), JsValue> {
        let mut s = self.take()?;
        let r = set_exact_host(&mut s, &vault, &id, exact).await;
        *self.0.borrow_mut() = Some(s);
        r.map_err(js_err)
    }
}

#[wasm_bindgen]
pub struct AddResult {
    account: Option<Account>,
    sealed: String,
}

#[wasm_bindgen]
impl AddResult {
    /// The account; can be taken once.
    pub fn account(&mut self) -> Option<Account> {
        self.account.take()
    }
    #[wasm_bindgen(js_name = sealedSecretKey)]
    pub fn sealed_secret_key(&self) -> String {
        self.sealed.clone()
    }
}

/// A password from the generator: `{"type":"random","length":20,"digits":true,"symbols":true}`,
/// `{"type":"memorable","words":4,"separator":"-","capitalize":false}` or `{"type":"pin","length":6}`.
#[wasm_bindgen]
pub fn generate(recipe: String) -> Result<String, JsValue> {
    let r = serde_json::from_str(&recipe).map_err(|_| js_err(Error::Refused("bad recipe".into())))?;
    Ok(core::tools::generate(&r))
}

/// Estimated strength in bits, for the meter.
#[wasm_bindgen]
pub fn strength(password: String) -> f64 {
    core::tools::strength_bits(&password)
}

/// Whether talking to `url` would expose sign-ins to the network (plain http
/// outside this machine and private networks).
#[wasm_bindgen(js_name = insecureUrl)]
pub fn insecure_url(url: String) -> bool {
    plaintext_client::insecure_url(&url)
}

#[cfg(test)]
mod tests;
