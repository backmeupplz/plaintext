//! Plaintext server: stores opaque blobs and signed documents, and enforces who may
//! read or write them. It holds no keys, salts or KDF parameters, and no emails.
//! Every rule here is also checked by the clients; the server's checks only stop
//! honest-but-buggy or unauthorized callers, never the server itself.

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use plaintext_core::api::*;
use plaintext_core::crypto::{login_message, password_change_message, sha256, verify};
use plaintext_core::identity::valid_username;
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::Deserialize;
use serde::de::DeserializeOwned;

// ponytail: one connection behind a mutex; a self-hosted vault server is nowhere
// near SQLite's single-writer limit. Pool readers if that ever changes.
type Db = Arc<Mutex<Connection>>;

type R<T> = Result<T, (StatusCode, &'static str)>;

const MAX_BLOB: usize = 1 << 20;
const MAX_FILE: usize = 64 << 20;
const LOGIN_SKEW_MS: u64 = 120_000;

const BAD: StatusCode = StatusCode::BAD_REQUEST;
const DENIED: (StatusCode, &str) = (StatusCode::FORBIDDEN, "not allowed");

pub fn open_db(path: &str) -> rusqlite::Result<Connection> {
    let c = Connection::open(path)?;
    c.execute_batch(include_str!("schema.sql"))?;
    Ok(c)
}

#[derive(Clone)]
struct Setup(Option<String>);

/// `setup_code`: if set, the first account must present it (so nobody can race
/// you to become admin of a fresh public server).
pub fn app(db: Connection, setup_code: Option<String>) -> Router {
    let db: Db = Arc::new(Mutex::new(db));
    Router::new()
        .route("/v1/signup", post(signup))
        .route("/v1/agents", post(create_agent))
        .route("/v1/login", post(login))
        .route("/v1/logout", post(logout))
        .route("/v1/account", get(account))
        .route("/v1/account/keyring", put(put_keyring))
        .route("/v1/account/password", post(change_password))
        .route("/v1/sessions", get(sessions))
        .route("/v1/sessions/{id}", axum::routing::delete(end_session))
        .route("/v1/users", get(users))
        .route("/v1/users/{name}/disable", post(disable_user))
        .route("/v1/invites", post(create_invite))
        .route("/v1/vaults", post(create_vault))
        .route("/v1/vaults/{id}", get(get_vault).put(put_vault))
        .route("/v1/vaults/{id}/roster", post(update_roster))
        .route("/v1/vaults/{id}/audit", get(audit))
        .route("/v1/vaults/{id}/files/{fid}", get(get_file).put(put_file).delete(delete_file))
        .route("/v1/messages", get(inbox).post(send_message))
        .route("/v1/messages/{id}", axum::routing::delete(delete_message))
        .route("/v1/links", post(create_link))
        .route("/v1/links/{id}", get(open_link).delete(delete_link))
        .route("/health", get(|| async { "ok" }))
        .layer(DefaultBodyLimit::max(MAX_FILE + (1 << 20)))
        .layer(axum::Extension(Setup(setup_code)))
        .with_state(db)
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("clock after 1970").as_millis() as u64
}

fn now() -> u64 {
    now_ms() / 1000
}

fn db_err<E>(_: E) -> (StatusCode, &'static str) {
    (StatusCode::INTERNAL_SERVER_ERROR, "database error")
}

fn check_blob(b: &B64) -> R<()> {
    if b.0.is_empty() || b.0.len() > MAX_BLOB {
        return Err((BAD, "blob size"));
    }
    Ok(())
}

fn parse<T: DeserializeOwned>(s: &Signed) -> R<T> {
    serde_json::from_slice(&s.body.0).map_err(|_| (BAD, "malformed document"))
}

fn json(s: &Signed) -> String {
    serde_json::to_string(s).expect("serializable")
}

fn hex_id(s: &str) -> R<[u8; 16]> {
    let mut id = [0u8; 16];
    hex::decode_to_slice(s, &mut id).map_err(|_| (BAD, "bad id"))?;
    Ok(id)
}

/// The signed-in caller.
struct Caller {
    id: Vec<u8>,
    username: String,
    human: bool,
    admin: bool,
    token_hash: Vec<u8>,
}

fn caller(db: &Connection, h: &HeaderMap) -> R<Caller> {
    let token = h
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or((StatusCode::UNAUTHORIZED, "no token"))?;
    let th = sha256(token.as_bytes()).to_vec();
    db.query_row(
        "SELECT a.id, a.username, a.kind, a.admin FROM sessions s JOIN accounts a ON a.id = s.account_id
         WHERE s.token_hash = ? AND a.disabled = 0",
        [&th],
        |r| Ok(Caller { id: r.get(0)?, username: r.get(1)?, human: r.get::<_, String>(2)? == "human", admin: r.get(3)?, token_hash: th.clone() }),
    )
    .optional()
    .map_err(db_err)?
    .ok_or((StatusCode::UNAUTHORIZED, "bad token"))
}

/// The identity signing key the server holds for `username`.
fn sign_pk(db: &Connection, username: &str) -> R<Vec<u8>> {
    let s: String = db
        .query_row("SELECT identity FROM accounts WHERE username = ?", [username], |r| r.get(0))
        .optional()
        .map_err(db_err)?
        .ok_or((BAD, "unknown user"))?;
    let signed: Signed = serde_json::from_str(&s).map_err(db_err)?;
    Ok(parse::<Identity>(&signed)?.sign_pk.0)
}

fn verify_signed(db: &Connection, s: &Signed, domain: &str, expected_signer: &str) -> R<()> {
    if s.signer != expected_signer {
        return Err((BAD, "signer must be you"));
    }
    verify(&sign_pk(db, &s.signer)?, domain, &s.body.0, &s.sig.0).map_err(|_| (BAD, "bad signature"))
}

/// The caller's active role in a vault.
fn role(db: &Connection, vault: &[u8], username: &str) -> R<Option<Role>> {
    let r: Option<String> = db
        .query_row(
            "SELECT role FROM members WHERE vault_id = ? AND username = ? AND (expires IS NULL OR expires > ?)",
            params![vault, username, now()],
            |r| r.get(0),
        )
        .optional()
        .map_err(db_err)?;
    Ok(r.and_then(|r| serde_json::from_value(serde_json::Value::String(r)).ok()))
}

fn need_role(db: &Connection, vault: &[u8], username: &str, min: Role) -> R<()> {
    match role(db, vault, username)? {
        Some(r) if r >= min => Ok(()),
        Some(_) => Err(DENIED),
        None => Err((StatusCode::NOT_FOUND, "no such vault")),
    }
}

fn audit_log(db: &Connection, vault: &[u8], who: &str, action: &str) -> R<()> {
    db.execute("INSERT INTO audit(vault_id, ts, username, action) VALUES(?,?,?,?)", params![vault, now(), who, action])
        .map_err(db_err)?;
    Ok(())
}

// ---------- Accounts ----------

fn insert_account(tx: &Transaction, req: &SignupRequest, kind: Kind, owner: Option<&str>, admin: bool) -> R<Identity> {
    check_blob(&req.account_key)?;
    check_blob(&req.keyring)?;
    let auth: [u8; 32] = req.auth_key.0.as_slice().try_into().map_err(|_| (BAD, "auth key"))?;
    ed25519_dalek::VerifyingKey::from_bytes(&auth).map_err(|_| (BAD, "auth key"))?;
    let id: Identity = parse(&req.identity)?;
    verify(&id.sign_pk.0, "identity", &req.identity.body.0, &req.identity.sig.0).map_err(|_| (BAD, "bad signature"))?;
    if req.identity.signer != id.username || !valid_username(&id.username) || id.kind != kind || id.owner.as_deref() != owner {
        return Err((BAD, "bad identity"));
    }
    let (invite_id, proof) = req.invite.as_ref().map(|i| (i.id.0.to_vec(), i.proof.0.clone())).unzip();
    let inserted = tx
        .execute(
            "INSERT OR IGNORE INTO accounts(id, username, kind, owner, identity, auth_key, account_key, keyring, admin, invite_id, invite_proof, created)
             VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            params![
                &req.account_id.0[..],
                id.username,
                if kind == Kind::Human { "human" } else { "agent" },
                owner,
                json(&req.identity),
                &auth[..],
                req.account_key.0,
                req.keyring.0,
                admin,
                invite_id,
                proof,
                now()
            ],
        )
        .map_err(db_err)?;
    if inserted == 0 {
        return Err((StatusCode::CONFLICT, "that username or account is taken"));
    }
    Ok(id)
}

async fn signup(State(db): State<Db>, axum::Extension(setup): axum::Extension<Setup>, Json(req): Json<SignupRequest>) -> R<StatusCode> {
    let mut db = db.lock().expect("db lock");
    let tx = db.transaction().map_err(db_err)?;
    let first = tx.query_row("SELECT COUNT(*) FROM accounts", [], |r| r.get::<_, i64>(0)).map_err(db_err)? == 0;
    if first && let Some(code) = &setup.0 {
        let given = req.setup.as_deref().unwrap_or_default();
        if !bool::from(subtle::ConstantTimeEq::ct_eq(given.as_bytes(), code.as_bytes())) {
            return Err((StatusCode::FORBIDDEN, "this server needs its setup code for the first account"));
        }
    }
    if !first {
        let inv = req.invite.as_ref().ok_or((StatusCode::FORBIDDEN, "signups need an invite"))?;
        let used = tx
            .execute("UPDATE invites SET used = 1 WHERE id = ? AND used = 0 AND expires > ?", params![&inv.id.0[..], now()])
            .map_err(db_err)?;
        if used == 0 {
            return Err((StatusCode::FORBIDDEN, "that invite is used or expired"));
        }
    }
    let id = insert_account(&tx, &req, Kind::Human, None, first)?;
    insert_vault(&tx, req.vault.as_ref().ok_or((BAD, "a personal vault is required"))?, &id.username)?;
    tx.commit().map_err(db_err)?;
    Ok(StatusCode::CREATED)
}

async fn create_agent(State(db): State<Db>, h: HeaderMap, Json(req): Json<SignupRequest>) -> R<StatusCode> {
    let mut db = db.lock().expect("db lock");
    let c = caller(&db, &h)?;
    if !c.human || req.vault.is_some() || req.invite.is_some() {
        return Err(DENIED);
    }
    let tx = db.transaction().map_err(db_err)?;
    insert_account(&tx, &req, Kind::Agent, Some(&c.username), false)?;
    tx.commit().map_err(db_err)?;
    Ok(StatusCode::CREATED)
}

async fn login(State(db): State<Db>, Json(req): Json<LoginRequest>) -> R<Json<LoginResponse>> {
    let denied = (StatusCode::UNAUTHORIZED, "login failed");
    if req.ts.abs_diff(now_ms()) > LOGIN_SKEW_MS || req.device.len() > 200 {
        return Err(denied);
    }
    let db = db.lock().expect("db lock");
    let (auth, last): (Vec<u8>, u64) = db
        .query_row("SELECT auth_key, last_login FROM accounts WHERE id = ? AND disabled = 0", [&req.account_id.0[..]], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .optional()
        .map_err(db_err)?
        .ok_or(denied)?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&auth.try_into().map_err(|_| denied)?).map_err(|_| denied)?;
    let sig = ed25519_dalek::Signature::from_slice(&req.sig.0).map_err(|_| denied)?;
    // Strictly newer timestamps only: a captured login can't be replayed.
    if req.ts <= last || key.verify_strict(&login_message(&req.account_id.0, req.ts), &sig).is_err() {
        return Err(denied);
    }
    let mut raw = [0u8; 32];
    getrandom::fill(&mut raw).map_err(db_err)?;
    let token = hex::encode(raw);
    db.execute("UPDATE accounts SET last_login = ? WHERE id = ?", params![req.ts, &req.account_id.0[..]]).map_err(db_err)?;
    db.execute(
        "INSERT INTO sessions(token_hash, account_id, device, created) VALUES(?,?,?,?)",
        params![&sha256(token.as_bytes())[..], &req.account_id.0[..], req.device, now()],
    )
    .map_err(db_err)?;
    Ok(Json(LoginResponse { token }))
}

async fn logout(State(db): State<Db>, h: HeaderMap) -> R<StatusCode> {
    let db = db.lock().expect("db lock");
    let c = caller(&db, &h)?;
    db.execute("DELETE FROM sessions WHERE token_hash = ?", [&c.token_hash]).map_err(db_err)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn account(State(db): State<Db>, h: HeaderMap) -> R<Json<AccountResponse>> {
    let db = db.lock().expect("db lock");
    let c = caller(&db, &h)?;
    let (account_key, keyring, keyring_counter) = db
        .query_row("SELECT account_key, keyring, keyring_counter FROM accounts WHERE id = ?", [&c.id], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .map_err(db_err)?;
    let mut q = db
        .prepare("SELECT vault_id FROM members WHERE username = ? AND (expires IS NULL OR expires > ?)")
        .map_err(db_err)?;
    let vaults = q
        .query_map(params![c.username, now()], |r| r.get::<_, Vec<u8>>(0))
        .map_err(db_err)?
        .filter_map(|v| v.ok()?.try_into().ok().map(Hex))
        .collect();
    Ok(Json(AccountResponse { username: c.username, admin: c.admin, account_key: B64(account_key), keyring: B64(keyring), keyring_counter, vaults }))
}

async fn put_keyring(State(db): State<Db>, h: HeaderMap, Json(req): Json<KeyringPut>) -> R<StatusCode> {
    check_blob(&req.keyring)?;
    let db = db.lock().expect("db lock");
    let c = caller(&db, &h)?;
    let n = db
        .execute(
            "UPDATE accounts SET keyring = ?, keyring_counter = keyring_counter + 1 WHERE id = ? AND keyring_counter = ?",
            params![req.keyring.0, c.id, req.expected_counter],
        )
        .map_err(db_err)?;
    if n == 0 {
        return Err((StatusCode::CONFLICT, "keyring changed, pull first"));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn change_password(State(db): State<Db>, h: HeaderMap, Json(req): Json<PasswordChange>) -> R<StatusCode> {
    check_blob(&req.account_key)?;
    let db = db.lock().expect("db lock");
    let c = caller(&db, &h)?;
    let auth: Vec<u8> = db.query_row("SELECT auth_key FROM accounts WHERE id = ?", [&c.id], |r| r.get(0)).map_err(db_err)?;
    let id: [u8; 16] = c.id.as_slice().try_into().map_err(db_err)?;
    let msg = password_change_message(&id, req.ts, &req.auth_key.0, &req.account_key.0);
    let key = ed25519_dalek::VerifyingKey::from_bytes(&auth.try_into().map_err(db_err)?).map_err(db_err)?;
    let sig = ed25519_dalek::Signature::from_slice(&req.sig.0).map_err(|_| (BAD, "bad signature"))?;
    let new: [u8; 32] = req.auth_key.0.as_slice().try_into().map_err(|_| (BAD, "auth key"))?;
    if req.ts.abs_diff(now_ms()) > LOGIN_SKEW_MS || key.verify_strict(&msg, &sig).is_err() {
        return Err((StatusCode::UNAUTHORIZED, "re-enter your current password"));
    }
    db.execute("UPDATE accounts SET auth_key = ?, account_key = ? WHERE id = ?", params![&new[..], req.account_key.0, c.id])
        .map_err(db_err)?;
    // Every other device signs in again with the new password.
    db.execute("DELETE FROM sessions WHERE account_id = ? AND token_hash != ?", params![c.id, c.token_hash]).map_err(db_err)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn sessions(State(db): State<Db>, h: HeaderMap) -> R<Json<Vec<DeviceSession>>> {
    let db = db.lock().expect("db lock");
    let c = caller(&db, &h)?;
    let mut q = db.prepare("SELECT token_hash, device, created FROM sessions WHERE account_id = ? ORDER BY created").map_err(db_err)?;
    let list = q
        .query_map([&c.id], |r| {
            let th: Vec<u8> = r.get(0)?;
            Ok(DeviceSession { id: hex::encode(&th[..8]), device: r.get(1)?, created: r.get(2)?, current: th == c.token_hash })
        })
        .map_err(db_err)?
        .collect::<Result<_, _>>()
        .map_err(db_err)?;
    Ok(Json(list))
}

async fn end_session(State(db): State<Db>, h: HeaderMap, Path(id): Path<String>) -> R<StatusCode> {
    let db = db.lock().expect("db lock");
    let c = caller(&db, &h)?;
    let prefix = hex::decode(&id).map_err(|_| (BAD, "bad id"))?;
    if prefix.len() != 8 {
        return Err((BAD, "bad id"));
    }
    db.execute("DELETE FROM sessions WHERE account_id = ? AND substr(token_hash, 1, 8) = ?", params![c.id, prefix]).map_err(db_err)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn users(State(db): State<Db>, h: HeaderMap) -> R<Json<Vec<UserInfo>>> {
    let db = db.lock().expect("db lock");
    caller(&db, &h)?;
    let mut q = db.prepare("SELECT identity, admin, disabled, invite_id, invite_proof FROM accounts ORDER BY username").map_err(db_err)?;
    let list = q
        .query_map([], |r| {
            let id: String = r.get(0)?;
            let inv: Option<Vec<u8>> = r.get(3)?;
            let proof: Option<Vec<u8>> = r.get(4)?;
            Ok((id, r.get(1)?, r.get(2)?, inv.zip(proof)))
        })
        .map_err(db_err)?
        .filter_map(|row| {
            let (id, admin, disabled, inv) = row.ok()?;
            let invite = inv.and_then(|(i, p)| Some(InviteProof { id: Hex(i.try_into().ok()?), proof: B64(p) }));
            Some(UserInfo { identity: serde_json::from_str(&id).ok()?, admin, disabled, invite })
        })
        .collect();
    Ok(Json(list))
}

async fn disable_user(State(db): State<Db>, h: HeaderMap, Path(name): Path<String>) -> R<StatusCode> {
    let db = db.lock().expect("db lock");
    let c = caller(&db, &h)?;
    // Admins disable anyone but themselves; humans disable the agents they own.
    let owner: Option<Option<String>> =
        db.query_row("SELECT owner FROM accounts WHERE username = ?", [&name], |r| r.get(0)).optional().map_err(db_err)?;
    let Some(owner) = owner else { return Err((StatusCode::NOT_FOUND, "no such user")) };
    if name == c.username || !(c.admin || owner.as_deref() == Some(c.username.as_str())) {
        return Err(DENIED);
    }
    db.execute("UPDATE accounts SET disabled = 1 WHERE username = ?", [&name]).map_err(db_err)?;
    db.execute("DELETE FROM sessions WHERE account_id = (SELECT id FROM accounts WHERE username = ?)", [&name]).map_err(db_err)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn create_invite(State(db): State<Db>, h: HeaderMap, Json(req): Json<NewInvite>) -> R<StatusCode> {
    let db = db.lock().expect("db lock");
    let c = caller(&db, &h)?;
    if !c.admin {
        return Err(DENIED);
    }
    db.execute(
        "INSERT INTO invites(id, created_by, expires) VALUES(?,?,?)",
        params![&req.id.0[..], c.username, now() + 7 * 86400],
    )
    .map_err(|_| (StatusCode::CONFLICT, "invite exists"))?;
    Ok(StatusCode::CREATED)
}

// ---------- Vaults ----------

/// Store a roster version and refresh the members table from it.
fn store_roster(tx: &Transaction, vault: &[u8], s: &Signed, r: &Roster) -> R<()> {
    for m in &r.members {
        let id: Identity = parse(&serde_json::from_str::<Signed>(
            &tx.query_row("SELECT identity FROM accounts WHERE username = ? AND disabled = 0", [&m.username], |row| row.get::<_, String>(0))
                .optional()
                .map_err(db_err)?
                .ok_or((BAD, "a member doesn't exist"))?,
        )
        .map_err(db_err)?)?;
        if id.sign_pk != m.sign_pk || id.enc_pk != m.enc_pk {
            return Err((BAD, "a member's keys don't match their identity"));
        }
    }
    tx.execute("INSERT INTO rosters(vault_id, version, signed) VALUES(?,?,?)", params![vault, r.version, json(s)])
        .map_err(|_| (StatusCode::CONFLICT, "roster changed, pull first"))?;
    tx.execute("DELETE FROM members WHERE vault_id = ?", [vault]).map_err(db_err)?;
    for m in &r.members {
        let role = serde_json::to_value(m.role).expect("serializable");
        tx.execute(
            "INSERT INTO members(vault_id, username, role, expires) VALUES(?,?,?,?)",
            params![vault, m.username, role.as_str(), m.expires],
        )
        .map_err(db_err)?;
    }
    tx.execute(
        "UPDATE vaults SET roster_version = ?, roster_hash = ?, epoch = ? WHERE id = ?",
        params![r.version, &sha256(&s.body.0)[..], r.epoch, vault],
    )
    .map_err(db_err)?;
    Ok(())
}

fn store_keys(tx: &Transaction, vault: &[u8], keys: &[WrappedKey]) -> R<()> {
    for k in keys {
        check_blob(&k.key)?;
        tx.execute(
            "INSERT OR REPLACE INTO vault_keys(vault_id, username, epoch, key) VALUES(?,?,?,?)",
            params![vault, k.username, k.epoch, k.key.0],
        )
        .map_err(db_err)?;
    }
    Ok(())
}

/// Check a manifest against the vault's chain and append it with its items.
fn store_put(tx: &Transaction, vault: &[u8], put: &VaultPut, username: &str) -> R<()> {
    verify_signed(tx, &put.manifest, "manifest", username)?;
    let env: ManifestEnvelope = parse(&put.manifest)?;
    let (counter, epoch, last): (u64, u64, Option<Vec<u8>>) = tx
        .query_row("SELECT counter, epoch, manifest_hash FROM vaults WHERE id = ?", [vault], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .map_err(db_err)?;
    if counter != put.expected_counter {
        return Err((StatusCode::CONFLICT, "vault changed, pull first"));
    }
    if env.vault_id.0[..] != *vault || env.counter != counter + 1 || env.epoch != epoch || env.prev.0 != last.unwrap_or_default() {
        return Err((BAD, "manifest doesn't extend the chain"));
    }
    check_blob(&env.sealed)?;
    for u in &put.upserts {
        check_blob(&u.blob)?;
        tx.execute(
            "INSERT OR REPLACE INTO items(vault_id, id, blob, counter) VALUES(?,?,?,?)",
            params![vault, &u.id.0[..], u.blob.0, env.counter],
        )
        .map_err(db_err)?;
    }
    for d in &put.deletes {
        tx.execute("DELETE FROM items WHERE vault_id = ? AND id = ?", params![vault, &d.0[..]]).map_err(db_err)?;
    }
    tx.execute("INSERT INTO manifests(vault_id, counter, signed) VALUES(?,?,?)", params![vault, env.counter, json(&put.manifest)])
        .map_err(db_err)?;
    tx.execute(
        "UPDATE vaults SET counter = ?, manifest_hash = ? WHERE id = ?",
        params![env.counter, &sha256(&put.manifest.body.0)[..], vault],
    )
    .map_err(db_err)?;
    Ok(())
}

fn insert_vault(tx: &Transaction, nv: &NewVault, username: &str) -> R<()> {
    verify_signed(tx, &nv.roster, "roster", username)?;
    let r: Roster = parse(&nv.roster)?;
    if r.version != 0 || !r.prev.0.is_empty() || r.epoch != 0 || !r.members.iter().any(|m| m.username == username && m.role == Role::Owner) {
        return Err((BAD, "bad roster"));
    }
    let vault = r.vault_id.0;
    tx.execute("INSERT INTO vaults(id, counter, epoch, roster_version) VALUES(?,0,0,0)", [&vault[..]])
        .map_err(|_| (StatusCode::CONFLICT, "vault exists"))?;
    store_roster(tx, &vault, &nv.roster, &r)?;
    store_keys(tx, &vault, &nv.keys)?;
    let put = VaultPut { expected_counter: 0, manifest: nv.manifest.clone(), upserts: vec![], deletes: vec![] };
    store_put(tx, &vault, &put, username)
}

async fn create_vault(State(db): State<Db>, h: HeaderMap, Json(nv): Json<NewVault>) -> R<StatusCode> {
    let mut db = db.lock().expect("db lock");
    let c = caller(&db, &h)?;
    if !c.human {
        return Err(DENIED);
    }
    let tx = db.transaction().map_err(db_err)?;
    insert_vault(&tx, &nv, &c.username)?;
    tx.commit().map_err(db_err)?;
    Ok(StatusCode::CREATED)
}

#[derive(Deserialize)]
struct Since {
    #[serde(default)]
    since: u64,
    roster: Option<u64>,
}

async fn get_vault(State(db): State<Db>, h: HeaderMap, Path(id): Path<String>, Query(q): Query<Since>) -> R<Json<VaultResponse>> {
    let vault = hex_id(&id)?;
    let db = db.lock().expect("db lock");
    let c = caller(&db, &h)?;
    need_role(&db, &vault, &c.username, Role::Reader)?;
    if !c.human {
        audit_log(&db, &vault, &c.username, "read")?;
    }
    let (counter, epoch): (u64, u64) =
        db.query_row("SELECT counter, epoch FROM vaults WHERE id = ?", [&vault[..]], |r| Ok((r.get(0)?, r.get(1)?))).map_err(db_err)?;
    let signed_list = |sql: &str, after: i64| -> R<Vec<Signed>> {
        let mut st = db.prepare(sql).map_err(db_err)?;
        st.query_map(params![&vault[..], after], |r| r.get::<_, String>(0))
            .map_err(db_err)?
            .map(|s| serde_json::from_str(&s.map_err(db_err)?).map_err(db_err))
            .collect()
    };
    let manifests = signed_list("SELECT signed FROM manifests WHERE vault_id = ? AND counter > ? ORDER BY counter", q.since as i64)?;
    let rosters = signed_list(
        "SELECT signed FROM rosters WHERE vault_id = ? AND version > ? ORDER BY version",
        q.roster.map_or(-1, |v| v as i64),
    )?;
    let key = db
        .query_row(
            "SELECT key FROM vault_keys WHERE vault_id = ? AND username = ? AND epoch = ?",
            params![&vault[..], c.username, epoch],
            |r| r.get(0),
        )
        .optional()
        .map_err(db_err)?
        .map(B64);
    let mut st = db.prepare("SELECT id, blob FROM items WHERE vault_id = ? AND counter > ?").map_err(db_err)?;
    let items = st
        .query_map(params![&vault[..], q.since], |r| Ok(ItemBlob { id: Hex(r.get(0)?), blob: B64(r.get(1)?) }))
        .map_err(db_err)?
        .collect::<Result<_, _>>()
        .map_err(db_err)?;
    Ok(Json(VaultResponse { counter, manifests, rosters, key, items }))
}

async fn put_vault(State(db): State<Db>, h: HeaderMap, Path(id): Path<String>, Json(put): Json<VaultPut>) -> R<StatusCode> {
    let vault = hex_id(&id)?;
    let mut db = db.lock().expect("db lock");
    let c = caller(&db, &h)?;
    let tx = db.transaction().map_err(db_err)?;
    need_role(&tx, &vault, &c.username, Role::Writer)?;
    store_put(&tx, &vault, &put, &c.username)?;
    audit_log(&tx, &vault, &c.username, &format!("write {} items, delete {}", put.upserts.len(), put.deletes.len()))?;
    tx.commit().map_err(db_err)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn update_roster(State(db): State<Db>, h: HeaderMap, Path(id): Path<String>, Json(u): Json<RosterUpdate>) -> R<StatusCode> {
    let vault = hex_id(&id)?;
    let mut db = db.lock().expect("db lock");
    let c = caller(&db, &h)?;
    let tx = db.transaction().map_err(db_err)?;
    need_role(&tx, &vault, &c.username, Role::Owner)?;
    verify_signed(&tx, &u.roster, "roster", &c.username)?;
    let r: Roster = parse(&u.roster)?;
    let (version, epoch, hash): (u64, u64, Vec<u8>) = tx
        .query_row("SELECT roster_version, epoch, roster_hash FROM vaults WHERE id = ?", [&vault[..]], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .map_err(db_err)?;
    if r.vault_id.0 != vault || r.version != version + 1 || r.prev.0 != hash {
        return Err((StatusCode::CONFLICT, "roster changed, pull first"));
    }
    let rotating = r.epoch == epoch + 1;
    if !(r.epoch == epoch || rotating) || rotating != u.rotation.is_some() {
        return Err((BAD, "a key change needs a rotation and vice versa"));
    }
    store_roster(&tx, &vault, &u.roster, &r)?;
    store_keys(&tx, &vault, &u.keys)?;
    if let Some(put) = &u.rotation {
        tx.execute("DELETE FROM items WHERE vault_id = ?", [&vault[..]]).map_err(db_err)?;
        store_put(&tx, &vault, put, &c.username)?;
    }
    audit_log(&tx, &vault, &c.username, &format!("roster v{}", r.version))?;
    tx.commit().map_err(db_err)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn audit(State(db): State<Db>, h: HeaderMap, Path(id): Path<String>) -> R<Json<Vec<AuditEntry>>> {
    let vault = hex_id(&id)?;
    let db = db.lock().expect("db lock");
    let c = caller(&db, &h)?;
    need_role(&db, &vault, &c.username, Role::Owner)?;
    let mut st = db.prepare("SELECT ts, username, action FROM audit WHERE vault_id = ? ORDER BY ts DESC LIMIT 1000").map_err(db_err)?;
    let list = st
        .query_map([&vault[..]], |r| Ok(AuditEntry { ts: r.get(0)?, username: r.get(1)?, action: r.get(2)? }))
        .map_err(db_err)?
        .collect::<Result<_, _>>()
        .map_err(db_err)?;
    Ok(Json(list))
}

async fn put_file(State(db): State<Db>, h: HeaderMap, Path((id, fid)): Path<(String, String)>, body: Bytes) -> R<StatusCode> {
    let (vault, file) = (hex_id(&id)?, hex_id(&fid)?);
    if body.is_empty() || body.len() > MAX_FILE {
        return Err((BAD, "file size"));
    }
    let db = db.lock().expect("db lock");
    let c = caller(&db, &h)?;
    need_role(&db, &vault, &c.username, Role::Writer)?;
    db.execute("INSERT OR REPLACE INTO files(vault_id, id, blob) VALUES(?,?,?)", params![&vault[..], &file[..], &body[..]])
        .map_err(db_err)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_file(State(db): State<Db>, h: HeaderMap, Path((id, fid)): Path<(String, String)>) -> R<Vec<u8>> {
    let (vault, file) = (hex_id(&id)?, hex_id(&fid)?);
    let db = db.lock().expect("db lock");
    let c = caller(&db, &h)?;
    need_role(&db, &vault, &c.username, Role::Reader)?;
    if !c.human {
        audit_log(&db, &vault, &c.username, "read file")?;
    }
    db.query_row("SELECT blob FROM files WHERE vault_id = ? AND id = ?", params![&vault[..], &file[..]], |r| r.get(0))
        .optional()
        .map_err(db_err)?
        .ok_or((StatusCode::NOT_FOUND, "no such file"))
}

async fn delete_file(State(db): State<Db>, h: HeaderMap, Path((id, fid)): Path<(String, String)>) -> R<StatusCode> {
    let (vault, file) = (hex_id(&id)?, hex_id(&fid)?);
    let db = db.lock().expect("db lock");
    let c = caller(&db, &h)?;
    need_role(&db, &vault, &c.username, Role::Writer)?;
    db.execute("DELETE FROM files WHERE vault_id = ? AND id = ?", params![&vault[..], &file[..]]).map_err(db_err)?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------- Messages and links ----------

async fn send_message(State(db): State<Db>, h: HeaderMap, Json(s): Json<Signed>) -> R<StatusCode> {
    let db = db.lock().expect("db lock");
    let c = caller(&db, &h)?;
    verify_signed(&db, &s, "message", &c.username)?;
    let m: Message = parse(&s)?;
    check_blob(&m.sealed)?;
    sign_pk(&db, &m.to)?;
    db.execute(
        "INSERT INTO messages(id, to_user, signed, expires, created) VALUES(?,?,?,?,?)",
        params![&m.id.0[..], m.to, json(&s), m.expires, now()],
    )
    .map_err(|_| (StatusCode::CONFLICT, "message exists"))?;
    Ok(StatusCode::CREATED)
}

async fn inbox(State(db): State<Db>, h: HeaderMap) -> R<Json<Vec<Signed>>> {
    let db = db.lock().expect("db lock");
    let c = caller(&db, &h)?;
    db.execute("DELETE FROM messages WHERE expires IS NOT NULL AND expires <= ?", [now()]).map_err(db_err)?;
    let mut st = db.prepare("SELECT signed FROM messages WHERE to_user = ? ORDER BY created").map_err(db_err)?;
    let list = st
        .query_map([&c.username], |r| r.get::<_, String>(0))
        .map_err(db_err)?
        .filter_map(|s| serde_json::from_str(&s.ok()?).ok())
        .collect();
    Ok(Json(list))
}

async fn delete_message(State(db): State<Db>, h: HeaderMap, Path(id): Path<String>) -> R<StatusCode> {
    let id = hex_id(&id)?;
    let db = db.lock().expect("db lock");
    let c = caller(&db, &h)?;
    db.execute("DELETE FROM messages WHERE id = ? AND to_user = ?", params![&id[..], c.username]).map_err(db_err)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn create_link(State(db): State<Db>, h: HeaderMap, Json(l): Json<NewLink>) -> R<StatusCode> {
    check_blob(&l.blob)?;
    let db = db.lock().expect("db lock");
    let c = caller(&db, &h)?;
    if l.expires <= now() || l.expires > now() + 30 * 86400 {
        return Err((BAD, "links last up to 30 days"));
    }
    db.execute(
        "INSERT INTO links(id, creator, blob, expires, views_left) VALUES(?,?,?,?,?)",
        params![&l.id.0[..], c.username, l.blob.0, l.expires, l.max_views],
    )
    .map_err(|_| (StatusCode::CONFLICT, "link exists"))?;
    Ok(StatusCode::CREATED)
}

/// Public: anyone with the link may fetch the sealed blob (the key is in the
/// link's fragment, which never reaches us). CORS is open so the static viewer
/// page at getplaintext.org can fetch it.
async fn open_link(State(db): State<Db>, Path(id): Path<String>) -> Response {
    let res: R<Vec<u8>> = (|| {
        let id = hex_id(&id)?;
        let db = db.lock().expect("db lock");
        db.execute("DELETE FROM links WHERE expires <= ? OR views_left = 0", [now()]).map_err(db_err)?;
        let blob: Vec<u8> = db
            .query_row("SELECT blob FROM links WHERE id = ?", [&id[..]], |r| r.get(0))
            .optional()
            .map_err(db_err)?
            .ok_or((StatusCode::NOT_FOUND, "this link has expired or doesn't exist"))?;
        db.execute("UPDATE links SET views_left = views_left - 1 WHERE id = ? AND views_left IS NOT NULL", [&id[..]])
            .map_err(db_err)?;
        Ok(blob)
    })();
    let mut resp = match res {
        Ok(b) => Json(B64(b)).into_response(),
        Err(e) => e.into_response(),
    };
    resp.headers_mut().insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    resp
}

async fn delete_link(State(db): State<Db>, h: HeaderMap, Path(id): Path<String>) -> R<StatusCode> {
    let id = hex_id(&id)?;
    let db = db.lock().expect("db lock");
    let c = caller(&db, &h)?;
    db.execute("DELETE FROM links WHERE id = ? AND creator = ?", params![&id[..], c.username]).map_err(db_err)?;
    Ok(StatusCode::NO_CONTENT)
}
