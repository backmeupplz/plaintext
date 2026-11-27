//! Plaintext server: stores opaque blobs and enforces only who may read or write
//! them. It holds no keys, salts or KDF parameters, and no emails.

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use ed25519_dalek::{Signature, VerifyingKey};
use plaintext_core::api::*;
use plaintext_core::crypto::{login_message, sha256};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Deserialize;

// ponytail: one connection behind a mutex; a self-hosted vault server is nowhere
// near SQLite's single-writer limit. Pool readers if that ever changes.
type Db = Arc<Mutex<Connection>>;

#[derive(Clone)]
struct AppState {
    db: Db,
    /// If set, signups need `x-invite: <value>`. If unset, only the first account may sign up.
    invite: Option<String>,
}

type R<T> = Result<T, (StatusCode, &'static str)>;

const MAX_BLOB: usize = 1 << 20;
const MAX_BODY: usize = 64 << 20;
const LOGIN_SKEW: u64 = 120;

pub fn open_db(path: &str) -> rusqlite::Result<Connection> {
    let c = Connection::open(path)?;
    c.execute_batch(
        "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;
         CREATE TABLE IF NOT EXISTS accounts(
           id BLOB PRIMARY KEY, auth_key BLOB NOT NULL, account_key BLOB NOT NULL,
           last_login INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL);
         CREATE TABLE IF NOT EXISTS sessions(
           token_hash BLOB PRIMARY KEY, account_id BLOB NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
           device TEXT NOT NULL, created INTEGER NOT NULL);
         CREATE TABLE IF NOT EXISTS vaults(
           id BLOB PRIMARY KEY, account_id BLOB NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
           vault_key BLOB NOT NULL, manifest BLOB NOT NULL, counter INTEGER NOT NULL);
         CREATE TABLE IF NOT EXISTS items(
           vault_id BLOB NOT NULL REFERENCES vaults(id) ON DELETE CASCADE, id BLOB NOT NULL,
           blob BLOB NOT NULL, counter INTEGER NOT NULL, PRIMARY KEY(vault_id, id));
         CREATE INDEX IF NOT EXISTS items_since ON items(vault_id, counter);",
    )?;
    Ok(c)
}

pub fn app(db: Connection, invite: Option<String>) -> Router {
    let state = AppState { db: Arc::new(Mutex::new(db)), invite };
    Router::new()
        .route("/v1/signup", post(signup))
        .route("/v1/login", post(login))
        .route("/v1/logout", post(logout))
        .route("/v1/account", get(account))
        .route("/v1/vaults/{id}", get(get_vault).put(put_vault))
        .route("/health", get(|| async { "ok" }))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(state)
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("clock after 1970").as_secs()
}

fn db_err<E>(_: E) -> (StatusCode, &'static str) {
    (StatusCode::INTERNAL_SERVER_ERROR, "database error")
}

fn check_blob(b: &B64) -> R<()> {
    if b.0.is_empty() || b.0.len() > MAX_BLOB {
        return Err((StatusCode::BAD_REQUEST, "blob size"));
    }
    Ok(())
}

/// Resolve `Authorization: Bearer <token>` to an account id.
fn authed(db: &Connection, h: &HeaderMap) -> R<Vec<u8>> {
    let token = h
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or((StatusCode::UNAUTHORIZED, "no token"))?;
    db.query_row("SELECT account_id FROM sessions WHERE token_hash=?", [&sha256(token.as_bytes())[..]], |r| r.get(0))
        .optional()
        .map_err(db_err)?
        .ok_or((StatusCode::UNAUTHORIZED, "bad token"))
}

async fn signup(State(s): State<AppState>, h: HeaderMap, Json(req): Json<SignupRequest>) -> R<StatusCode> {
    check_blob(&req.account_key)?;
    check_blob(&req.vault.vault_key)?;
    check_blob(&req.vault.manifest)?;
    let auth: [u8; 32] = req.auth_key.0.as_slice().try_into().map_err(|_| (StatusCode::BAD_REQUEST, "auth key"))?;
    VerifyingKey::from_bytes(&auth).map_err(|_| (StatusCode::BAD_REQUEST, "auth key"))?;
    let mut db = s.db.lock().expect("db lock");
    let tx = db.transaction().map_err(db_err)?;
    let allowed = match &s.invite {
        Some(code) => h.get("x-invite").and_then(|v| v.to_str().ok()) == Some(code.as_str()),
        None => tx.query_row("SELECT COUNT(*) FROM accounts", [], |r| r.get::<_, i64>(0)).map_err(db_err)? == 0,
    };
    if !allowed {
        return Err((StatusCode::FORBIDDEN, "signups need an invite"));
    }
    let inserted = tx
        .execute(
            "INSERT OR IGNORE INTO accounts(id, auth_key, account_key, created) VALUES(?,?,?,?)",
            params![&req.account_id.0[..], &auth[..], &req.account_key.0, now()],
        )
        .map_err(db_err)?;
    if inserted == 0 {
        return Err((StatusCode::CONFLICT, "account exists"));
    }
    tx.execute(
        "INSERT INTO vaults(id, account_id, vault_key, manifest, counter) VALUES(?,?,?,?,0)",
        params![&req.vault.id.0[..], &req.account_id.0[..], &req.vault.vault_key.0, &req.vault.manifest.0],
    )
    .map_err(|_| (StatusCode::CONFLICT, "vault exists"))?;
    tx.commit().map_err(db_err)?;
    Ok(StatusCode::CREATED)
}

async fn login(State(s): State<AppState>, Json(req): Json<LoginRequest>) -> R<Json<LoginResponse>> {
    let denied = (StatusCode::UNAUTHORIZED, "login failed");
    if req.ts.abs_diff(now()) > LOGIN_SKEW || req.device.len() > 200 {
        return Err(denied);
    }
    let sig = Signature::from_slice(&req.sig.0).map_err(|_| denied)?;
    let db = s.db.lock().expect("db lock");
    let (auth, last): (Vec<u8>, u64) = db
        .query_row("SELECT auth_key, last_login FROM accounts WHERE id=?", [&req.account_id.0[..]], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .optional()
        .map_err(db_err)?
        .ok_or(denied)?;
    let key = VerifyingKey::from_bytes(&auth.try_into().map_err(|_| denied)?).map_err(|_| denied)?;
    // Strictly newer timestamps only: a captured login can't be replayed.
    if req.ts <= last || key.verify_strict(&login_message(&req.account_id.0, req.ts), &sig).is_err() {
        return Err(denied);
    }
    let mut raw = [0u8; 32];
    getrandom::fill(&mut raw).map_err(db_err)?;
    let token = hex::encode(raw);
    db.execute("UPDATE accounts SET last_login=? WHERE id=?", params![req.ts, &req.account_id.0[..]])
        .map_err(db_err)?;
    db.execute(
        "INSERT INTO sessions(token_hash, account_id, device, created) VALUES(?,?,?,?)",
        params![&sha256(token.as_bytes())[..], &req.account_id.0[..], req.device, now()],
    )
    .map_err(db_err)?;
    Ok(Json(LoginResponse { token }))
}

async fn logout(State(s): State<AppState>, h: HeaderMap) -> R<StatusCode> {
    let db = s.db.lock().expect("db lock");
    authed(&db, &h)?;
    let token = h.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or_default();
    let token = token.trim_start_matches("Bearer ");
    db.execute("DELETE FROM sessions WHERE token_hash=?", [&sha256(token.as_bytes())[..]]).map_err(db_err)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn account(State(s): State<AppState>, h: HeaderMap) -> R<Json<AccountResponse>> {
    let db = s.db.lock().expect("db lock");
    let id = authed(&db, &h)?;
    let account_key: Vec<u8> =
        db.query_row("SELECT account_key FROM accounts WHERE id=?", [&id], |r| r.get(0)).map_err(db_err)?;
    let mut q = db.prepare("SELECT id, vault_key, counter FROM vaults WHERE account_id=?").map_err(db_err)?;
    let vaults = q
        .query_map([&id], |r| {
            Ok(VaultInfo { id: Hex(r.get(0)?), vault_key: B64(r.get(1)?), counter: r.get(2)? })
        })
        .map_err(db_err)?
        .collect::<Result<_, _>>()
        .map_err(db_err)?;
    Ok(Json(AccountResponse { account_key: B64(account_key), vaults }))
}

fn vault_id(s: &str) -> R<[u8; 16]> {
    let mut id = [0u8; 16];
    hex::decode_to_slice(s, &mut id).map_err(|_| (StatusCode::BAD_REQUEST, "vault id"))?;
    Ok(id)
}

/// The vault's (manifest, counter), if this account owns it.
fn owned(db: &Connection, account: &[u8], vault: &[u8; 16]) -> R<(Vec<u8>, u64)> {
    db.query_row("SELECT manifest, counter FROM vaults WHERE id=? AND account_id=?", params![&vault[..], account], |r| {
        Ok((r.get(0)?, r.get(1)?))
    })
    .optional()
    .map_err(db_err)?
    .ok_or((StatusCode::NOT_FOUND, "no such vault"))
}

#[derive(Deserialize)]
struct Since {
    #[serde(default)]
    since: u64,
}

async fn get_vault(
    State(s): State<AppState>,
    h: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<Since>,
) -> R<Json<VaultResponse>> {
    let vid = vault_id(&id)?;
    let db = s.db.lock().expect("db lock");
    let account = authed(&db, &h)?;
    let (manifest, counter) = owned(&db, &account, &vid)?;
    let mut st = db.prepare("SELECT id, blob FROM items WHERE vault_id=? AND counter>?").map_err(db_err)?;
    let items = st
        .query_map(params![&vid[..], q.since], |r| Ok(ItemBlob { id: Hex(r.get(0)?), blob: B64(r.get(1)?) }))
        .map_err(db_err)?
        .collect::<Result<_, _>>()
        .map_err(db_err)?;
    Ok(Json(VaultResponse { counter, manifest: B64(manifest), items }))
}

async fn put_vault(
    State(s): State<AppState>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(put): Json<VaultPut>,
) -> R<StatusCode> {
    let vid = vault_id(&id)?;
    check_blob(&put.manifest)?;
    for u in &put.upserts {
        check_blob(&u.blob)?;
    }
    let mut db = s.db.lock().expect("db lock");
    let account = authed(&db, &h)?;
    let tx = db.transaction().map_err(db_err)?;
    let (_, counter) = owned(&tx, &account, &vid)?;
    if counter != put.expected_counter {
        return Err((StatusCode::CONFLICT, "vault changed, pull first"));
    }
    let next = counter + 1;
    for u in &put.upserts {
        tx.execute(
            "INSERT OR REPLACE INTO items(vault_id, id, blob, counter) VALUES(?,?,?,?)",
            params![&vid[..], &u.id.0[..], &u.blob.0, next],
        )
        .map_err(db_err)?;
    }
    for d in &put.deletes {
        tx.execute("DELETE FROM items WHERE vault_id=? AND id=?", params![&vid[..], &d.0[..]]).map_err(db_err)?;
    }
    tx.execute("UPDATE vaults SET manifest=?, counter=? WHERE id=?", params![&put.manifest.0, next, &vid[..]])
        .map_err(db_err)?;
    tx.commit().map_err(db_err)?;
    Ok(StatusCode::NO_CONTENT)
}
