//! Plaintext server: stores opaque blobs and signed documents, and enforces who may
//! read or write them. It holds no keys, salts or KDF parameters, and no emails.
//! Every rule here is also checked by the clients; the server's checks only stop
//! honest-but-buggy or unauthorized callers, never the server itself.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, Query, Request, State};
use axum::handler::Handler;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use plaintext_core::api::*;
use plaintext_core::crypto::{account_delete_message, login_message, password_change_message, server_host, sha256, verify};
use plaintext_core::identity::valid_username;
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::Deserialize;
use serde::de::DeserializeOwned;

// ponytail: one connection behind a mutex; a self-hosted vault server is nowhere
// near SQLite's single-writer limit. Pool readers if that ever changes.
type Db = Arc<Mutex<Connection>>;

/// A panic while holding a lock leaves the data as it was (SQLite rolls back the
/// open transaction when it drops), so later requests carry on rather than fail.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

type R<T> = Result<T, (StatusCode, &'static str)>;

const MAX_BLOB: usize = 1 << 20;
const MAX_FILE: usize = 64 << 20;
const LOGIN_SKEW_MS: u64 = 120_000;
/// The longest a session lasts, in seconds; a login may ask for less.
const SESSION_TTL: u64 = 30 * 86400;
/// A manifest lists every item (~90 bytes each), so it gets more room than an item.
const MAX_MANIFEST: usize = 16 * MAX_BLOB;
const MAX_MEMBERS: usize = 1000;
/// Largest inbox response; the rest waits until these are deleted.
const INBOX_BYTES: usize = 32 << 20;

/// Request body limits. Most requests are small; the larger ones need a session,
/// which is checked before the body is read.
const SMALL_BODY: usize = 64 << 10;
/// A blob up to MAX_BLOB, base64 (twice inside a signed message), with room for the JSON.
const BLOB_BODY: usize = 2 << 20;
/// Vault create, push, stage and roster requests. A push or key rotation with
/// more items than fit sends them ahead in parts (`/stage`).
const VAULT_BODY: usize = 32 << 20;
/// How long staged items wait for the push that commits them, in seconds.
const STAGE_TTL: u64 = 86400;

const BAD: StatusCode = StatusCode::BAD_REQUEST;
const DENIED: (StatusCode, &str) = (StatusCode::FORBIDDEN, "not allowed");
/// A push whose items a device couldn't pull in one go (`api::MAX_PUSH`).
const TOO_BIG: (StatusCode, &str) = (StatusCode::PAYLOAD_TOO_LARGE, "more items than a device can pull in one go: push fewer at a time");
/// 507, not 413: clients tell a full account from a request that's too big.
const FULL: (StatusCode, &str) =
    (StatusCode::INSUFFICIENT_STORAGE, "the account this counts against is out of storage: delete items, share links or sent messages, or leave a vault someone handed you, to make room (attachments are freed about a week later, by a device that syncs the vault)");

pub fn open_db(path: &str) -> rusqlite::Result<Connection> {
    let c = Connection::open(path)?;
    c.execute_batch(include_str!("schema.sql"))?;
    // Who a vault's storage counts against. Added after v1 shipped, so every
    // database (new ones too) gets it here: roster v0's signer if still a current
    // member, otherwise one, owners first (as when the creator's account is deleted).
    if !has_col(&c, "vaults", "creator")? {
        c.execute_batch(
            "BEGIN;
             ALTER TABLE vaults ADD COLUMN creator TEXT;
             UPDATE vaults SET creator = (SELECT COALESCE(a.owner, m.username) FROM members m JOIN accounts a ON a.username = m.username
               WHERE m.vault_id = vaults.id AND (m.expires IS NULL OR m.expires > unixepoch()) AND a.disabled = 0
               ORDER BY m.username = (SELECT json_extract(signed, '$.signer') FROM rosters r WHERE r.vault_id = m.vault_id AND r.version = 0) DESC,
                        m.role = 'owner' DESC, m.username LIMIT 1);
             CREATE INDEX vaults_creator ON vaults(creator);
             COMMIT;",
        )?;
    }
    // Sessions end on the server too. Existing ones get the full term from now.
    if !has_col(&c, "sessions", "expires")? {
        c.execute_batch(&format!(
            "BEGIN;
             ALTER TABLE sessions ADD COLUMN expires INTEGER NOT NULL DEFAULT 0;
             UPDATE sessions SET expires = unixepoch() + {SESSION_TTL};
             CREATE INDEX sessions_expires ON sessions(expires);
             COMMIT;"
        ))?;
    }
    // Messages count against their sender's quota.
    if !has_col(&c, "messages", "sender")? {
        c.execute_batch(
            "BEGIN;
             ALTER TABLE messages ADD COLUMN sender TEXT;
             UPDATE messages SET sender = json_extract(signed, '$.signer');
             CREATE INDEX messages_sender ON messages(sender);
             COMMIT;",
        )?;
    }
    // Each account's signed ML-KEM key (`KemPub`), for post-quantum sealing.
    if !has_col(&c, "accounts", "kem")? {
        c.execute("ALTER TABLE accounts ADD COLUMN kem TEXT", [])?;
    }
    // A disabled person's agents are disabled with them (databases from before that rule).
    c.execute("UPDATE accounts SET disabled = 1 WHERE disabled = 0 AND owner IN (SELECT username FROM accounts WHERE disabled = 1)", [])?;
    Ok(c)
}

fn has_col(c: &Connection, table: &str, col: &str) -> rusqlite::Result<bool> {
    c.query_row("SELECT COUNT(*) FROM pragma_table_info(?1) WHERE name = ?2", [table, col], |r| r.get(0))
}

/// Deletes expired links, messages and sessions. Requests skip expired rows
/// themselves, so this only keeps the tables small.
fn cleanup(db: &Connection) -> rusqlite::Result<()> {
    let t = now();
    db.execute("DELETE FROM links WHERE expires <= ?", [t])?;
    db.execute("DELETE FROM messages WHERE expires <= ?", [t])?;
    db.execute("DELETE FROM sessions WHERE expires <= ?", [t])?;
    db.execute("DELETE FROM staged WHERE created <= ?", [t - STAGE_TTL])?;
    Ok(())
}

/// Writes a consistent copy of the database at `db_path` to `<dir>/backup/<name>`,
/// for volume backups that copy files one by one while the server writes. Uses
/// its own connection (WAL lets it read while requests write) and replaces the
/// previous copy atomically, so a backup sees either the old or the new copy.
pub fn backup_copy(db_path: &str) -> std::io::Result<std::path::PathBuf> {
    let db = std::path::Path::new(db_path);
    let dir = db.parent().unwrap_or(std::path::Path::new("")).join("backup");
    std::fs::create_dir_all(&dir)?;
    let name = db.file_name().ok_or(std::io::ErrorKind::InvalidInput)?;
    let dest = dir.join(name);
    let mut tmp_name = name.to_os_string();
    tmp_name.push(".tmp");
    let tmp = dir.join(tmp_name);
    match std::fs::remove_file(&tmp) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let c = Connection::open(db).map_err(std::io::Error::other)?;
    let tmp_str = tmp.to_str().ok_or(std::io::ErrorKind::InvalidInput)?;
    if let Err(e) = c.execute("VACUUM INTO ?1", [tmp_str]) {
        let _ = std::fs::remove_file(&tmp);
        return Err(std::io::Error::other(e));
    }
    std::fs::File::open(&tmp)?.sync_all()?;
    std::fs::rename(&tmp, &dest)?;
    std::fs::File::open(&dir)?.sync_all()?;
    Ok(dest)
}

#[derive(Clone, Default)]
pub struct Config {
    /// If set, the first account must present it (so nobody can race you to
    /// become admin of a fresh public server).
    pub setup_code: Option<String>,
    /// Anyone may sign up without an invite (a hosted server). The directory then
    /// stops listing everyone: people are looked up by exact username.
    pub open_signup: bool,
    /// The hosts clients reach this server at (`crypto::server_host`). Logins
    /// signed for any other host are refused. Empty: the request's Host header,
    /// which is weaker if the port is also reachable directly.
    pub hosts: Vec<String>,
    /// Bytes of items and files each account may keep in the vaults it created.
    /// `None`: unlimited (the self-hosting default).
    pub quota: Option<u64>,
    /// Behind a reverse proxy: rate-limit by the last `X-Forwarded-For` address
    /// (the one the proxy added) instead of the connection's.
    pub trust_proxy: bool,
    /// Clients reach this server over HTTPS (a `PLAINTEXT_URL` entry starts with
    /// `https://`): every response tells browsers to keep using it.
    pub hsts: bool,
}

/// Whether any comma-separated `PLAINTEXT_URL` entry is an `https://` address
/// (`Config::hsts`); read before `crypto::server_host` drops the scheme.
pub fn https_url(urls: &str) -> bool {
    urls.split(',').any(|u| u.trim().get(..8).is_some_and(|s| s.eq_ignore_ascii_case("https://")))
}

/// Serve `app` with each connection's address, which the rate limits need.
pub async fn serve(listener: tokio::net::TcpListener, db: Connection, cfg: Config) -> std::io::Result<()> {
    axum::serve(listener, app(db, cfg).into_make_service_with_connect_info::<SocketAddr>()).await
}

fn app(db: Connection, cfg: Config) -> Router {
    let db: Db = Arc::new(Mutex::new(db));
    let weak = Arc::downgrade(&db);
    std::thread::spawn(move || {
        while let Some(db) = weak.upgrade() {
            if let Err(e) = cleanup(&lock(&db)) {
                eprintln!("cleanup failed: {e}");
            }
            drop(db);
            std::thread::sleep(std::time::Duration::from_secs(600));
        }
    });
    let hsts = cfg.hsts;
    let limits = axum::middleware::from_fn(rate_limit);
    let big = |n: usize| (axum::middleware::from_fn_with_state(db.clone(), signed_in), DefaultBodyLimit::max(n));
    Router::new()
        .route("/v1/signup", post(signup).layer(limits.clone()))
        .route("/v1/agents", post(create_agent))
        .route("/v1/login", post(login).layer(limits))
        .route("/v1/logout", post(logout))
        .route("/v1/account", get(account).delete(delete_account))
        .route("/v1/account/keyring", put(put_keyring.layer(big(BLOB_BODY))))
        .route("/v1/account/kem", put(put_kem))
        .route("/v1/account/password", post(change_password))
        .route("/v1/sessions", get(sessions))
        .route("/v1/sessions/{id}", axum::routing::delete(end_session))
        .route("/v1/info", get(info))
        .route("/v1/users", get(users))
        .route("/v1/users/{name}", get(user))
        .route("/v1/users/{name}/disable", post(disable_user))
        .route("/v1/invites", post(create_invite))
        .route("/v1/vaults", post(create_vault.layer(big(VAULT_BODY))))
        .route("/v1/vaults/{id}", get(get_vault).put(put_vault.layer(big(VAULT_BODY))))
        .route("/v1/vaults/{id}/roster", post(update_roster.layer(big(VAULT_BODY))))
        .route("/v1/vaults/{id}/stage", post(stage.layer(big(VAULT_BODY))))
        .route("/v1/vaults/{id}/leave", post(leave))
        .route("/v1/vaults/{id}/audit", get(audit))
        .route("/v1/vaults/{id}/files", get(list_files))
        .route("/v1/vaults/{id}/files/{fid}", get(get_file).put(put_file.layer(big(MAX_FILE))).delete(delete_file))
        .route("/v1/messages", get(inbox).post(send_message.layer(big(BLOB_BODY))))
        .route("/v1/messages/{id}", axum::routing::delete(delete_message))
        .route("/v1/links", post(create_link.layer(big(BLOB_BODY))))
        // HEAD would otherwise run the GET handler and use up a view.
        .route("/v1/links/{id}", get(open_link).head(|| async { StatusCode::METHOD_NOT_ALLOWED }).delete(delete_link))
        .route("/health", get(|| async { "ok" }))
        .layer(DefaultBodyLimit::max(SMALL_BODY))
        .layer(axum::middleware::map_response(|mut r: Response| async {
            r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            r
        }))
        .layer(axum::Extension(cfg))
        .layer(axum::Extension(Arc::new(Limiter::default())))
        .with_state(db)
        // Outermost, so 404s and body-limit refusals carry it too.
        .layer(axum::middleware::map_response(move |mut r: Response| async move {
            if hsts {
                r.headers_mut().insert(header::STRICT_TRANSPORT_SECURITY, HeaderValue::from_static("max-age=31536000"));
            }
            r
        }))
}

/// Refuses a request without a valid session before its body is read.
async fn signed_in(State(db): State<Db>, req: Request, next: axum::middleware::Next) -> Response {
    if let Err(e) = caller(&lock(&db), req.headers()) {
        return e.into_response();
    }
    next.run(req).await
}

// ---------- Rate limits ----------

/// Signups, and failed logins, per client address and hour on open servers.
const SIGNUPS_PER_HOUR: u32 = 10;
const FAILED_LOGINS_PER_HOUR: u32 = 30;

/// Addresses tracked per hour; past this, new addresses are refused until the hour ends.
const LIMITER_KEYS: usize = 100_000;

// ponytail: in-memory windows per clock hour, so they reset on restart and aren't
// shared between processes. Move to SQLite or the proxy if the server ever runs as several.
#[derive(Default)]
struct Limiter(Mutex<(u64, HashMap<LimitKey, u32>)>);

/// A client address, and whether it's signing up (or else logging in).
type LimitKey = (IpAddr, bool);

impl Limiter {
    /// Takes one attempt for `key` if it has any left this hour.
    fn take(&self, key: LimitKey, max: u32) -> bool {
        let mut guard = lock(&self.0);
        let (hour, map) = &mut *guard;
        if *hour != now() / 3600 {
            *hour = now() / 3600;
            map.clear();
        }
        // A full table refuses new signups but lets logins through, so nobody can
        // lock everyone out by filling it (a login needs the Secret Key anyway).
        if map.len() >= LIMITER_KEYS && !map.contains_key(&key) {
            return !key.1;
        }
        let n = map.entry(key).or_insert(0);
        if *n >= max {
            return false;
        }
        *n += 1;
        true
    }

    fn give_back(&self, key: LimitKey) {
        if let Some(n) = lock(&self.0).1.get_mut(&key) {
            *n = n.saturating_sub(1);
        }
    }
}

/// The hosts logins and account deletions must be signed for.
fn own_hosts(cfg: &Config, h: &HeaderMap) -> R<Vec<String>> {
    if !cfg.hosts.is_empty() {
        return Ok(cfg.hosts.clone());
    }
    // Without PLAINTEXT_URL the Host header is all we have, and a look-alike
    // server relaying a login sets it to anything. Only this machine can be trusted.
    let host = h.get(header::HOST).and_then(|v| v.to_str().ok()).map(server_host).filter(|h| loopback(h));
    Ok(vec![host.ok_or((StatusCode::FORBIDDEN, "this server doesn't know its own address: its operator needs to set PLAINTEXT_URL"))?])
}

/// `localhost`, a loopback IPv4 address or `[::1]`, optionally with a port, and nothing else.
fn loopback(host: &str) -> bool {
    let (name, rest) = match host.strip_prefix('[') {
        Some(r) => r.split_once(']').unwrap_or(("", "")),
        None => host.find(':').map_or((host, ""), |i| host.split_at(i)),
    };
    let port_ok = rest.is_empty() || rest.strip_prefix(':').is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    port_ok && (name == "localhost" || name.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback()))
}

/// The address to rate-limit by. IPv6 counts per /64, since one host usually has the whole block.
fn client_ip(cfg: &Config, h: &HeaderMap, peer: IpAddr) -> IpAddr {
    // Proxies append to the header or add another one; either way the last entry is theirs.
    let forwarded = || {
        let last = h.get_all("x-forwarded-for").iter().next_back()?.to_str().ok()?.rsplit(',').next()?.trim();
        // Some proxies add a port (`1.2.3.4:5678`, `[::1]:80`) or brackets.
        last.parse::<SocketAddr>().map(|a| a.ip()).or_else(|_| last.trim_start_matches('[').trim_end_matches(']').parse()).ok()
    };
    let ip = if cfg.trust_proxy { forwarded().unwrap_or(peer) } else { peer }.to_canonical();
    match ip {
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & !((1u128 << 64) - 1))),
        v4 => v4,
    }
}

async fn rate_limit(
    axum::Extension(cfg): axum::Extension<Config>,
    axum::Extension(limiter): axum::Extension<Arc<Limiter>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
    next: axum::middleware::Next,
) -> Response {
    if !cfg.open_signup {
        return next.run(req).await;
    }
    let signup = req.uri().path() == "/v1/signup";
    let key = (client_ip(&cfg, req.headers(), peer.ip()), signup);
    let allowed = limiter.take(key, if signup { SIGNUPS_PER_HOUR } else { FAILED_LOGINS_PER_HOUR });
    let too_many = || (StatusCode::TOO_MANY_REQUESTS, "too many attempts from your address; try again in an hour").into_response();
    if signup {
        return if allowed { next.run(req).await } else { too_many() };
    }
    // A correct login always works, even past the limit: others behind the same
    // address mustn't be able to lock everyone out, and the login key can't be guessed.
    // Successful logins don't count either: agents sign in on every run.
    let resp = next.run(req).await;
    match (resp.status().is_success(), allowed) {
        (true, true) => {
            limiter.give_back(key);
            resp
        }
        (false, false) => too_many(),
        _ => resp,
    }
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
    /// Whose quota the caller's links and messages count against: an agent's owner.
    payer: String,
}

fn caller(db: &Connection, h: &HeaderMap) -> R<Caller> {
    let token = h
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or((StatusCode::UNAUTHORIZED, "no token"))?;
    let th = sha256(token.as_bytes()).to_vec();
    db.query_row(
        "SELECT a.id, a.username, a.kind, a.admin, COALESCE(a.owner, a.username) FROM sessions s JOIN accounts a ON a.id = s.account_id
         WHERE s.token_hash = ? AND s.expires > ? AND a.disabled = 0",
        params![&th, now()],
        |r| Ok(Caller { id: r.get(0)?, username: r.get(1)?, human: r.get::<_, String>(2)? == "human", admin: r.get(3)?, token_hash: th.clone(), payer: r.get(4)? }),
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

/// The largest signed body of each kind: its sealed part in base64, with room
/// for the rest. Checked before anything is parsed.
fn max_body(domain: &str) -> usize {
    match domain {
        "identity" => 2 << 10,
        "kem" => 4 << 10,
        // Up to 1000 members, each with a signed ML-KEM key (about 2.3 KiB).
        "roster" => 4 << 20,
        "leave" => 256,
        "message" => MAX_BLOB / 3 * 4 + (4 << 10),
        "manifest" => MAX_MANIFEST / 3 * 4 + (4 << 10),
        _ => 0,
    }
}

/// A signed `KemPub` for `username`, signed by `sign_pk`.
fn check_kem(doc: &Signed, username: &str, sign_pk: &[u8]) -> R<()> {
    if doc.signer != username || doc.body.0.len() > max_body("kem") {
        return Err((BAD, "bad ML-KEM key"));
    }
    plaintext_core::identity::check_kem(doc, sign_pk).map(drop).map_err(|_| (BAD, "bad ML-KEM key"))
}

/// The signed `KemPub` an account published, if any.
fn kem_of(db: &Connection, username: &str) -> R<Option<Signed>> {
    let s: Option<Option<String>> = db.query_row("SELECT kem FROM accounts WHERE username = ?", [username], |r| r.get(0)).optional().map_err(db_err)?;
    s.flatten().map(|s| serde_json::from_str(&s).map_err(db_err)).transpose()
}

fn verify_signed(db: &Connection, s: &Signed, domain: &str, expected_signer: &str) -> R<()> {
    if s.signer != expected_signer {
        return Err((BAD, "signer must be you"));
    }
    if s.body.0.len() > max_body(domain) {
        return Err((BAD, "document too large"));
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
    // Owners see the newest 1000 (`audit`); older rows would only take up room.
    db.execute(
        "DELETE FROM audit WHERE vault_id = ?1 AND rowid NOT IN (SELECT rowid FROM audit WHERE vault_id = ?1 ORDER BY ts DESC, rowid DESC LIMIT 1000)",
        [vault],
    )
    .map_err(db_err)?;
    Ok(())
}

// ---------- Accounts ----------

fn insert_account(tx: &Transaction, req: &SignupRequest, kind: Kind, owner: Option<&str>, admin: bool) -> R<Identity> {
    check_blob(&req.account_key)?;
    check_blob(&req.keyring)?;
    if req.identity.body.0.len() > max_body("identity") {
        return Err((BAD, "document too large"));
    }
    let auth: [u8; 32] = req.auth_key.0.as_slice().try_into().map_err(|_| (BAD, "auth key"))?;
    ed25519_dalek::VerifyingKey::from_bytes(&auth).map_err(|_| (BAD, "auth key"))?;
    let id: Identity = parse(&req.identity)?;
    verify(&id.sign_pk.0, "identity", &req.identity.body.0, &req.identity.sig.0).map_err(|_| (BAD, "bad signature"))?;
    if req.identity.signer != id.username || !valid_username(&id.username) || id.kind != kind || id.owner.as_deref() != owner {
        return Err((BAD, "bad identity"));
    }
    if let Some(k) = &req.kem {
        check_kem(k, &id.username, &id.sign_pk.0)?;
    }
    let (invite_id, proof) = req.invite.as_ref().map(|i| (i.id.0.to_vec(), i.proof.0.clone())).unzip();
    let inserted = tx
        .execute(
            "INSERT OR IGNORE INTO accounts(id, username, kind, owner, identity, auth_key, account_key, keyring, admin, invite_id, invite_proof, created, kem)
             VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
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
                now(),
                req.kem.as_ref().map(json)
            ],
        )
        .map_err(db_err)?;
    if inserted == 0 {
        return Err((StatusCode::CONFLICT, "that username or account is taken"));
    }
    Ok(id)
}

async fn info(State(db): State<Db>, axum::Extension(cfg): axum::Extension<Config>) -> R<Json<ServerInfo>> {
    let db = lock(&db);
    let empty = db.query_row("SELECT COUNT(*) FROM accounts", [], |r| r.get::<_, i64>(0)).map_err(db_err)? == 0;
    Ok(Json(ServerInfo { version: env!("CARGO_PKG_VERSION").into(), open: cfg.open_signup, setup: empty && cfg.setup_code.is_some() }))
}

async fn signup(State(db): State<Db>, axum::Extension(cfg): axum::Extension<Config>, Json(req): Json<SignupRequest>) -> R<StatusCode> {
    let mut db = lock(&db);
    let tx = db.transaction().map_err(db_err)?;
    let first = tx.query_row("SELECT COUNT(*) FROM accounts", [], |r| r.get::<_, i64>(0)).map_err(db_err)? == 0;
    if first && let Some(code) = &cfg.setup_code {
        let given = req.setup.as_deref().unwrap_or_default();
        if !bool::from(subtle::ConstantTimeEq::ct_eq(given.as_bytes(), code.as_bytes())) {
            return Err((StatusCode::FORBIDDEN, "this server needs its setup code for the first account"));
        }
    }
    // On open servers an invite is optional, but one that's given must be valid.
    if !first && (!cfg.open_signup || req.invite.is_some()) {
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
    let mut db = lock(&db);
    let c = caller(&db, &h)?;
    if !c.human || req.vault.is_some() || req.invite.is_some() {
        return Err(DENIED);
    }
    let tx = db.transaction().map_err(db_err)?;
    insert_account(&tx, &req, Kind::Agent, Some(&c.username), false)?;
    tx.commit().map_err(db_err)?;
    Ok(StatusCode::CREATED)
}

async fn login(State(db): State<Db>, axum::Extension(cfg): axum::Extension<Config>, h: HeaderMap, Json(req): Json<LoginRequest>) -> R<Json<LoginResponse>> {
    let denied = (StatusCode::UNAUTHORIZED, "login failed");
    if req.ts.abs_diff(now_ms()) > LOGIN_SKEW_MS || req.device.len() > 200 {
        return Err(denied);
    }
    let db = lock(&db);
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
    let hosts = own_hosts(&cfg, &h)?;
    if req.ts <= last || !hosts.iter().any(|host| key.verify_strict(&login_message(&req.account_id.0, req.ts, host), &sig).is_ok()) {
        return Err(denied);
    }
    let mut raw = [0u8; 32];
    getrandom::fill(&mut raw).map_err(db_err)?;
    let token = hex::encode(raw);
    db.execute("UPDATE accounts SET last_login = ? WHERE id = ?", params![req.ts, &req.account_id.0[..]]).map_err(db_err)?;
    db.execute(
        "INSERT INTO sessions(token_hash, account_id, device, created, expires) VALUES(?,?,?,?,?)",
        params![&sha256(token.as_bytes())[..], &req.account_id.0[..], req.device, now(), now() + req.ttl.unwrap_or(SESSION_TTL).min(SESSION_TTL)],
    )
    .map_err(db_err)?;
    Ok(Json(LoginResponse { token }))
}

async fn logout(State(db): State<Db>, h: HeaderMap) -> R<StatusCode> {
    let db = lock(&db);
    let c = caller(&db, &h)?;
    db.execute("DELETE FROM sessions WHERE token_hash = ?", [&c.token_hash]).map_err(db_err)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn account(State(db): State<Db>, axum::Extension(cfg): axum::Extension<Config>, h: HeaderMap) -> R<Json<AccountResponse>> {
    let db = lock(&db);
    let c = caller(&db, &h)?;
    let (account_key, keyring, keyring_counter, kem) = db
        .query_row("SELECT account_key, keyring, keyring_counter, kem FROM accounts WHERE id = ?", [&c.id], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get::<_, Option<String>>(3)?))
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
    let usage = usage(&db, Some(&c.username))?;
    let paid = db
        .prepare("SELECT id FROM vaults WHERE creator = ?")
        .map_err(db_err)?
        .query_map([&c.username], |r| r.get::<_, Vec<u8>>(0))
        .map_err(db_err)?
        .filter_map(|v| v.ok()?.try_into().ok().map(Hex))
        .collect();
    Ok(Json(AccountResponse {
        username: c.username,
        admin: c.admin,
        account_key: B64(account_key),
        keyring: B64(keyring),
        keyring_counter,
        vaults,
        quota: cfg.quota,
        usage,
        paid,
        kem: kem.and_then(|k| serde_json::from_str(&k).ok()),
    }))
}

/// Publish the caller's signed ML-KEM key, for accounts made before signup sent one.
async fn put_kem(State(db): State<Db>, h: HeaderMap, Json(doc): Json<Signed>) -> R<StatusCode> {
    let db = lock(&db);
    let c = caller(&db, &h)?;
    check_kem(&doc, &c.username, &sign_pk(&db, &c.username)?)?;
    db.execute("UPDATE accounts SET kem = ? WHERE id = ?", params![json(&doc), c.id]).map_err(db_err)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn put_keyring(State(db): State<Db>, h: HeaderMap, Json(req): Json<KeyringPut>) -> R<StatusCode> {
    check_blob(&req.keyring)?;
    let db = lock(&db);
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
    let db = lock(&db);
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

/// `col` names the account being deleted or one of its agents (`?1` is its username).
fn in_set(col: &str) -> String {
    format!("({col} = ?1 OR {col} IN (SELECT username FROM accounts WHERE owner = ?1))")
}

/// Takes `username` and their agents out of `vault`, which the remaining members'
/// owners then rekey (`gone` in the vault response). The vault is deleted if
/// nobody else uses it. With `keep_an_owner`, refused while `username` is its only
/// owner and others use it.
fn leave_vault(tx: &Transaction, vault: &[u8], username: &str, why: &str, keep_an_owner: bool) -> R<()> {
    // Members who keep the vault: current, not disabled, not leaving.
    let rest: Vec<(String, String)> = tx
        .prepare(&format!(
            "SELECT m.username, m.role FROM members m JOIN accounts a ON a.username = m.username
             WHERE m.vault_id = ?2 AND (m.expires IS NULL OR m.expires > ?3) AND a.disabled = 0 AND NOT {}
             ORDER BY m.username",
            in_set("m.username")
        ))
        .map_err(db_err)?
        .query_map(params![username, vault, now()], |r| Ok((r.get(0)?, r.get(1)?)))
        .map_err(db_err)?
        .collect::<Result<_, _>>()
        .map_err(db_err)?;
    if rest.is_empty() {
        tx.execute("DELETE FROM vaults WHERE id = ?", [vault]).map_err(db_err)?;
        return Ok(());
    }
    let owns: bool = keep_an_owner
        && tx
        .query_row(
            &format!("SELECT COUNT(*) FROM members WHERE vault_id = ?2 AND role = 'owner' AND (expires IS NULL OR expires > ?3) AND {}", in_set("username")),
            params![username, vault, now()],
            |r| r.get(0),
        )
        .map_err(db_err)?;
    if owns && !rest.iter().any(|(_, role)| role == "owner") {
        return Err((StatusCode::CONFLICT, "you're the only owner of a vault others use: make one of them an owner, remove them, or leave it, first"));
    }
    for table in ["members", "vault_keys", "staged"] {
        tx.execute(&format!("DELETE FROM {table} WHERE vault_id = ?2 AND {}", in_set("username")), params![username, vault]).map_err(db_err)?;
    }
    hand_off(tx, username, Some(vault))?;
    audit_log(tx, vault, username, why)
}

/// Vaults that live on without whoever they count against move to a remaining
/// member, owners first: every vault `username` created, or just `vault` if
/// neither its payer nor any agent of theirs is a member any more.
fn hand_off(tx: &Transaction, username: &str, vault: Option<&[u8]>) -> R<()> {
    let whose = match vault {
        Some(_) => "id = ?3 AND creator NOT IN (SELECT COALESCE(a.owner, m.username) FROM members m JOIN accounts a ON a.username = m.username
                    WHERE m.vault_id = ?3)"
            .to_string(),
        // ?3 (NULL here) keeps both forms' parameters the same.
        None => format!("{} AND ?3 IS NULL", in_set("creator")),
    };
    tx.execute(
        &format!(
            "UPDATE vaults SET creator = (SELECT COALESCE(a.owner, m.username) FROM members m JOIN accounts a ON a.username = m.username
               WHERE m.vault_id = vaults.id AND (m.expires IS NULL OR m.expires > ?2) AND a.disabled = 0
               ORDER BY m.role = 'owner' DESC, a.owner IS NOT NULL, m.username LIMIT 1)
             WHERE {whose}"
        ),
        params![username, now(), vault],
    )
    .map_err(db_err)?;
    Ok(())
}

/// Deletes the caller's account and its agents. Their vaults that nobody else
/// uses go too; shared vaults stop serving them, and the remaining owners'
/// devices replace the key (`gone` in the vault response). Refused while they
/// are the only owner of a vault others use, or the admin of a server others use.
async fn delete_account(
    State(db): State<Db>,
    axum::Extension(cfg): axum::Extension<Config>,
    h: HeaderMap,
    Json(req): Json<AccountDelete>,
) -> R<StatusCode> {
    let hosts = own_hosts(&cfg, &h)?;
    let mut db = lock(&db);
    let c = caller(&db, &h)?;
    let auth: Vec<u8> = db.query_row("SELECT auth_key FROM accounts WHERE id = ?", [&c.id], |r| r.get(0)).map_err(db_err)?;
    let id: [u8; 16] = c.id.as_slice().try_into().map_err(db_err)?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&auth.try_into().map_err(db_err)?).map_err(db_err)?;
    let sig = ed25519_dalek::Signature::from_slice(&req.sig.0).map_err(|_| (BAD, "bad signature"))?;
    if req.ts.abs_diff(now_ms()) > LOGIN_SKEW_MS || !hosts.iter().any(|host| key.verify_strict(&account_delete_message(&id, req.ts, host), &sig).is_ok()) {
        return Err((StatusCode::UNAUTHORIZED, "re-enter your password"));
    }
    let tx = db.transaction().map_err(db_err)?;
    let others = format!("SELECT COUNT(*) FROM accounts WHERE NOT {}", in_set("username"));
    if c.admin && tx.query_row(&format!("{others} AND admin = 0"), [&c.username], |r| r.get::<_, i64>(0)).map_err(db_err)? > 0
        && tx.query_row(&format!("{others} AND admin = 1"), [&c.username], |r| r.get::<_, i64>(0)).map_err(db_err)? == 0
    {
        return Err((StatusCode::CONFLICT, "you're this server's admin, and others still use it"));
    }
    let vaults: Vec<Vec<u8>> = tx
        .prepare(&format!("SELECT DISTINCT vault_id FROM members WHERE {}", in_set("username")))
        .map_err(db_err)?
        .query_map([&c.username], |r| r.get(0))
        .map_err(db_err)?
        .collect::<Result<_, _>>()
        .map_err(db_err)?;
    for v in vaults {
        leave_vault(&tx, &v, &c.username, "account deleted", true)?;
    }
    // Including keys from vaults they were removed from earlier.
    tx.execute(&format!("DELETE FROM vault_keys WHERE {}", in_set("username")), [&c.username]).map_err(db_err)?;
    hand_off(&tx, &c.username, None)?;
    // Messages they sent stay with the recipients, but no longer count against the username.
    tx.execute(&format!("UPDATE messages SET sender = NULL WHERE {}", in_set("sender")), [&c.username]).map_err(db_err)?;
    for (table, col) in [("messages", "to_user"), ("links", "creator"), ("invites", "created_by")] {
        tx.execute(&format!("DELETE FROM {table} WHERE {}", in_set(col)), [&c.username]).map_err(db_err)?;
    }
    tx.execute(&format!("DELETE FROM sessions WHERE account_id IN (SELECT id FROM accounts WHERE {})", in_set("username")), [&c.username])
        .map_err(db_err)?;
    tx.execute("DELETE FROM accounts WHERE owner = ?1 OR username = ?1", [&c.username]).map_err(db_err)?;
    tx.commit().map_err(db_err)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn sessions(State(db): State<Db>, h: HeaderMap) -> R<Json<Vec<DeviceSession>>> {
    let db = lock(&db);
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
    let db = lock(&db);
    let c = caller(&db, &h)?;
    let prefix = hex::decode(&id).map_err(|_| (BAD, "bad id"))?;
    if prefix.len() != 8 {
        return Err((BAD, "bad id"));
    }
    db.execute("DELETE FROM sessions WHERE account_id = ? AND substr(token_hash, 1, 8) = ?", params![c.id, prefix]).map_err(db_err)?;
    Ok(StatusCode::NO_CONTENT)
}

const USER_COLS: &str = "SELECT identity, admin, disabled, invite_id, invite_proof, kem FROM accounts";

/// The directory. On an open (hosted) server only admins see everyone; others
/// see the people who joined with their invites, so their devices can verify them,
/// and their own agents.
async fn users(State(db): State<Db>, axum::Extension(cfg): axum::Extension<Config>, h: HeaderMap) -> R<Json<Vec<UserInfo>>> {
    let db = lock(&db);
    let c = caller(&db, &h)?;
    let (filter, who) = if cfg.open_signup && !c.admin {
        (" WHERE owner = ?1 OR invite_id IN (SELECT id FROM invites WHERE created_by = ?1)", c.username)
    } else {
        (" WHERE ?1 = ?1", String::new())
    };
    Ok(Json(user_rows(&db, &format!("{USER_COLS}{filter} ORDER BY username"), &who)?))
}

/// One person by exact username, on any server.
async fn user(State(db): State<Db>, h: HeaderMap, Path(name): Path<String>) -> R<Json<UserInfo>> {
    let db = lock(&db);
    caller(&db, &h)?;
    user_rows(&db, &format!("{USER_COLS} WHERE username = ?1"), &name)?.pop().map(Json).ok_or((StatusCode::NOT_FOUND, "no such user"))
}

fn user_rows(db: &Connection, sql: &str, arg: &str) -> R<Vec<UserInfo>> {
    let mut q = db.prepare(sql).map_err(db_err)?;
    let list = q
        .query_map([arg], |r| {
            let id: String = r.get(0)?;
            let inv: Option<Vec<u8>> = r.get(3)?;
            let proof: Option<Vec<u8>> = r.get(4)?;
            Ok((id, r.get(1)?, r.get(2)?, inv.zip(proof), r.get::<_, Option<String>>(5)?))
        })
        .map_err(db_err)?
        .filter_map(|row| {
            let (id, admin, disabled, inv, kem) = row.ok()?;
            let invite = inv.and_then(|(i, p)| Some(InviteProof { id: Hex(i.try_into().ok()?), proof: B64(p) }));
            let kem = kem.and_then(|k| serde_json::from_str(&k).ok());
            Some(UserInfo { identity: serde_json::from_str(&id).ok()?, admin, disabled, invite, kem })
        })
        .collect();
    Ok(list)
}

async fn disable_user(State(db): State<Db>, h: HeaderMap, Path(name): Path<String>) -> R<StatusCode> {
    let db = lock(&db);
    let c = caller(&db, &h)?;
    // Admins disable anyone but themselves; humans disable the agents they own.
    let owner: Option<Option<String>> =
        db.query_row("SELECT owner FROM accounts WHERE username = ?", [&name], |r| r.get(0)).optional().map_err(db_err)?;
    let Some(owner) = owner else { return Err((StatusCode::NOT_FOUND, "no such user")) };
    if name == c.username || !(c.admin || owner.as_deref() == Some(c.username.as_str())) {
        return Err(DENIED);
    }
    // Their agents go with them: the person still holds the agents' keys.
    db.execute(&format!("UPDATE accounts SET disabled = 1 WHERE {}", in_set("username")), [&name]).map_err(db_err)?;
    db.execute(&format!("DELETE FROM sessions WHERE account_id IN (SELECT id FROM accounts WHERE {})", in_set("username")), [&name])
        .map_err(db_err)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn create_invite(State(db): State<Db>, axum::Extension(cfg): axum::Extension<Config>, h: HeaderMap, Json(req): Json<NewInvite>) -> R<StatusCode> {
    let db = lock(&db);
    let c = caller(&db, &h)?;
    // Anyone may invite on an open server: signup needs no invite there, and an
    // invite still verifies both people.
    if !(c.admin || cfg.open_signup && c.human) {
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

/// Bytes `account` stores: items, files, staged items and the latest roster and
/// manifest of the vaults it created, and the share links and messages it and its
/// agents sent.
// ponytail: earlier rosters and manifests aren't counted (see "Known limits" in DESIGN.md).
fn usage(db: &Connection, account: Option<&str>) -> R<u64> {
    db.query_row(
        &format!(
            "SELECT (SELECT COALESCE(SUM(length(blob)), 0) FROM items WHERE vault_id IN (SELECT id FROM vaults WHERE creator = ?1))
                  + (SELECT COALESCE(SUM(length(blob)), 0) FROM files WHERE vault_id IN (SELECT id FROM vaults WHERE creator = ?1))
                  + (SELECT COALESCE(SUM(length(blob)), 0) FROM staged WHERE vault_id IN (SELECT id FROM vaults WHERE creator = ?1))
                  + (SELECT COALESCE(SUM(octet_length(r.signed)), 0) FROM rosters r JOIN vaults v ON v.id = r.vault_id AND v.roster_version = r.version
                     WHERE v.creator = ?1)
                  + (SELECT COALESCE(SUM(octet_length(m.signed)), 0) FROM manifests m JOIN vaults v ON v.id = m.vault_id AND v.counter = m.counter
                     WHERE v.creator = ?1)
                  + (SELECT COALESCE(SUM(length(blob)), 0) FROM links WHERE {})
                  + (SELECT COALESCE(SUM(octet_length(signed)), 0) FROM messages WHERE {})",
            in_set("creator"),
            in_set("sender")
        ),
        [account],
        |r| r.get(0),
    )
    .map_err(db_err)
}

/// Who a vault's storage counts against.
fn creator(db: &Connection, vault: &[u8]) -> R<Option<String>> {
    db.query_row("SELECT creator FROM vaults WHERE id = ?", [vault], |r| r.get(0)).map_err(db_err)
}

/// Runs a write and keeps it only if `account` stays within the quota or the
/// write doesn't add anything, so deleting and re-sealing always work.
// ponytail: sums the account's storage on every write; keep a running total if accounts get big.
fn within_quota<T>(tx: &Transaction, cfg: &Config, account: Option<&str>, write: impl FnOnce() -> R<T>) -> R<T> {
    let Some(quota) = cfg.quota else { return write() };
    let before = usage(tx, account)?;
    let out = write()?;
    let after = usage(tx, account)?;
    if after > quota && after > before {
        return Err(FULL);
    }
    Ok(out)
}

/// `within_quota` for a roster change into `vault` signed by `signer`, checked
/// against whoever pays once it's stored: removing the creator moves the vault to
/// the signer's account (its owner's, for an agent), which then mustn't end up over
/// the quota with more than it had. The signer's staged items for the vault don't
/// count as room the change frees: a new key's re-seal (in `write`) uses them up.
fn roster_within_quota<T>(tx: &Transaction, cfg: &Config, vault: &[u8], signer: &str, write: impl FnOnce() -> R<T>) -> R<T> {
    let Some(quota) = cfg.quota else { return write() };
    let staged: u64 = tx
        .query_row("SELECT COALESCE(SUM(length(blob)), 0) FROM staged WHERE vault_id = ? AND username = ?", params![vault, signer], |r| r.get(0))
        .map_err(db_err)?;
    let signer: Option<String> =
        tx.query_row("SELECT COALESCE(owner, username) FROM accounts WHERE username = ?", [signer], |r| r.get(0)).map_err(db_err)?;
    let old = creator(tx, vault)?;
    let before = [(old.clone(), usage(tx, old.as_deref())?.saturating_sub(staged)), (signer.clone(), usage(tx, signer.as_deref())?)];
    let out = write()?;
    let payer = creator(tx, vault)?;
    let after = usage(tx, payer.as_deref())?;
    let before = before.iter().find(|(a, _)| *a == payer).map_or(0, |(_, u)| *u);
    if after > quota && after > before {
        return Err(FULL);
    }
    Ok(out)
}

/// Runs a push (or a key rotation's re-seal) into `vault` and keeps it if the
/// account it counts against stays within the quota or, over it, if the vault's
/// items take no more room and its sealed manifest is no larger than the one
/// before. The signed envelope around it can grow by a digit as the counter does,
/// so editing and deleting keep working when the account is full.
fn push_within_quota<T>(tx: &Transaction, cfg: &Config, vault: &[u8], write: impl FnOnce() -> R<T>) -> R<T> {
    let Some(quota) = cfg.quota else { return write() };
    // Items, sealed manifest, and bytes in the signed envelope beyond its known fields.
    let sizes = || -> R<(u64, usize, usize)> {
        let items: u64 = tx.query_row("SELECT COALESCE(SUM(length(blob)), 0) FROM items WHERE vault_id = ?", [vault], |r| r.get(0)).map_err(db_err)?;
        let manifest: String = tx
            .query_row("SELECT m.signed FROM manifests m JOIN vaults v ON v.id = m.vault_id AND v.counter = m.counter WHERE v.id = ?", [vault], |r| r.get(0))
            .map_err(db_err)?;
        let s: Signed = serde_json::from_str(&manifest).map_err(db_err)?;
        let env: ManifestEnvelope = parse(&s)?;
        Ok((items, env.sealed.0.len(), padding(&s, &env)))
    };
    let before = sizes()?;
    let out = write()?;
    let after = sizes()?;
    if (after.0 > before.0 || after.1 > before.1 || after.2 > before.2) && usage(tx, creator(tx, vault)?.as_deref())? > quota {
        return Err(FULL);
    }
    Ok(out)
}

/// Bytes of a signed document's body beyond what its known fields take (unknown
/// fields or whitespace): over the quota, nobody may grow a counted document that way.
fn padding<T: serde::Serialize>(s: &Signed, doc: &T) -> usize {
    s.body.0.len().saturating_sub(serde_json::to_vec(doc).map_or(0, |b| b.len()))
}

/// Store a roster version and refresh the members table from it.
fn store_roster(tx: &Transaction, vault: &[u8], s: &Signed, r: &Roster) -> R<()> {
    let names: std::collections::HashSet<&str> = r.members.iter().map(|m| m.username.as_str()).collect();
    if r.members.len() > MAX_MEMBERS || names.len() != r.members.len() {
        return Err((BAD, "a roster lists up to 1000 different members"));
    }
    if r.key_check.0.len() != 32 {
        return Err((BAD, "key check size"));
    }
    for m in &r.members {
        let id: Identity = parse(&serde_json::from_str::<Signed>(
            // Disabled accounts may stay listed (they can't sign in); revoke them to change the key.
            &tx.query_row("SELECT identity FROM accounts WHERE username = ?", [&m.username], |row| row.get::<_, String>(0))
                .optional()
                .map_err(db_err)?
                .ok_or((BAD, "a member doesn't exist"))?,
        )
        .map_err(db_err)?)?;
        if id.sign_pk != m.sign_pk || id.enc_pk != m.enc_pk {
            return Err((BAD, "a member's keys don't match their identity"));
        }
        // Signed by the member, so one they haven't published yet (a device that
        // hasn't synced since updating) is published with it.
        if let Some(k) = &m.kem {
            check_kem(k, &m.username, &m.sign_pk.0)?;
            match kem_of(tx, &m.username)? {
                None => drop(tx.execute("UPDATE accounts SET kem = ? WHERE username = ?", params![json(k), m.username]).map_err(db_err)?),
                Some(had) if had != *k => return Err((BAD, "a member's ML-KEM key doesn't match the one they published")),
                Some(_) => {}
            }
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
    // Only current writers can commit what they staged.
    tx.execute(
        "DELETE FROM staged WHERE vault_id = ?1 AND username NOT IN
           (SELECT username FROM members WHERE vault_id = ?1 AND role != 'reader' AND (expires IS NULL OR expires > ?2))",
        params![vault, now()],
    )
    .map_err(db_err)?;
    tx.execute(
        "UPDATE vaults SET roster_version = ?, roster_hash = ?, epoch = ? WHERE id = ?",
        params![r.version, &sha256(&s.body.0)[..], r.epoch, vault],
    )
    .map_err(db_err)?;
    // A creator who was removed (with any agents of theirs) stops paying for the
    // vault: the owner who removed them does (an agent's owner, if an agent signed).
    tx.execute(
        "UPDATE vaults SET creator = (SELECT COALESCE(owner, username) FROM accounts WHERE username = ?1)
         WHERE id = ?2 AND creator NOT IN (SELECT COALESCE(a.owner, m.username) FROM members m JOIN accounts a ON a.username = m.username
                                           WHERE m.vault_id = ?2)",
        params![s.signer, vault],
    )
    .map_err(db_err)?;
    Ok(())
}

/// Wrapped keys for members of the roster just stored, at its epoch. Keys of
/// other epochs (pulls serve only the current one) and of anyone no longer listed
/// go, so they never pile up.
fn store_keys(tx: &Transaction, vault: &[u8], keys: &[WrappedKey]) -> R<()> {
    if keys.len() > MAX_MEMBERS {
        return Err((BAD, "too many keys"));
    }
    let epoch: u64 = tx.query_row("SELECT epoch FROM vaults WHERE id = ?", [vault], |r| r.get(0)).map_err(db_err)?;
    tx.execute(
        "DELETE FROM vault_keys WHERE vault_id = ?1 AND (epoch != ?2 OR username NOT IN (SELECT username FROM members WHERE vault_id = ?1))",
        params![vault, epoch],
    )
    .map_err(db_err)?;
    for k in keys {
        // A post-quantum wrap is 1194 bytes (`crypto::seal_to`).
        if k.key.0.is_empty() || k.key.0.len() > 1536 {
            return Err((BAD, "key size"));
        }
        let member: bool = tx
            .query_row("SELECT COUNT(*) FROM members WHERE vault_id = ? AND username = ?", params![vault, k.username], |r| r.get(0))
            .map_err(db_err)?;
        if k.epoch != epoch || !member {
            return Err((BAD, "a key is for someone outside the roster or for another key epoch"));
        }
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
    let (counter, epoch, last, roster): (u64, u64, Option<Vec<u8>>, u64) = tx
        .query_row("SELECT counter, epoch, manifest_hash, roster_version FROM vaults WHERE id = ?", [vault], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })
        .map_err(db_err)?;
    if counter != put.expected_counter {
        return Err((StatusCode::CONFLICT, "vault changed, pull first"));
    }
    if env.vault_id.0[..] != *vault || env.counter != counter + 1 || env.epoch != epoch || env.roster > roster || env.prev.0 != last.unwrap_or_default() {
        return Err((BAD, "manifest doesn't extend the chain"));
    }
    if env.sealed.0.is_empty() || env.sealed.0.len() > MAX_MANIFEST {
        return Err((BAD, "manifest size"));
    }
    for u in &put.upserts {
        check_blob(&u.blob)?;
        tx.execute(
            "INSERT OR REPLACE INTO items(vault_id, id, blob, counter) VALUES(?,?,?,?)",
            params![vault, &u.id.0[..], u.blob.0, env.counter],
        )
        .map_err(db_err)?;
    }
    if let Some(st) = &put.staged {
        let n = tx
            .execute(
                "INSERT OR REPLACE INTO items(vault_id, id, blob, counter)
                 SELECT vault_id, id, blob, ?1 FROM staged WHERE vault_id = ?2 AND username = ?3 AND stage = ?4 AND created > ?5",
                params![env.counter, vault, username, &st.id.0[..], now() - STAGE_TTL],
            )
            .map_err(db_err)?;
        if n as u64 != st.count {
            return Err((StatusCode::CONFLICT, "the staged items are gone (another push from this account replaced them, or they expired): push again"));
        }
    }
    // Whatever this member staged is either in now or left over from a push that won't come.
    tx.execute("DELETE FROM staged WHERE vault_id = ? AND username = ?", params![vault, username]).map_err(db_err)?;
    // Every member's next pull brings all of this push's items in one response.
    let pushed: u64 = tx
        .query_row("SELECT COALESCE(SUM(length(blob)), 0) FROM items WHERE vault_id = ? AND counter = ?", params![vault, env.counter], |r| r.get(0))
        .map_err(db_err)?;
    if pushed > MAX_PUSH as u64 {
        return Err(TOO_BIG);
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
    tx.execute("INSERT INTO vaults(id, counter, epoch, roster_version, creator) VALUES(?,0,0,0,?)", params![&vault[..], username])
        .map_err(|_| (StatusCode::CONFLICT, "vault exists"))?;
    store_roster(tx, &vault, &nv.roster, &r)?;
    store_keys(tx, &vault, &nv.keys)?;
    let put = VaultPut { expected_counter: 0, manifest: nv.manifest.clone(), upserts: vec![], deletes: vec![], staged: None };
    store_put(tx, &vault, &put, username)
}

async fn create_vault(State(db): State<Db>, axum::Extension(cfg): axum::Extension<Config>, h: HeaderMap, Json(nv): Json<NewVault>) -> R<StatusCode> {
    let mut db = lock(&db);
    let c = caller(&db, &h)?;
    if !c.human {
        return Err(DENIED);
    }
    let tx = db.transaction().map_err(db_err)?;
    within_quota(&tx, &cfg, Some(&c.username), || insert_vault(&tx, &nv, &c.username))?;
    tx.commit().map_err(db_err)?;
    Ok(StatusCode::CREATED)
}

#[derive(Deserialize)]
struct Since {
    #[serde(default)]
    since: u64,
    roster: Option<u64>,
    /// Only the latest manifest (for a device with no state yet).
    #[serde(default)]
    latest: bool,
}

async fn get_vault(State(db): State<Db>, h: HeaderMap, Path(id): Path<String>, Query(q): Query<Since>) -> R<Json<VaultResponse>> {
    let vault = hex_id(&id)?;
    let db = lock(&db);
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
    let manifests = if q.latest {
        signed_list("SELECT signed FROM manifests WHERE vault_id = ? AND counter > ? ORDER BY counter DESC LIMIT 1", q.since as i64)?
    } else {
        signed_list("SELECT signed FROM manifests WHERE vault_id = ? AND counter > ? ORDER BY counter", q.since as i64)?
    };
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
    // Roster members the server no longer serves: they left, or their accounts were deleted.
    let (roster,): (String,) = db
        .query_row(
            "SELECT signed FROM rosters WHERE vault_id = ?1 AND version = (SELECT roster_version FROM vaults WHERE id = ?1)",
            [&vault[..]],
            |r| Ok((r.get(0)?,)),
        )
        .map_err(db_err)?;
    let roster: Roster = parse(&serde_json::from_str::<Signed>(&roster).map_err(db_err)?)?;
    let mut gone = Vec::new();
    let mut kems = Vec::new();
    for m in roster.members {
        let kept: bool = db
            .query_row("SELECT COUNT(*) FROM members WHERE vault_id = ? AND username = ?", params![&vault[..], m.username], |r| r.get(0))
            .map_err(db_err)?;
        if !kept {
            gone.push(m.username);
        } else if m.kem.is_none()
            && let Some(k) = kem_of(&db, &m.username)?
        {
            kems.push(k);
        }
    }
    Ok(Json(VaultResponse { counter, manifests, rosters, key, items, gone, kems }))
}

async fn put_vault(
    State(db): State<Db>,
    axum::Extension(cfg): axum::Extension<Config>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(put): Json<VaultPut>,
) -> R<StatusCode> {
    let vault = hex_id(&id)?;
    let mut db = lock(&db);
    let c = caller(&db, &h)?;
    let res = (|| -> R<()> {
        let tx = db.transaction().map_err(db_err)?;
        need_role(&tx, &vault, &c.username, Role::Writer)?;
        push_within_quota(&tx, &cfg, &vault, || store_put(&tx, &vault, &put, &c.username))?;
        let written = put.upserts.len() as u64 + put.staged.as_ref().map_or(0, |s| s.count);
        audit_log(&tx, &vault, &c.username, &format!("write {written} items, delete {}", put.deletes.len()))?;
        tx.commit().map_err(db_err)
    })();
    // A failed push is never retried with the same stage (the client stages
    // anew), so its staged items would only take up room.
    if let (Err(_), Some(st)) = (&res, put.staged.as_ref()) {
        let _ = db.execute("DELETE FROM staged WHERE vault_id = ? AND username = ? AND stage = ?", params![&vault[..], c.username, &st.id.0[..]]);
    }
    res.map(|()| StatusCode::NO_CONTENT)
}

/// The caller (and their agents) stop using a vault; see `leave_vault`. Anyone
/// listed can leave, expired or not, through an agent, and even as its only owner
/// (the others keep the vault, though its members and key can't change any more):
/// nobody is asked before being added, so nobody may be stuck paying for a vault.
/// Signed by the caller's identity key, so a stolen session token alone can't
/// delete a vault nobody else uses.
async fn leave(State(db): State<Db>, h: HeaderMap, Path(id): Path<String>, Json(s): Json<Signed>) -> R<StatusCode> {
    let vault = hex_id(&id)?;
    let mut db = lock(&db);
    let c = caller(&db, &h)?;
    let tx = db.transaction().map_err(db_err)?;
    let listed: bool = tx
        .query_row(&format!("SELECT COUNT(*) FROM members WHERE vault_id = ?2 AND {}", in_set("username")), params![c.username, &vault[..]], |r| r.get(0))
        .map_err(db_err)?;
    if !listed {
        return Err((StatusCode::NOT_FOUND, "no such vault"));
    }
    verify_signed(&tx, &s, "leave", &c.username)?;
    let req: LeaveVault = parse(&s)?;
    if req.vault_id.0 != vault || req.ts.abs_diff(now_ms()) > LOGIN_SKEW_MS {
        return Err((BAD, "the request names another vault or time"));
    }
    leave_vault(&tx, &vault, &c.username, "left", false)?;
    tx.commit().map_err(db_err)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Holds part of a big push's items until the push commits them (`store_put`).
async fn stage(
    State(db): State<Db>,
    axum::Extension(cfg): axum::Extension<Config>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<StageRequest>,
) -> R<StatusCode> {
    let vault = hex_id(&id)?;
    for u in &req.upserts {
        check_blob(&u.blob)?;
    }
    let mut db = lock(&db);
    let c = caller(&db, &h)?;
    let tx = db.transaction().map_err(db_err)?;
    need_role(&tx, &vault, &c.username, Role::Writer)?;
    tx.execute("DELETE FROM staged WHERE vault_id = ? AND username = ? AND stage != ?", params![&vault[..], c.username, &req.stage.0[..]])
        .map_err(db_err)?;
    // The stage expires a day after its first part (`store_put` and `cleanup`).
    let first: Option<u64> = tx
        .query_row("SELECT MIN(created) FROM staged WHERE vault_id = ? AND username = ?", params![&vault[..], c.username], |r| r.get(0))
        .map_err(db_err)?;
    if first.is_none() && !req.upserts.is_empty() {
        audit_log(&tx, &vault, &c.username, "staging a big push")?;
    }
    for u in &req.upserts {
        tx.execute(
            "INSERT OR REPLACE INTO staged(vault_id, username, stage, id, blob, created) VALUES(?,?,?,?,?,?)",
            params![&vault[..], c.username, &req.stage.0[..], &u.id.0[..], u.blob.0, first.unwrap_or_else(now)],
        )
        .map_err(db_err)?;
    }
    // Staged items count against the vault's creator. Over the quota, an owner may
    // still stage up to the size of the vault's items, which is what re-sealing
    // them all for a new key takes: once per vault, whichever owner it is.
    let sum = |sql: &str, p: &[&dyn rusqlite::ToSql]| -> R<u64> { tx.query_row(sql, p, |r| r.get(0)).map_err(db_err) };
    let mine = sum("SELECT COALESCE(SUM(length(blob)), 0) FROM staged WHERE vault_id = ? AND username = ?", &[&&vault[..], &c.username])?;
    let refused = if mine > MAX_PUSH as u64 {
        Some(TOO_BIG)
    } else if let Some(quota) = cfg.quota {
        let items = sum("SELECT COALESCE(SUM(length(blob)), 0) FROM items WHERE vault_id = ?", &[&&vault[..]])?;
        // Owners' stages only: a writer's stage stays within the quota anyway, and mustn't use up the allowance.
        let all = sum(
            "SELECT COALESCE(SUM(length(blob)), 0) FROM staged WHERE vault_id = ?1 AND username IN (SELECT username FROM members WHERE vault_id = ?1 AND role = 'owner')",
            &[&&vault[..]],
        )?;
        let rekey = role(&tx, &vault, &c.username)? == Some(Role::Owner) && all <= items;
        (!rekey && usage(&tx, creator(&tx, &vault)?.as_deref())? > quota).then_some(FULL)
    } else {
        None
    };
    if let Some(e) = refused {
        // The push this was part of can't go through: drop its earlier parts too.
        drop(tx);
        db.execute("DELETE FROM staged WHERE vault_id = ? AND username = ?", params![&vault[..], c.username]).map_err(db_err)?;
        return Err(e);
    }
    tx.commit().map_err(db_err)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn update_roster(
    State(db): State<Db>,
    axum::Extension(cfg): axum::Extension<Config>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(u): Json<RosterUpdate>,
) -> R<StatusCode> {
    let vault = hex_id(&id)?;
    let mut db = lock(&db);
    let c = caller(&db, &h)?;
    let res = (|| -> R<()> {
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
        let prev: String =
            tx.query_row("SELECT signed FROM rosters WHERE vault_id = ? AND version = ?", params![&vault[..], version], |row| row.get(0)).map_err(db_err)?;
        let prev_signed: Signed = serde_json::from_str(&prev).map_err(db_err)?;
        let prev: Roster = parse(&prev_signed)?;
        let had = |name: &str| prev.members.iter().any(|m| m.username == name);
        if !r.members.iter().any(|m| m.username == c.username) {
            return Err((BAD, "to stop using a vault, leave it"));
        }
        // Without an owner nobody could change its key or members again. Owners never
        // expire (clients refuse such a roster), and a disabled one can't sign in.
        if r.members.iter().any(|m| m.role == Role::Owner && m.expires.is_some()) {
            return Err((BAD, "owners don't expire"));
        }
        let mut owners = 0;
        for m in r.members.iter().filter(|m| m.role == Role::Owner) {
            owners += tx
                .query_row("SELECT COUNT(*) FROM accounts WHERE username = ? AND disabled = 0", [&m.username], |row| row.get::<_, i64>(0))
                .map_err(db_err)?;
        }
        if owners == 0 {
            return Err((BAD, "a vault needs an owner who can sign in"));
        }
        // Someone who left (or was deleted) stays out unless an owner adds them anew: a
        // roster built before they left, still listing them, mustn't bring them back.
        for m in r.members.iter().filter(|m| had(&m.username)) {
            let kept: bool = tx
                .query_row("SELECT COUNT(*) FROM members WHERE vault_id = ? AND username = ?", params![&vault[..], m.username], |row| row.get(0))
                .map_err(db_err)?;
            if !kept {
                return Err((StatusCode::CONFLICT, "someone left the vault: remove them with a new key first"));
            }
        }
        // Adding someone needs room in the account that pays afterwards: for the longer
        // roster, or for the whole vault if it moves to the signer. Other changes (a
        // promotion, removing someone with a new key) always go through, as long as the
        // items don't grow. Measured after any new key's items are re-sealed, which
        // uses up the staged copies.
        let store = || -> R<()> {
            store_roster(&tx, &vault, &u.roster, &r)?;
            store_keys(&tx, &vault, &u.keys)?;
            if let Some(put) = &u.rotation {
                push_within_quota(&tx, &cfg, &vault, || {
                    tx.execute("DELETE FROM items WHERE vault_id = ?", [&vault[..]]).map_err(db_err)?;
                    store_put(&tx, &vault, put, &c.username)
                })?;
            }
            Ok(())
        };
        if r.members.iter().any(|m| !had(&m.username)) {
            roster_within_quota(&tx, &cfg, &vault, &c.username, store)?;
        } else {
            store()?;
        }
        // As with a manifest, fields the server doesn't know may grow only while the
        // account paying for the vault (from now on, if the creator was removed; with any
        // new key's items re-sealed) has room.
        if let Some(quota) = cfg.quota
            && padding(&u.roster, &r) > padding(&prev_signed, &prev)
            && usage(&tx, creator(&tx, &vault)?.as_deref())? > quota
        {
            return Err(FULL);
        }
        audit_log(&tx, &vault, &c.username, &format!("roster v{}", r.version))?;
        tx.commit().map_err(db_err)
    })();
    // A failed push is never retried with the same stage (the client stages
    // anew), so its staged items would only take up room.
    if let (Err(_), Some(st)) = (&res, u.rotation.as_ref().and_then(|p| p.staged.as_ref())) {
        let _ = db.execute("DELETE FROM staged WHERE vault_id = ? AND username = ? AND stage = ?", params![&vault[..], c.username, &st.id.0[..]]);
    }
    res.map(|()| StatusCode::NO_CONTENT)
}

async fn audit(State(db): State<Db>, h: HeaderMap, Path(id): Path<String>) -> R<Json<Vec<AuditEntry>>> {
    let vault = hex_id(&id)?;
    let db = lock(&db);
    let c = caller(&db, &h)?;
    need_role(&db, &vault, &c.username, Role::Owner)?;
    let mut st = db.prepare("SELECT ts, username, action FROM audit WHERE vault_id = ? ORDER BY ts DESC, rowid DESC LIMIT 1000").map_err(db_err)?;
    let list = st
        .query_map([&vault[..]], |r| Ok(AuditEntry { ts: r.get(0)?, username: r.get(1)?, action: r.get(2)? }))
        .map_err(db_err)?
        .collect::<Result<_, _>>()
        .map_err(db_err)?;
    Ok(Json(list))
}

async fn put_file(
    State(db): State<Db>,
    axum::Extension(cfg): axum::Extension<Config>,
    h: HeaderMap,
    Path((id, fid)): Path<(String, String)>,
    body: Bytes,
) -> R<StatusCode> {
    let (vault, file) = (hex_id(&id)?, hex_id(&fid)?);
    if body.is_empty() || body.len() > MAX_FILE {
        return Err((BAD, "file size"));
    }
    let mut db = lock(&db);
    let c = caller(&db, &h)?;
    let tx = db.transaction().map_err(db_err)?;
    need_role(&tx, &vault, &c.username, Role::Writer)?;
    within_quota(&tx, &cfg, creator(&tx, &vault)?.as_deref(), || {
        tx.execute("INSERT OR REPLACE INTO files(vault_id, id, blob) VALUES(?,?,?)", params![&vault[..], &file[..], &body[..]])
            .map_err(db_err)
    })?;
    tx.commit().map_err(db_err)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_files(State(db): State<Db>, h: HeaderMap, Path(id): Path<String>) -> R<Json<FileList>> {
    let vault = hex_id(&id)?;
    let db = lock(&db);
    let c = caller(&db, &h)?;
    need_role(&db, &vault, &c.username, Role::Writer)?;
    let mut st = db.prepare("SELECT id, length(blob) FROM files WHERE vault_id = ? ORDER BY id").map_err(db_err)?;
    let files = st
        .query_map([&vault[..]], |r| Ok(FileInfo { id: Hex(r.get(0)?), size: r.get(1)? }))
        .map_err(db_err)?
        .collect::<Result<_, _>>()
        .map_err(db_err)?;
    Ok(Json(FileList { now: now(), files }))
}

async fn get_file(State(db): State<Db>, h: HeaderMap, Path((id, fid)): Path<(String, String)>) -> R<Vec<u8>> {
    let (vault, file) = (hex_id(&id)?, hex_id(&fid)?);
    let db = lock(&db);
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
    let db = lock(&db);
    let c = caller(&db, &h)?;
    need_role(&db, &vault, &c.username, Role::Writer)?;
    db.execute("DELETE FROM files WHERE vault_id = ? AND id = ?", params![&vault[..], &file[..]]).map_err(db_err)?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------- Messages and links ----------

async fn send_message(
    State(db): State<Db>,
    axum::Extension(cfg): axum::Extension<Config>,
    h: HeaderMap,
    Json(s): Json<Signed>,
) -> R<StatusCode> {
    let mut db = lock(&db);
    let c = caller(&db, &h)?;
    let tx = db.transaction().map_err(db_err)?;
    verify_signed(&tx, &s, "message", &c.username)?;
    let m: Message = parse(&s)?;
    check_blob(&m.sealed)?;
    sign_pk(&tx, &m.to)?;
    within_quota(&tx, &cfg, Some(&c.payer), || {
        tx.execute(
            "INSERT INTO messages(id, to_user, signed, expires, created, sender) VALUES(?,?,?,?,?,?)",
            params![&m.id.0[..], m.to, json(&s), m.expires, now(), c.username],
        )
        .map_err(|_| (StatusCode::CONFLICT, "message exists"))
    })?;
    tx.commit().map_err(db_err)?;
    Ok(StatusCode::CREATED)
}

async fn inbox(State(db): State<Db>, h: HeaderMap) -> R<Json<Vec<Signed>>> {
    let db = lock(&db);
    let c = caller(&db, &h)?;
    let mut st = db
        .prepare("SELECT signed FROM messages WHERE to_user = ? AND (expires IS NULL OR expires > ?) ORDER BY created")
        .map_err(db_err)?;
    let mut rows = st.query(params![c.username, now()]).map_err(db_err)?;
    // Oldest first, and at least one: once they're deleted, the next fetch gets the rest.
    let (mut list, mut size) = (Vec::new(), 0);
    while let Some(row) = rows.next().map_err(db_err)? {
        let s: String = row.get(0).map_err(db_err)?;
        size += s.len();
        if size > INBOX_BYTES && !list.is_empty() {
            break;
        }
        list.extend(serde_json::from_str::<Signed>(&s).ok());
    }
    Ok(Json(list))
}

async fn delete_message(State(db): State<Db>, h: HeaderMap, Path(id): Path<String>) -> R<StatusCode> {
    let id = hex_id(&id)?;
    let db = lock(&db);
    let c = caller(&db, &h)?;
    // The recipient, or the sender while it's waiting (it counts against their quota).
    db.execute(
        &format!("DELETE FROM messages WHERE id = ?2 AND (to_user = ?1 OR {})", in_set("sender")),
        params![c.username, &id[..]],
    )
    .map_err(db_err)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn create_link(
    State(db): State<Db>,
    axum::Extension(cfg): axum::Extension<Config>,
    h: HeaderMap,
    Json(l): Json<NewLink>,
) -> R<StatusCode> {
    check_blob(&l.blob)?;
    let mut db = lock(&db);
    let c = caller(&db, &h)?;
    if l.expires <= now() || l.expires > now() + 30 * 86400 {
        return Err((BAD, "links last up to 30 days"));
    }
    let tx = db.transaction().map_err(db_err)?;
    within_quota(&tx, &cfg, Some(&c.payer), || {
        tx.execute(
            "INSERT INTO links(id, creator, blob, expires, views_left) VALUES(?,?,?,?,?)",
            params![&l.id.0[..], c.username, l.blob.0, l.expires, l.max_views],
        )
        .map_err(|_| (StatusCode::CONFLICT, "link exists"))
    })?;
    tx.commit().map_err(db_err)?;
    Ok(StatusCode::CREATED)
}

/// Public: anyone with the link may fetch the sealed blob (the key is in the
/// link's fragment, which never reaches us). CORS is open so the static viewer
/// page at getplaintext.org can fetch it.
async fn open_link(State(db): State<Db>, Path(id): Path<String>) -> Response {
    let res: R<Vec<u8>> = (|| {
        let id = hex_id(&id)?;
        let db = lock(&db);
        let (blob, views): (Vec<u8>, Option<u32>) = db
            .query_row("SELECT blob, views_left FROM links WHERE id = ? AND expires > ? AND views_left IS NOT 0", params![&id[..], now()], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()
            .map_err(db_err)?
            .ok_or((StatusCode::NOT_FOUND, "this link has expired or doesn't exist"))?;
        match views {
            Some(1) => db.execute("DELETE FROM links WHERE id = ?", [&id[..]]),
            Some(_) => db.execute("UPDATE links SET views_left = views_left - 1 WHERE id = ?", [&id[..]]),
            None => Ok(0),
        }
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
    let db = lock(&db);
    let c = caller(&db, &h)?;
    db.execute("DELETE FROM links WHERE id = ? AND creator = ?", params![&id[..], c.username]).map_err(db_err)?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    /// Over the quota, adding someone with a new key whose items were staged first:
    /// the staged copies the re-seal uses up aren't room the change frees.
    #[test]
    fn roster_room_leaves_out_the_signers_staged_items() {
        let mut db = super::open_db(":memory:").unwrap();
        db.execute_batch(
            "INSERT INTO accounts(id, username, kind, identity, auth_key, account_key, keyring, created) VALUES (x'01', 'alice', 'human', '', x'', x'', x'', 0);
             INSERT INTO vaults(id, counter, epoch, roster_version, creator) VALUES (x'01', 0, 0, 0, 'alice');
             INSERT INTO items(vault_id, id, blob, counter) VALUES (x'01', x'01', zeroblob(1000), 0);
             INSERT INTO staged(vault_id, username, stage, id, blob, created) VALUES (x'01', 'alice', x'01', x'01', zeroblob(1000), 0);",
        )
        .unwrap();
        let cfg = super::Config { quota: Some(500), ..Default::default() };
        // The re-seal, plus `extra` bytes for the longer roster.
        let run = |db: &mut rusqlite::Connection, extra: usize| {
            let tx = db.transaction().unwrap();
            super::roster_within_quota(&tx, &cfg, &[1], "alice", || {
                tx.execute_batch("DELETE FROM items; INSERT INTO items(vault_id, id, blob, counter) SELECT vault_id, id, blob, 1 FROM staged; DELETE FROM staged;")
                    .map_err(super::db_err)?;
                tx.execute("INSERT INTO items(vault_id, id, blob, counter) VALUES (x'01', x'02', zeroblob(?), 1)", [extra]).map_err(super::db_err)
            })
        };
        assert_eq!(run(&mut db, 10).unwrap_err(), super::FULL);
        assert!(run(&mut db, 0).is_ok(), "a re-seal that takes no more room");
    }

    /// A vault's audit log keeps the newest 1000 rows, which is all owners see.
    #[test]
    fn audit_keeps_the_newest_1000() {
        let db = super::open_db(":memory:").unwrap();
        db.execute("INSERT INTO vaults(id, counter, epoch, roster_version) VALUES (x'01', 0, 0, 0)", []).unwrap();
        for i in 0..1005 {
            super::audit_log(&db, &[1], "alice", &format!("write {i}")).unwrap();
        }
        let (n, oldest): (i64, String) =
            db.query_row("SELECT COUNT(*), (SELECT action FROM audit ORDER BY rowid LIMIT 1) FROM audit", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!((n, oldest.as_str()), (1000, "write 5"));
    }

    /// A database from before `vaults.creator`, `sessions.expires` and `messages.sender`
    /// gets them. The creator is filled from roster
    /// v0's signer while they're still a current member (else an enabled owner), and opening it again changes nothing.
    #[test]
    fn creator_migration() {
        let path = std::env::temp_dir().join(format!("plaintext-migrate-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let old = rusqlite::Connection::open(&path).unwrap();
        old.execute_batch(include_str!("schema.sql")).unwrap();
        old.execute_batch(
            r#"INSERT INTO vaults(id, counter, epoch, roster_version) VALUES (x'01', 1, 0, 1), (x'02', 1, 0, 1);
               INSERT INTO rosters(vault_id, version, signed) VALUES (x'01', 0, '{"body":"","signer":"alice","sig":""}'),
                                                                    (x'01', 1, '{"body":"","signer":"bob","sig":""}'),
                                                                    (x'02', 0, '{"body":"","signer":"alice","sig":""}');
               INSERT INTO members(vault_id, username, role) VALUES (x'01', 'alice', 'writer'), (x'01', 'bob', 'owner'),
                                                                    (x'02', 'aaron', 'owner'), (x'02', 'bob', 'writer'), (x'02', 'carol', 'owner');
               INSERT INTO accounts(id, username, kind, identity, auth_key, account_key, keyring, disabled, created)
                 VALUES (x'a1', 'alice', 'human', '', x'', x'', x'', 0, 0), (x'a2', 'aaron', 'human', '', x'', x'', x'', 1, 0),
                        (x'b1', 'bob', 'human', '', x'', x'', x'', 0, 0), (x'c1', 'carol', 'human', '', x'', x'', x'', 0, 0);
               INSERT INTO accounts(id, username, kind, owner, identity, auth_key, account_key, keyring, created)
                 VALUES (x'a3', 'aaron-ci', 'agent', 'aaron', '', x'', x'', x'', 0);
               INSERT INTO sessions(token_hash, account_id, device, created) VALUES (x'01', x'b1', 'phone', 0);
               INSERT INTO messages(id, to_user, signed, created) VALUES (x'01', 'bob', '{"body":"","signer":"carol","sig":""}', 0);"#,
        )
        .unwrap();
        drop(old);
        for _ in 0..2 {
            let db = super::open_db(path.to_str().unwrap()).unwrap();
            let creators: Vec<String> =
                db.prepare("SELECT creator FROM vaults ORDER BY id").unwrap().query_map([], |r| r.get(0)).unwrap().map(Result::unwrap).collect();
            assert_eq!(creators, ["alice", "carol"], "alice was removed from the second vault, aaron is disabled");
            let expires: u64 = db.query_row("SELECT expires FROM sessions", [], |r| r.get(0)).unwrap();
            assert!(expires > super::now() + super::SESSION_TTL - 60, "old sessions get a full term");
            let sender: String = db.query_row("SELECT sender FROM messages", [], |r| r.get(0)).unwrap();
            assert_eq!(sender, "carol");
            let disabled: bool = db.query_row("SELECT disabled FROM accounts WHERE username = 'aaron-ci'", [], |r| r.get(0)).unwrap();
            assert!(disabled, "a disabled person's agent");
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn https_urls() {
        for u in ["https://a", "http://a, https://b", " HTTPS://a/"] {
            assert!(super::https_url(u), "{u}");
        }
        for u in ["http://a", "vault.example.com", "", "https:/a", "a,http://b"] {
            assert!(!super::https_url(u), "{u}");
        }
    }

    #[test]
    fn loopback_hosts() {
        for h in ["localhost", "localhost:8080", "127.0.0.1", "127.0.0.1:1", "[::1]", "[::1]:8080"] {
            assert!(super::loopback(h), "{h}");
        }
        let not = ["localhost.evil.example", "localhost:x@evil.example", "127.0.0.1@evil.example", "127.0.0.1:1@evil.example"];
        for h in not.into_iter().chain(["[::1]@evil.example", "[::1]:80x", "localhost:", "[::ffff:127.0.0.1]", "evil.example", "[::1"]) {
            assert!(!super::loopback(h), "{h}");
        }
    }

    /// A full rate-limit table refuses new signups but never logins.
    #[test]
    fn full_limiter_still_lets_logins_through() {
        let l = super::Limiter::default();
        for i in 0..super::LIMITER_KEYS as u32 {
            assert!(l.take((std::net::Ipv4Addr::from(i).into(), true), 1));
        }
        let new = std::net::IpAddr::from([255, 255, 255, 255]);
        assert!(!l.take((new, true), 1));
        assert!(l.take((new, false), 1));
    }

    #[test]
    fn backup_copy_has_the_same_rows() {
        let dir = std::env::temp_dir().join(format!("plaintext-backup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("backup")).unwrap();
        let path = dir.join("plaintext.db");
        let path = path.to_str().unwrap();
        // The writer stays open, so the rows live only in the WAL, as on a running server.
        let db = super::open_db(path).unwrap();
        let rows = |c: &rusqlite::Connection| -> Vec<(Vec<u8>, String)> {
            let mut st = c.prepare("SELECT id, created_by FROM invites ORDER BY id").unwrap();
            st.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().map(Result::unwrap).collect()
        };
        for i in 0..50u8 {
            db.execute("INSERT INTO invites(id, created_by, expires) VALUES (?1, ?2, 0)", rusqlite::params![vec![i; 16], format!("user{i}")])
                .unwrap();
        }
        assert!(std::fs::metadata(dir.join("plaintext.db-wal")).unwrap().len() > 0);
        // A copy interrupted mid-write leaves a junk temp file behind; the next run must cope.
        std::fs::write(dir.join("backup/plaintext.db.tmp"), b"junk").unwrap();
        let dest = super::backup_copy(path).unwrap();
        assert_eq!(dest, dir.join("backup/plaintext.db"));
        assert!(!dir.join("backup/plaintext.db.tmp").exists());
        let copy = rusqlite::Connection::open(&dest).unwrap();
        let ok: String = copy.query_row("PRAGMA integrity_check", [], |r| r.get(0)).unwrap();
        assert_eq!(ok, "ok");
        assert_eq!(rows(&copy).len(), 50);
        assert_eq!(rows(&copy), rows(&db));
        drop(copy);

        db.execute("DELETE FROM invites WHERE created_by = 'user7'", []).unwrap();
        super::backup_copy(path).unwrap();
        let copy = rusqlite::Connection::open(&dest).unwrap();
        assert_eq!(rows(&copy).len(), 49);
        assert_eq!(rows(&copy), rows(&db));
        drop((copy, db));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
