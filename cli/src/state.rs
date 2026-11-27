//! Where the CLI keeps things. The Secret Key and the unlocked session live in the
//! OS keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service);
//! vault snapshots on disk are sealed with the Account Key.

use std::path::PathBuf;

use plaintext_client::plaintext_core::Account;
use plaintext_client::plaintext_core::api::Hex;
use plaintext_client::plaintext_core::crypto::{AgentKey, SecretKey, derive, derive_agent};
use plaintext_client::plaintext_core::vault::Vault;
use plaintext_client::{Error, Http, Session, now};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub type S = Session<Http>;
pub type Res<T> = Result<T, Box<dyn std::error::Error>>;

/// How long `plaintext` stays unlocked after you enter your password.
const UNLOCKED_FOR: u64 = 12 * 3600;

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub server: String,
    pub username: String,
}

#[derive(Serialize, Deserialize)]
struct Stored {
    token: String,
    account_id: String,
    account_key: String,
    until: u64,
}

pub fn home() -> PathBuf {
    std::env::var_os("PLAINTEXT_HOME").map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".config").join("plaintext")
    })
}

/// The OS keychain, or with `PLAINTEXT_KEYCHAIN=file` a 0600 file under
/// PLAINTEXT_HOME (for CI and headless machines without a keychain; weaker).
enum Store {
    Os(keyring::Entry),
    File(PathBuf),
}

impl Store {
    fn get(&self) -> Res<String> {
        Ok(match self {
            Store::Os(e) => e.get_password()?,
            Store::File(p) => std::fs::read_to_string(p)?,
        })
    }
    fn set(&self, v: &str) -> Res<()> {
        match self {
            Store::Os(e) => e.set_password(v)?,
            Store::File(p) => {
                use std::io::Write;
                #[cfg(unix)]
                use std::os::unix::fs::OpenOptionsExt;
                std::fs::create_dir_all(home())?;
                let mut o = std::fs::OpenOptions::new();
                o.write(true).create(true).truncate(true);
                #[cfg(unix)]
                o.mode(0o600);
                o.open(p)?.write_all(v.as_bytes())?;
            }
        }
        Ok(())
    }
    fn delete(&self) {
        match self {
            Store::Os(e) => drop(e.delete_credential()),
            Store::File(p) => drop(std::fs::remove_file(p)),
        }
    }
}

fn entry(cfg: &Config, what: &str) -> Res<Store> {
    if std::env::var("PLAINTEXT_KEYCHAIN").is_ok_and(|v| v == "file") {
        return Ok(Store::File(home().join(format!("{what}.secret"))));
    }
    Ok(Store::Os(keyring::Entry::new("plaintext", &format!("{}@{} {what}", cfg.username, cfg.server))?))
}

pub fn load_config() -> Res<Config> {
    let raw = std::fs::read(home().join("config.json")).map_err(|_| "not signed in; run `plaintext signin` or set PLAINTEXT_AGENT_KEY")?;
    Ok(serde_json::from_slice(&raw)?)
}

pub fn save_config(cfg: &Config) -> Res<()> {
    std::fs::create_dir_all(home())?;
    std::fs::write(home().join("config.json"), serde_json::to_vec_pretty(cfg)?)?;
    Ok(())
}

pub fn save_secret_key(cfg: &Config, sk: &SecretKey) -> Res<()> {
    entry(cfg, "secret-key")?.set(&sk.encode())?;
    Ok(())
}

pub fn secret_key(cfg: &Config) -> Res<SecretKey> {
    let s = match entry(cfg, "secret-key")?.get() {
        Ok(s) => s,
        Err(_) => rpassword::prompt_password("Secret Key (A1-…): ")?,
    };
    let sk = SecretKey::parse(&s)?;
    save_secret_key(cfg, &sk)?;
    Ok(sk)
}

pub fn remember(cfg: &Config, s: &S) -> Res<()> {
    let stored = Stored {
        token: s.token.clone(),
        account_id: hex::encode(s.account.id),
        account_key: hex::encode(&s.account.account_key[..]),
        until: now() + UNLOCKED_FOR,
    };
    entry(cfg, "session")?.set(&serde_json::to_string(&stored)?)?;
    Ok(())
}

pub fn forget(cfg: &Config) {
    if let Ok(e) = entry(cfg, "session") {
        e.delete();
    }
}

fn resume(cfg: &Config) -> Option<S> {
    let raw = Zeroizing::new(entry(cfg, "session").ok()?.get().ok()?);
    let st: Stored = serde_json::from_str(&raw).ok()?;
    if st.until <= now() {
        return None;
    }
    let mut id = [0u8; 16];
    hex::decode_to_slice(&st.account_id, &mut id).ok()?;
    let key: [u8; 32] = hex::decode(&st.account_key).ok()?.try_into().ok()?;
    Session::resume(Http::new(&cfg.server), st.token, Account { id, account_key: Zeroizing::new(key) }).ok()
}

pub fn device() -> String {
    let host = std::process::Command::new("hostname").output().ok().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
    format!("CLI on {}", host.filter(|h| !h.is_empty()).unwrap_or_else(|| std::env::consts::OS.into()))
}

/// Sign in with the password (and the Secret Key from the keychain, or asked for).
pub fn sign_in(cfg: &Config) -> Res<S> {
    let sk = secret_key(cfg)?;
    let pw = Zeroizing::new(rpassword::prompt_password(format!("Password for {}: ", cfg.username))?);
    let s = Session::login(Http::new(&cfg.server), &derive(&pw, &sk), &device())?;
    remember(cfg, &s)?;
    Ok(s)
}

/// An unlocked, synced session: an agent from `PLAINTEXT_AGENT_KEY`, or the
/// signed-in human (asking for the password only once the keychain session lapses).
pub fn open() -> Res<S> {
    if let Ok(key) = std::env::var("PLAINTEXT_AGENT_KEY") {
        let server = std::env::var("PLAINTEXT_SERVER").map_err(|_| "set PLAINTEXT_SERVER along with PLAINTEXT_AGENT_KEY")?;
        let key = AgentKey::parse(&key)?;
        let mut s = Session::login(Http::new(&server), &derive_agent(&key), "agent")?;
        s.sync()?;
        return Ok(s);
    }
    let cfg = load_config()?;
    let mut s = match resume(&cfg) {
        Some(s) => s,
        None => sign_in(&cfg)?,
    };
    load_snapshots(&mut s);
    match s.sync() {
        Err(Error::Server(401, _)) => {
            forget(&cfg);
            s = sign_in(&cfg)?;
            load_snapshots(&mut s);
            s.sync()?;
        }
        r => r?,
    }
    save(&s)?;
    Ok(s)
}

fn snapshot_dir(s: &S) -> PathBuf {
    home().join("vaults").join(hex::encode(&s.account.id[..8]))
}

fn load_snapshots(s: &mut S) {
    let Ok(dir) = std::fs::read_dir(snapshot_dir(s)) else { return };
    for f in dir.flatten() {
        let Some(id) = f.file_name().to_str().and_then(|n| n.strip_suffix(".bin")).and_then(|n| n.parse::<Hex>().ok()) else { continue };
        if let Ok(blob) = std::fs::read(f.path())
            && let Ok(v) = Vault::restore(&s.account, id, &blob)
        {
            s.vaults.insert(id, v);
        }
    }
}

/// Persist vault snapshots (agents keep none: they always pull fresh).
pub fn save(s: &S) -> Res<()> {
    if std::env::var("PLAINTEXT_AGENT_KEY").is_ok() {
        return Ok(());
    }
    let dir = snapshot_dir(s);
    std::fs::create_dir_all(&dir)?;
    for (id, v) in &s.vaults {
        let tmp = dir.join(format!("{id}.tmp"));
        std::fs::write(&tmp, v.snapshot(&s.account))?;
        std::fs::rename(tmp, dir.join(format!("{id}.bin")))?;
    }
    Ok(())
}
