//! Where the CLI keeps things. The Secret Key and the unlocked session live in the
//! OS keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service);
//! vault snapshots on disk are sealed with the Account Key.

use std::path::PathBuf;
use std::sync::OnceLock;

use plaintext_client::plaintext_core::Account;
use plaintext_client::plaintext_core::api::Hex;
use plaintext_client::plaintext_core::crypto::{AgentKey, SecretKey, derive, derive_agent, server_host};
use plaintext_client::plaintext_core::vault::Vault;
use plaintext_client::{Error, Http, Session, Transport, now};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub type S = Session<Http>;
pub type Res<T> = Result<T, Box<dyn std::error::Error>>;

/// How long `plaintext` stays unlocked after you enter your password.
const UNLOCKED_FOR: u64 = 12 * 3600;

/// One account: a username on a server. You can hold several, on different servers.
#[derive(Serialize, Deserialize, Clone)]
pub struct Config {
    pub server: String,
    pub username: String,
}

impl Config {
    /// `alice@vault.example.com`
    pub fn name(&self) -> String {
        format!("{}@{}", self.username, server_host(&self.server))
    }
}

#[derive(Serialize, Deserialize, Default)]
pub struct Accounts {
    pub accounts: Vec<Config>,
    pub current: usize,
}

/// The account picked with `--account` or PLAINTEXT_ACCOUNT (else the current one).
pub static PICK: OnceLock<String> = OnceLock::new();

#[derive(Serialize, Deserialize)]
struct Stored {
    token: String,
    account_id: String,
    account_key: String,
    until: u64,
    /// The terminal it was unlocked in (see `terminal`).
    #[serde(default)]
    terminal: Option<String>,
}

/// The terminal this process runs in: the terminal device on stdin, stdout or
/// stderr, plus the login session. The unlocked session works only there (like
/// sudo's per-terminal tickets), so processes with no terminal, such as an MCP
/// server's commands, background jobs or anything an AI agent runs through
/// pipes, can't use it to reach this person's vaults; they need an agent key.
#[cfg(unix)]
fn terminal() -> Option<String> {
    use std::os::fd::AsRawFd;
    let fds = [std::io::stdin().as_raw_fd(), std::io::stdout().as_raw_fd(), std::io::stderr().as_raw_fd()];
    let fd = fds.into_iter().find(|fd| unsafe { libc::isatty(*fd) } == 1)?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return None;
    }
    Some(format!("{}:{}", st.st_rdev, unsafe { libc::getsid(0) }))
}

// ponytail: no per-terminal binding on Windows yet; the session is per user there.
#[cfg(not(unix))]
fn terminal() -> Option<String> {
    Some("console".into())
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
                std::fs::create_dir_all(p.parent().unwrap_or(&home()))?;
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
        let name: String = cfg.name().chars().map(|c| if c.is_ascii_alphanumeric() || "@.-_".contains(c) { c } else { '_' }).collect();
        return Ok(Store::File(home().join("secrets").join(format!("{name} {what}"))));
    }
    Ok(Store::Os(keyring::Entry::new("plaintext", &format!("{}@{} {what}", cfg.username, cfg.server))?))
}

pub fn load_accounts() -> Res<Accounts> {
    let Ok(raw) = std::fs::read(home().join("config.json")) else { return Ok(Accounts::default()) };
    // config.json from before several accounts held just one.
    Ok(serde_json::from_slice(&raw).or_else(|_| serde_json::from_slice(&raw).map(|c| Accounts { accounts: vec![c], current: 0 }))?)
}

fn save_accounts(a: &Accounts) -> Res<()> {
    std::fs::create_dir_all(home())?;
    std::fs::write(home().join("config.json"), serde_json::to_vec_pretty(a)?)?;
    Ok(())
}

/// Which account `sel` means: `user@host`, a username, or a server address.
pub fn pick(list: &[Config], sel: &str) -> Res<usize> {
    let hits: Vec<usize> = (0..list.len())
        .filter(|&i| list[i].name() == sel || list[i].username == sel || server_host(&list[i].server) == server_host(sel))
        .collect();
    match hits[..] {
        [i] => Ok(i),
        [] => Err(format!("no account {sel}; `plaintext account ls` lists them").into()),
        _ => Err(format!("{sel} matches several accounts; use username@server").into()),
    }
}

/// The account commands act on.
pub fn load_config() -> Res<Config> {
    let a = load_accounts()?;
    if a.accounts.is_empty() {
        return Err("not signed in; run `plaintext signin` or set PLAINTEXT_AGENT_KEY".into());
    }
    let i = match PICK.get() {
        Some(sel) => pick(&a.accounts, sel)?,
        None => a.current.min(a.accounts.len() - 1),
    };
    Ok(a.accounts[i].clone())
}

/// Add or update an account and make it the current one.
pub fn save_config(cfg: &Config) -> Res<()> {
    let mut a = load_accounts()?;
    a.current = a.accounts.iter().position(|c| c.name() == cfg.name()).unwrap_or_else(|| {
        a.accounts.push(cfg.clone());
        a.accounts.len() - 1
    });
    a.accounts[a.current] = cfg.clone();
    save_accounts(&a)
}

/// Sign this computer out of an account and forget its Secret Key here.
pub fn remove_account(cfg: &Config) -> Res<()> {
    let mut a = load_accounts()?;
    forget(cfg);
    entry(cfg, "secret-key")?.delete();
    let cur = a.accounts.get(a.current).map(Config::name);
    a.accounts.retain(|c| c.name() != cfg.name());
    a.current = a.accounts.iter().position(|c| Some(c.name()) == cur).unwrap_or(0);
    save_accounts(&a)
}

pub fn save_secret_key(cfg: &Config, sk: &SecretKey) -> Res<()> {
    entry(cfg, "secret-key")?.set(&sk.encode())?;
    Ok(())
}

pub fn secret_key(cfg: &Config) -> Res<SecretKey> {
    let s = match entry(cfg, "secret-key")?.get() {
        Ok(s) => s,
        Err(_) => prompt("Secret Key (A1-…): ")?.to_string(),
    };
    let sk = SecretKey::parse(&s)?;
    save_secret_key(cfg, &sk)?;
    Ok(sk)
}

/// Keep the unlocked session for this terminal, ending the one it replaces
/// (unlocked in another terminal, say) so no older token stays live.
pub fn remember(cfg: &Config, s: &S) -> Res<()> {
    forget(cfg);
    let stored = Stored {
        token: s.token.clone(),
        account_id: hex::encode(s.account.id),
        account_key: hex::encode(&s.account.account_key[..]),
        until: now() + UNLOCKED_FOR,
        terminal: terminal(),
    };
    entry(cfg, "session")?.set(&serde_json::to_string(&stored)?)?;
    Ok(())
}

/// Forget the unlocked session on this computer and end it on the server, so the
/// token stops working even if a copy of it survives somewhere.
pub fn forget(cfg: &Config) {
    let Ok(e) = entry(cfg, "session") else { return };
    if let Ok(raw) = e.get().map(Zeroizing::new)
        && let Ok(st) = serde_json::from_str::<Stored>(&raw)
        && let Ok(h) = http(&cfg.server)
    {
        // Best effort: an unreachable server still gets the local copy removed.
        let _ = h.send("POST", "/v1/logout", Some(&st.token), None);
    }
    e.delete();
}

/// A connection to an account's server, refusing plain http:// across the internet.
pub fn http(server: &str) -> Res<Http> {
    if plaintext_client::insecure_url(server) {
        return Err(format!("{server} isn't https://. Plain http:// is only allowed on this machine and private networks, because anyone on the way could take over the sign-in.").into());
    }
    Ok(Http::new(server))
}

fn resume(cfg: &Config) -> Option<S> {
    let raw = Zeroizing::new(entry(cfg, "session").ok()?.get().ok()?);
    let st: Stored = serde_json::from_str(&raw).ok()?;
    if st.until <= now() {
        // Expired: don't leave the Account Key and a live token lying around.
        forget(cfg);
        return None;
    }
    // Unlocked in another terminal (or this process has none): ask again here.
    if st.terminal.is_none() || st.terminal != terminal() {
        return None;
    }
    let mut id = [0u8; 16];
    hex::decode_to_slice(&st.account_id, &mut id).ok()?;
    let key: [u8; 32] = hex::decode(&st.account_key).ok()?.try_into().ok()?;
    Session::resume(http(&cfg.server).ok()?, st.token, Account { id, account_key: Zeroizing::new(key) }).ok()
}

/// Ask at the terminal. Without one (a script, an AI tool's command) there's
/// nobody to ask, so say what to do instead.
fn prompt(msg: &str) -> Res<Zeroizing<String>> {
    rpassword::prompt_password(msg).map(Zeroizing::new).map_err(|_| {
        "this needs your password and there's no terminal to ask in. Unlock in a terminal; scripts and AI tools use an agent key (plaintext agent create)".into()
    })
}

pub fn device() -> String {
    let host = std::process::Command::new("hostname").output().ok().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
    format!("CLI on {}", host.filter(|h| !h.is_empty()).unwrap_or_else(|| std::env::consts::OS.into()))
}

/// Sign in with the password (and the Secret Key from the keychain, or asked for).
pub fn sign_in(cfg: &Config) -> Res<S> {
    http(&cfg.server)?;
    let sk = secret_key(cfg)?;
    let pw = prompt(&format!("Password for {}: ", cfg.username))?;
    let s = Session::login(http(&cfg.server)?, &derive(&pw, &sk), &device())?;
    remember(cfg, &s)?;
    Ok(s)
}

/// Syncs, warning about a vault that couldn't push (out of storage, or another
/// device got there first) instead of failing every command over it.
fn sync(s: &mut S) -> Result<(), Error> {
    match s.sync() {
        Err(e) if e.held_back() => eprintln!("warning: {e}"),
        r => r?,
    }
    for p in &s.problems {
        eprintln!("plaintext: warning: {}", crate::clean(p));
    }
    Ok(())
}

/// An unlocked, synced session: an agent from `PLAINTEXT_AGENT_KEY`, or the
/// signed-in human (asking for the password only once the keychain session lapses).
pub fn open() -> Res<S> {
    if let Ok(key) = std::env::var("PLAINTEXT_AGENT_KEY") {
        let server = std::env::var("PLAINTEXT_SERVER").map_err(|_| "set PLAINTEXT_SERVER along with PLAINTEXT_AGENT_KEY")?;
        let key = AgentKey::parse(&key)?;
        let mut s = Session::login(http(&server)?, &derive_agent(&key), "agent")?;
        sync(&mut s)?;
        return Ok(s);
    }
    let cfg = load_config()?;
    let mut s = match resume(&cfg) {
        Some(s) => s,
        None => sign_in(&cfg)?,
    };
    load_snapshots(&mut s);
    match sync(&mut s) {
        Err(Error::Server(401, _)) => {
            forget(&cfg);
            s = sign_in(&cfg)?;
            load_snapshots(&mut s);
            sync(&mut s)?;
        }
        r => r?,
    }
    save(&s)?;
    Ok(s)
}

pub fn snapshot_dir(s: &S) -> PathBuf {
    home().join("vaults").join(hex::encode(&s.account.id[..8]))
}

fn load_snapshots(s: &mut S) {
    // This device's own keyring copy: pins it holds survive a server serving an old keyring.
    if let Ok(blob) = std::fs::read(snapshot_dir(s).join("keyring.bin"))
        && let Err(e) = s.merge_local_keyring(&blob)
    {
        eprintln!("plaintext: warning: {e}");
    }
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
    let write = |name: String, data: Vec<u8>| -> Res<()> {
        let tmp = dir.join(format!("{name}.tmp"));
        std::fs::write(&tmp, data)?;
        std::fs::rename(tmp, dir.join(format!("{name}.bin")))?;
        Ok(())
    };
    for (id, v) in s.vaults.iter().chain(&s.hidden) {
        write(id.to_string(), v.snapshot(&s.account))?;
    }
    write("keyring".into(), s.keyring_snapshot())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_accounts_across_servers() {
        let c = |u: &str, s: &str| Config { server: s.into(), username: u.into() };
        let list = [c("alice", "https://vault.family.org"), c("alice", "https://vault.getplaintext.org"), c("bob", "http://10.0.0.2:8080")];
        assert_eq!(pick(&list, "alice@vault.getplaintext.org").unwrap(), 1);
        assert_eq!(pick(&list, "https://vault.family.org/").unwrap(), 0);
        assert_eq!(pick(&list, "bob").unwrap(), 2);
        assert!(pick(&list, "alice").is_err(), "ambiguous");
        assert!(pick(&list, "carol").is_err());
        // An old single-account config.json still loads.
        let old: Accounts = serde_json::from_slice::<Accounts>(br#"{"server":"https://x","username":"a"}"#)
            .or_else(|_| serde_json::from_slice(br#"{"server":"https://x","username":"a"}"#).map(|c| Accounts { accounts: vec![c], current: 0 }))
            .unwrap();
        assert_eq!(old.accounts[0].name(), "a@x");
    }
}
