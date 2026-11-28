//! Where the CLI keeps things. The Secret Key and the unlocked session live in the
//! OS keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service);
//! vault snapshots on disk are sealed with the Account Key.

use std::path::PathBuf;
use std::sync::OnceLock;

use plaintext_client::plaintext_core::Account;
use plaintext_client::plaintext_core::crypto::{AgentKey, SecretKey, derive, derive_agent, server_host, sha256};
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
    /// The token belongs to a security key's sealed copy (see `seckey`):
    /// locking forgets it here but doesn't end it, or the key would stop working.
    #[serde(default)]
    keyed: bool,
}

/// The terminal this process runs in: the terminal device on stdin, stdout or
/// stderr, plus the login session. The unlocked session works only there (like
/// sudo's per-terminal tickets), so processes with no terminal, such as an MCP
/// server's commands, background jobs or anything an AI agent runs through
/// pipes, can't use it to reach this person's vaults; they need an agent key.
#[cfg(all(unix, not(test)))]
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
#[cfg(all(not(unix), not(test)))]
fn terminal() -> Option<String> {
    Some("console".into())
}

// Tests run without a terminal, but as one.
#[cfg(test)]
fn terminal() -> Option<String> {
    Some("test".into())
}

pub fn home() -> PathBuf {
    std::env::var_os("PLAINTEXT_HOME").map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".config").join("plaintext")
    })
}

/// The OS keychain, or with `PLAINTEXT_KEYCHAIN=file` a 0600 file under
/// PLAINTEXT_HOME (for CI and headless machines without a keychain; weaker).
pub(crate) enum Store {
    Os(keyring::Entry),
    File(PathBuf),
}

impl Store {
    pub(crate) fn get(&self) -> Res<String> {
        Ok(match self {
            Store::Os(e) => e.get_password()?,
            Store::File(p) => std::fs::read_to_string(p)?,
        })
    }
    /// None only when nothing is stored; any other failure is an error.
    pub(crate) fn find(&self) -> Res<Option<String>> {
        match self {
            Store::Os(e) => match e.get_password() {
                Err(keyring::Error::NoEntry) => Ok(None),
                r => Ok(Some(r?)),
            },
            Store::File(p) => match std::fs::read_to_string(p) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                r => Ok(Some(r?)),
            },
        }
    }
    pub(crate) fn set(&self, v: &str) -> Res<()> {
        match self {
            Store::Os(e) => e.set_password(v)?,
            Store::File(p) => {
                std::fs::create_dir_all(p.parent().unwrap_or(&home()))?;
                crate::write_private(p, v.as_bytes())?;
            }
        }
        Ok(())
    }
    /// Deleting what isn't there succeeds.
    pub(crate) fn delete(&self) -> Res<()> {
        match self {
            Store::Os(e) => match e.delete_credential() {
                Err(keyring::Error::NoEntry) => Ok(()),
                r => Ok(r?),
            },
            Store::File(p) => match std::fs::remove_file(p) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                r => Ok(r?),
            },
        }
    }
}

pub(crate) fn entry(cfg: &Config, what: &str) -> Res<Store> {
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
    // The security keys' sessions end too, if this terminal has a session to do it with.
    let ids: Option<Vec<String>> = crate::seckey::load(cfg).ok().map(|k| k.keys.into_iter().map(|k| k.session).collect());
    if !ids.clone().map_or(Ok(false), |ids| end_sessions(cfg, ids))? {
        let ids = ids.map_or("their ids are unknown".into(), |ids| ids.join(", "));
        eprintln!("plaintext: the sessions of this computer's security keys ({ids}) couldn't be ended; they end on their own within 30 days, or end them from another device with `plaintext sessions --end ID`.");
    }
    crate::seckey::clear(cfg).map_err(|e| format!("couldn't delete this computer's security keys ({e}), so it's still signed in; try again"))?;
    forget(cfg, true)?;
    entry(cfg, "secret-key")?.delete()?;
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
/// (unlocked in another terminal, say) so no older token stays live. `keyed`:
/// the token is a security key's (see `Stored::keyed`).
pub fn remember(cfg: &Config, s: &S, keyed: bool) -> Res<()> {
    let _ = forget(cfg, false); // the `set` below overwrites it, or says why it can't
    let stored = Stored {
        token: s.token.clone(),
        account_id: hex::encode(s.account.id),
        account_key: hex::encode(&s.account.account_key[..]),
        until: now() + UNLOCKED_FOR,
        terminal: terminal(),
        keyed,
    };
    entry(cfg, "session")?.set(&serde_json::to_string(&stored)?)?;
    Ok(())
}

/// Forget the unlocked session on this computer and end it on the server, so the
/// token stops working even if a copy of it survives somewhere.
/// A security key's session is only forgotten here, since its key still holds
/// it, unless `end_keyed` (signing out, a password change). An error only if
/// the local copy (with its Account Key) couldn't be deleted.
pub fn forget(cfg: &Config, end_keyed: bool) -> Res<()> {
    let e = entry(cfg, "session")?;
    if let Some(st) = stored(cfg).filter(|st| end_keyed || !st.keyed)
        && let Ok(h) = http(&cfg.server)
    {
        // Best effort: an unreachable server still gets the local copy removed.
        let _ = h.send("POST", "/v1/logout", Some(&st.token), None);
    }
    e.delete()
}

/// Let `lock` end this terminal's security key session after all (its key is gone).
pub fn unkey(cfg: &Config) {
    if let (Some(mut st), Ok(e)) = (stored(cfg).filter(|st| st.keyed), entry(cfg, "session")) {
        st.keyed = false;
        if let Ok(j) = serde_json::to_string(&st) {
            let _ = e.set(&j);
        }
    }
}

/// End these sessions (security keys') with this terminal's unlocked session,
/// ending that one last, and forget it here if it was one of them and ended.
/// False if any couldn't be ended (or there's no session here to do it with);
/// an error only if that ended session couldn't be deleted here.
pub fn end_sessions(cfg: &Config, mut ids: Vec<String>) -> Res<bool> {
    if ids.is_empty() {
        return Ok(true);
    }
    // Only what `resume` would use: unexpired, and unlocked in this terminal.
    let (Some(st), Ok(h)) = (stored(cfg).filter(|st| st.until > now() && here(st)), http(&cfg.server)) else { return Ok(false) };
    let own = session_id(&st.token);
    ids.sort_by_key(|id| *id == own);
    // Every one is tried, even after one fails.
    let ended: Vec<bool> = ids.iter().map(|id| h.send("DELETE", &format!("/v1/sessions/{id}"), Some(&st.token), None).is_ok_and(|(code, _)| code < 300)).collect();
    // Kept while its end isn't confirmed: `unkey` and `lock` still need its token.
    if ids.last() == Some(&own) && ended.last() == Some(&true) {
        entry(cfg, "session")?.delete()?;
    }
    Ok(ended.into_iter().all(|e| e))
}

/// A session's id in `plaintext sessions`: the start of its token's hash, as the server works it out.
fn session_id(token: &str) -> String {
    hex::encode(&sha256(token.as_bytes())[..8])
}

/// The id of the session stored for the account on this computer.
pub fn stored_session(cfg: &Config) -> Option<String> {
    stored(cfg).map(|st| session_id(&st.token))
}

/// Unlocked in this terminal (not another one, and this process has one).
fn here(st: &Stored) -> bool {
    st.terminal.is_some() && st.terminal == terminal()
}

fn stored(cfg: &Config) -> Option<Stored> {
    let raw = Zeroizing::new(entry(cfg, "session").ok()?.get().ok()?);
    serde_json::from_str(&raw).ok()
}

/// A connection to an account's server, refusing plain http:// across the internet.
pub fn http(server: &str) -> Res<Http> {
    if plaintext_client::insecure_url(server) {
        return Err(format!("{server} isn't https://. Plain http:// is only allowed on this machine and private networks, because anyone on the way could take over the sign-in.").into());
    }
    Ok(Http::new(server))
}

fn resume(cfg: &Config) -> Option<S> {
    let st = stored(cfg)?;
    if st.until <= now() {
        // Expired: don't leave the Account Key and a live token lying around.
        let _ = forget(cfg, false);
        return None;
    }
    // Unlocked in another terminal (or this process has none): ask again here.
    if !here(&st) {
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
    remember(cfg, &s, false)?;
    Ok(s)
}

/// Unlock this terminal: with a security key when one is added here, else (or
/// if that fails) the password. Never without a terminal: a touch asked for by
/// a command nobody is watching, an AI tool's say, must not open the vaults.
pub fn unlock(cfg: &Config) -> Res<S> {
    if terminal().is_some() && !crate::seckey::load(cfg).map(|k| k.keys).unwrap_or_default().is_empty() {
        match crate::seckey::unlock(cfg, &mut crate::seckey::Hid::default(), &mut |m: &str| prompt(m)) {
            Ok(s) => return Ok(s),
            Err(e) => eprintln!("plaintext: {}; unlocking with your password instead", crate::clean(&e.to_string())),
        }
    }
    sign_in(cfg)
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
    // By id: anyone who may write can name a vault anything.
    for id in &s.unsendable {
        let name = s.vaults.get(id).or(s.hidden.get(id)).map_or("", |v| &v.meta.name);
        eprintln!("plaintext: warning: to see or drop the unsent changes to vault {}, run plaintext vault reset {id}", crate::clean(name));
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
        None => unlock(&cfg)?,
    };
    load_snapshots(&mut s);
    match sync(&mut s) {
        Err(Error::Server(401, _)) => {
            let _ = forget(&cfg, false); // unlocking replaces it
            s = unlock(&cfg)?;
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
    if let Err(e) = s.load_local(&snapshot_dir(s)) {
        eprintln!("plaintext: warning: {e}");
    }
}

/// Persist vault snapshots (agents keep none: they always pull fresh).
pub fn save(s: &S) -> Res<()> {
    if std::env::var("PLAINTEXT_AGENT_KEY").is_ok() {
        return Ok(());
    }
    Ok(s.save_local(&snapshot_dir(s))?)
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
