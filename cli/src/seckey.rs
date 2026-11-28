//! Unlocking with a security key (FIDO2 hmac-secret) instead of typing the
//! password, on a computer that's already signed in. See DESIGN.md, "Security
//! keys": the key never stands in for the Secret Key or for the password on a
//! new device, and the server learns nothing secret from it.

use plaintext_client::plaintext_core::Account;
use plaintext_client::plaintext_core::api::{Assertion, B64, SigninKeyAction};
use plaintext_client::plaintext_core::crypto::{
    Derived, Id, client_data, derive, open_for_security_key, random, rp_id, seal_for_security_key, server_host, signin_key_add_challenge,
};
use plaintext_client::{Error, Session, SignIn, Transport, now, now_ms};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::state::{self, Config, Res, S};

/// A prompt at the terminal (the key's PIN, the password).
pub type Ask<'a> = &'a mut dyn FnMut(&str) -> Res<Zeroizing<String>>;

/// One account's security keys on this computer, kept in the keychain.
#[derive(Serialize, Deserialize, Default)]
pub struct Keys {
    /// The hmac-secret salt: random, one per computer and account.
    salt: String,
    account_id: String,
    pub keys: Vec<Enrolled>,
}

#[derive(Serialize, Deserialize)]
pub struct Enrolled {
    pub name: String,
    cred: String,
    /// The server session sealed in this copy, so removing the key can end it.
    pub session: String,
    sealed: String,
    pub added: u64,
}

impl Keys {
    fn creds(&self) -> Res<Vec<Vec<u8>>> {
        Ok(self.keys.iter().map(|k| hex::decode(&k.cred)).collect::<Result<_, _>>()?)
    }
    fn salt(&self) -> Res<[u8; 32]> {
        Ok(hex::decode(&self.salt)?.try_into().map_err(|_| "damaged security key list")?)
    }
    fn account_id(&self) -> Res<Id> {
        Ok(hex::decode(&self.account_id)?.try_into().map_err(|_| "damaged security key list")?)
    }
}

/// What unlocking needs from a security key. `Hid` talks to a real one over
/// USB; the tests use a software one.
///
/// The PIN is always required. A touch alone would let any process that can
/// fake a terminal, or talk to the key itself, unlock on a stray touch. CTAP 2.1
/// keys give a different output with user verification (the PIN, or an
/// enrolled finger on a key with a fingerprint reader) than without, so a touch
/// alone gets nothing useful from them; `add` refuses keys that give the same
/// one (CTAP 2.0).
pub trait Authenticator {
    /// Whether the plugged-in key has a PIN (and can do hmac-secret at all).
    fn has_pin(&mut self) -> Res<bool>;
    /// A new credential with hmac-secret, not stored on the key (a touch).
    fn create(&mut self, exclude: &[Vec<u8>], pin: &str) -> Res<Vec<u8>>;
    /// Which of `creds` the plugged-in key holds, without a touch.
    fn which(&mut self, creds: &[Vec<u8>]) -> Res<Vec<u8>>;
    /// The hmac-secret output for `salt` with the PIN (a touch).
    fn secret(&mut self, cred: &[u8], salt: &[u8; 32], pin: &str) -> Res<Zeroizing<[u8; 32]>>;
    /// The output without the PIN (a touch), or None if the key refuses to
    /// give one without it (alwaysUv).
    fn secret_without_pin(&mut self, cred: &[u8], salt: &[u8; 32]) -> Res<Option<Zeroizing<[u8; 32]>>>;

    /// For signing in (DESIGN "Signing in with a security key"): a new credential
    /// for `rp`, answering `client_data` (a touch, and the PIN if the key has one,
    /// which making a credential needs). Its authenticatorData.
    fn register(&mut self, rp: &str, client_data: &[u8], pin: Option<&str>) -> Res<Vec<u8>>;
    /// An answer to `client_data` by whichever of `creds` the key holds (a touch,
    /// no PIN): the credential id, authenticatorData and signature.
    fn assert(&mut self, rp: &str, creds: &[Vec<u8>], client_data: &[u8]) -> Res<(Vec<u8>, Vec<u8>, Vec<u8>)>;
}

pub fn load(cfg: &Config) -> Res<Keys> {
    // Only "nothing stored" means no keys: a failed read mustn't let `add` overwrite the list.
    match state::entry(cfg, "security-keys")?.find()? {
        Some(raw) => Ok(serde_json::from_str(&raw).map_err(|_| "this computer's list of security keys is damaged; `plaintext key remove --all` clears it")?),
        None => Ok(Keys::default()),
    }
}

fn save(cfg: &Config, k: &Keys) -> Res<()> {
    let e = state::entry(cfg, "security-keys")?;
    if k.keys.is_empty() {
        return e.delete();
    }
    e.set(&serde_json::to_string(k)?)
}

/// Forget every security key of this account here (signing out).
pub fn clear(cfg: &Config) -> Res<()> {
    state::entry(cfg, "security-keys")?.delete()
}

fn password(cfg: &Config, ask: Ask) -> Res<Derived> {
    let sk = state::secret_key(cfg)?;
    Ok(derive(&ask(&format!("Password for {}: ", cfg.username))?, &sk))
}

/// A session of its own for a key's sealed copy, named after the key in
/// `plaintext sessions`. If the account needs a key to sign in, `auth` answers
/// (the same one: macOS opens a security key for one user at a time).
fn login(cfg: &Config, auth: &mut dyn Authenticator, ask: Ask, d: &Derived, name: &str) -> Res<(S, String)> {
    let s = sign_in(cfg, d, &format!("{} (security key: {name})", state::device()), auth, ask)?;
    match s.sessions().map(|l| l.into_iter().find(|x| x.current).map(|x| x.id)) {
        Ok(Some(id)) => Ok((s, id)),
        r => {
            let _ = state::http(&cfg.server).map(|h| h.send("POST", "/v1/logout", Some(&s.token), None));
            Err(r.err().map_or("the server didn't list the new session".into(), Into::into))
        }
    }
}

/// Seal `s` for a key and save it, ending `s` on the server if that fails.
fn keep(cfg: &Config, keys: &mut Keys, i: usize, s: &S, session: String, cred: &[u8], out: &[u8; 32]) -> Res<()> {
    keys.keys[i].session = session;
    keys.keys[i].sealed = hex::encode(seal_for_security_key(out, &s.account.id, cred, &s.account.account_key, &s.token));
    save(cfg, keys).inspect_err(|_| {
        let _ = s.end_session(&keys.keys[i].session);
    })
}

/// Add the plugged-in key: the password once (so an unlocked terminal alone
/// can't add someone else's key), the key's PIN, then three touches. Leaves this
/// terminal unlocked.
pub fn add(cfg: &Config, auth: &mut dyn Authenticator, name: &str, ask: Ask) -> Res<S> {
    let mut keys = load(cfg)?;
    if keys.keys.iter().any(|k| k.name == name) {
        return Err(format!("there's already a security key named {name} here; pick another name").into());
    }
    if keys.salt.is_empty() {
        keys.salt = hex::encode(random::<32>());
    }
    if !auth.has_pin()? {
        return Err("this security key has no PIN. Set one first (for a YubiKey: ykman fido access change-pin; or fido2-token -S), so that a touch alone can't unlock".into());
    }
    let d = password(cfg, ask)?;
    let (s, session) = login(cfg, auth, ask, &d, name)?;
    let made = (|| -> Res<_> {
        let pin = ask("Security key PIN: ")?;
        eprintln!("Touch your security key to add it.");
        let cred = auth.create(&keys.creds()?, &pin)?;
        eprintln!("Touch it once more.");
        let out = auth.secret(&cred, &keys.salt()?, &pin)?;
        eprintln!("And once more, to check it needs the PIN.");
        if auth.secret_without_pin(&cred, &keys.salt()?)?.is_some_and(|o| o == out) {
            return Err("this security key (an older FIDO2 one) gives the same secret without its PIN, so a touch alone would unlock; it can't be used here".into());
        }
        // Unlocking starts by asking, silently, which credential the key holds. (Last, so
        // the no-PIN check above explains credProtect keys first.)
        if auth.which(std::slice::from_ref(&cred)).map_err(|e| format!("checking that unlocking can find it: {e}"))? != cred {
            return Err("this security key won't say which credential it holds without a touch, which unlocking starts with; it can't be used here".into());
        }
        Ok((cred, out))
    })();
    let (cred, out) = match made {
        Ok(x) => x,
        Err(e) => {
            let _ = s.end_session(&session);
            return Err(e);
        }
    };
    keys.account_id = hex::encode(s.account.id);
    keys.keys.push(Enrolled { name: name.into(), cred: hex::encode(&cred), session: String::new(), sealed: String::new(), added: now() });
    let i = keys.keys.len() - 1;
    keep(cfg, &mut keys, i, &s, session, &cred, &out)?;
    state::remember(cfg, &s, true)?;
    Ok(s)
}

/// Unlock with whichever added key is plugged in: its PIN and a touch. If the
/// key's session has ended (30 days, or a password change), the password
/// renews it once, sealed with the same touch.
pub fn unlock(cfg: &Config, auth: &mut dyn Authenticator, ask: Ask) -> Res<S> {
    let mut keys = load(cfg)?;
    let cred = auth.which(&keys.creds()?)?;
    let i = keys.keys.iter().position(|k| k.cred == hex::encode(&cred)).ok_or("the security key plugged in isn't set up to unlock this account here")?;
    let pin = ask(&format!("PIN for security key {}: ", keys.keys[i].name))?;
    eprintln!("Touch your security key to unlock {}.", cfg.name());
    let out = auth.secret(&cred, &keys.salt()?, &pin)?;
    let id = keys.account_id()?;
    let (account_key, token) = open_for_security_key(&out, &id, &cred, &hex::decode(&keys.keys[i].sealed)?)
        .map_err(|_| "this security key doesn't open its copy here; remove it (plaintext key remove) and add it again")?;
    let s = match Session::resume(state::http(&cfg.server)?, token.to_string(), Account { id, account_key }) {
        Err(Error::Server(401, _)) => {
            eprintln!("This key's session has ended (they last 30 days, and a password change ends them). Your password renews it.");
            let d = password(cfg, ask)?;
            let (s, session) = login(cfg, auth, ask, &d, &keys.keys[i].name)?;
            if s.account.id != id {
                let _ = s.end_session(&session);
                return Err("that password signs in to a different account".into());
            }
            keep(cfg, &mut keys, i, &s, session, &cred, &out)?;
            s
        }
        r => r?,
    };
    state::remember(cfg, &s, true)?;
    Ok(s)
}

/// Delete this computer's copy for a key. Returns it, so the caller can end
/// its server session.
pub fn remove(cfg: &Config, name: &str) -> Res<Enrolled> {
    let mut keys = load(cfg)?;
    let i = keys.keys.iter().position(|k| k.name == name).ok_or_else(|| format!("no security key named {name}; plaintext key ls lists them"))?;
    let e = keys.keys.remove(i);
    save(cfg, &keys)?;
    Ok(e)
}

// ---------- Signing in (DESIGN "Signing in with a security key") ----------

/// The origin a browser on this server's address would report, for clientDataJSON.
fn origin(cfg: &Config) -> String {
    let scheme = cfg.server.split_once("://").map_or("https".into(), |(s, _)| s.to_ascii_lowercase());
    format!("{scheme}://{}", server_host(&cfg.server))
}

/// Sign in with the password. If the account needs a security key and this
/// computer isn't trusted yet, the key plugged in answers (a touch); failing
/// that, the approval page in a browser or a recovery code. The computer is
/// then trusted, so it isn't asked again.
pub fn sign_in(cfg: &Config, d: &Derived, device: &str, auth: &mut dyn Authenticator, ask: Ask) -> Res<S> {
    let trust = state::entry(cfg, "trust")?.find().unwrap_or_default();
    let mut p = match Session::sign_in(state::http(&cfg.server)?, d, device, trust.as_deref())? {
        SignIn::Done(s) => return Ok(s),
        SignIn::Key(p) => p,
    };
    let rp = p.rp_id();
    let creds: Vec<Vec<u8>> = p.needed.keys.iter().filter(|k| k.rp_id == rp).map(|k| k.id.0.clone()).collect();
    eprintln!("{} needs a security key to sign in on this computer. Touch it.", cfg.name());
    let cd = client_data("webauthn.get", &p.needed.challenge.0, &origin(cfg));
    let answer = match creds.is_empty() {
        true => Err(format!("none of this account's security keys was added for {rp}").into()),
        false => auth.assert(&rp, &creds, &cd),
    };
    let done = match answer {
        Ok((id, auth_data, signature)) => p.finish(Some(Assertion { id: B64(id), client_data: B64(cd), auth_data: B64(auth_data), signature: B64(signature) }), None)?,
        Err(e) => {
            eprintln!("plaintext: {}", crate::clean(&e.to_string()));
            let page = format!("{}{}", cfg.server, p.page());
            let mut tries = 0;
            loop {
                let a = ask(&format!("Approve the sign-in at {page} with your security key and press Enter, or type a recovery code: "))?;
                let code = Some(a.trim()).filter(|c| !c.is_empty());
                match p.finish(None, code) {
                    Err(Error::Server(409 | 401, m)) if tries < 4 && !m.contains("too long") => {
                        tries += 1;
                        eprintln!("plaintext: {}", crate::clean(&m));
                    }
                    r => break r?,
                }
            }
        }
    };
    let (s, trust) = done;
    if let Err(e) = state::entry(cfg, "trust").and_then(|e| e.set(&trust)) {
        eprintln!("plaintext: couldn't remember that this computer signed in with a security key ({e}); it'll be asked for one again next time");
    }
    Ok(s)
}

/// Make the plugged-in key one that signing in to this account needs (on top of
/// the password): its PIN if it has one, and two touches. Returns new recovery
/// codes when it's the first.
pub fn add_for_sign_in(cfg: &Config, s: &S, auth: &mut dyn Authenticator, name: &str, ask: Ask) -> Res<Vec<String>> {
    let d = password(cfg, ask)?;
    let rp = rp_id(&server_host(&cfg.server));
    let pin = if auth.has_pin()? { Some(ask("Security key PIN: ")?) } else { None };
    eprintln!("Touch your security key to add it.");
    let registration = auth.register(&rp, &client_data("webauthn.create", &random::<32>(), &origin(cfg)), pin.as_deref().map(|p| p.as_str()))?;
    let ts = now_ms();
    let cd = client_data("webauthn.get", &signin_key_add_challenge(&d.account_id, ts), &origin(cfg));
    eprintln!("Touch it once more, to check it.");
    // Only the new credential: the key answers with it, which proves it holds it.
    let cred = cred_id(&registration).ok_or("the security key's answer is malformed")?;
    let (id, auth_data, signature) = auth.assert(&rp, &[cred], &cd)?;
    let proof = Assertion { id: B64(id), client_data: B64(cd), auth_data: B64(auth_data), signature: B64(signature) };
    let r = s.change_signin_keys(&d, ts, &SigninKeyAction::Add { name: name.into(), rp_id: rp, registration: B64(registration), proof })?;
    // This computer just proved the key, so signing in here won't ask for it.
    if let Some(t) = r.trust {
        let _ = state::entry(cfg, "trust").and_then(|e| e.set(&t));
    }
    Ok(r.codes)
}

/// The credential id in a new credential's authenticatorData.
fn cred_id(a: &[u8]) -> Option<Vec<u8>> {
    let n = u16::from_be_bytes([*a.get(53)?, *a.get(54)?]) as usize;
    a.get(55..55 + n).map(<[u8]>::to_vec)
}

/// Stop a key being needed to sign in (the last one: none is needed any more),
/// or replace the recovery codes. Both need the password.
pub fn change_sign_in(cfg: &Config, s: &S, action: SigninKeyAction, ask: Ask) -> Res<Vec<String>> {
    Ok(s.change_signin_keys(&password(cfg, ask)?, now_ms(), &action)?.codes)
}

/// A USB security key, through `ctap-hid-fido2`. Builds without it (the static
/// Linux release, Windows) say so instead.
#[derive(Default)]
pub struct Hid(#[cfg(fido)] Option<ctap_hid_fido2::FidoKeyHid>);

#[cfg(not(fido))]
impl Authenticator for Hid {
    fn has_pin(&mut self) -> Res<bool> {
        Err(UNSUPPORTED.into())
    }
    fn create(&mut self, _: &[Vec<u8>], _: &str) -> Res<Vec<u8>> {
        Err(UNSUPPORTED.into())
    }
    fn which(&mut self, _: &[Vec<u8>]) -> Res<Vec<u8>> {
        Err(UNSUPPORTED.into())
    }
    fn secret(&mut self, _: &[u8], _: &[u8; 32], _: &str) -> Res<Zeroizing<[u8; 32]>> {
        Err(UNSUPPORTED.into())
    }
    fn secret_without_pin(&mut self, _: &[u8], _: &[u8; 32]) -> Res<Option<Zeroizing<[u8; 32]>>> {
        Err(UNSUPPORTED.into())
    }
    fn register(&mut self, _: &str, _: &[u8], _: Option<&str>) -> Res<Vec<u8>> {
        Err(UNSUPPORTED.into())
    }
    fn assert(&mut self, _: &str, _: &[Vec<u8>], _: &[u8]) -> Res<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        Err(UNSUPPORTED.into())
    }
}

#[cfg(all(not(fido), target_os = "linux"))]
const UNSUPPORTED: &str = "this build of plaintext can't use security keys; build it from source (cargo install), which can";
#[cfg(all(not(fido), not(target_os = "linux")))]
const UNSUPPORTED: &str = "plaintext can't use security keys on this system yet";

#[cfg(fido)]
mod hid {
    use super::*;
    use ctap_hid_fido2::fidokey::get_info::InfoOption;
    use ctap_hid_fido2::fidokey::{AssertionExtension as Gext, CredentialExtension as Mext, GetAssertionArgsBuilder, MakeCredentialArgsBuilder};
    use ctap_hid_fido2::{Cfg, FidoKeyHid, FidoKeyHidFactory, get_fidokey_devices};

    /// The relying party these credentials are made for: a name no web origin
    /// can claim, so no page can ask the key for this secret.
    const RP: &str = "plaintext:unlock";
    const NO_KEY: &str = "no security key is plugged in";
    #[cfg(target_os = "linux")]
    const ACCESS: &str = " On Linux your user needs access to /dev/hidraw*: systemd grants it to whoever is logged in at the computer, and on Arch the libfido2 package adds rules for other cases.";
    #[cfg(not(target_os = "linux"))]
    const ACCESS: &str = "";

    /// Every FIDO device plugged in that can be opened.
    fn devices() -> Res<Vec<FidoKeyHid>> {
        let cfg = Cfg { enable_keep_alive_msg: false, ..Cfg::init() };
        let found = get_fidokey_devices();
        if found.is_empty() {
            return Err(NO_KEY.into());
        }
        let (mut open, mut failed) = (Vec::new(), None);
        for d in found {
            match FidoKeyHidFactory::create_by_params(&[d.param], &cfg) {
                Ok(k) => open.push(k),
                Err(e) => failed = Some(e),
            }
        }
        match failed {
            Some(e) if open.is_empty() => Err(format!("can't open the security key ({e}).{ACCESS}").into()),
            _ => Ok(open),
        }
    }

    /// Turn the CTAP status codes people can cause into plain words.
    fn ctap(e: anyhow::Error) -> Box<dyn std::error::Error> {
        let s = e.to_string();
        let say = |m: &str| m.to_string().into();
        if s.contains("PIN_INVALID") {
            say("wrong security key PIN")
        } else if s.contains("PIN_AUTH_BLOCKED") {
            say("too many wrong PINs in a row; unplug the security key and plug it in again")
        } else if s.contains("PIN_BLOCKED") {
            say("the security key's PIN is blocked for good; only a reset, which erases the key, unblocks it")
        } else if s.contains("CREDENTIAL_EXCLUDED") {
            say("that security key is already set up here")
        } else if s.contains("TIMEOUT") {
            say("the security key wasn't touched in time")
        } else if s.contains("NO_CREDENTIALS") {
            say("the security key plugged in isn't set up to unlock this account here")
        } else {
            format!("security key: {s}").into()
        }
    }

    impl Hid {
        /// The one key plugged in (adding a key needs exactly one).
        fn one(&mut self) -> Res<&FidoKeyHid> {
            if self.0.is_none() {
                let mut d = devices()?;
                if d.len() > 1 {
                    return Err("more than one security key is plugged in; leave only the one to use".into());
                }
                self.0 = d.pop();
            }
            Ok(self.0.as_ref().expect("set above"))
        }
    }

    impl Authenticator for Hid {
        fn has_pin(&mut self) -> Res<bool> {
            let d = self.one()?;
            if !d.get_info().map_err(ctap)?.extensions.iter().any(|e| e == "hmac-secret") {
                return Err("this security key can't do hmac-secret, which unlocking needs (any FIDO2 key, such as a YubiKey 5, can)".into());
            }
            Ok(d.enable_info_option(&InfoOption::ClientPin).map_err(ctap)? == Some(true))
        }

        fn create(&mut self, exclude: &[Vec<u8>], pin: &str) -> Res<Vec<u8>> {
            let mut b = MakeCredentialArgsBuilder::new(RP, &random::<32>()).extensions(&[Mext::HmacSecret(Some(true))]).pin(pin);
            for c in exclude {
                b = b.exclude_authenticator(c);
            }
            Ok(self.one()?.make_credential_with_args(&b.build()).map_err(ctap)?.credential_descriptor.id)
        }

        fn which(&mut self, creds: &[Vec<u8>]) -> Res<Vec<u8>> {
            // Ask every key plugged in, silently (no touch, no PIN), which credential it holds.
            // Let go of a key held from `add` first: macOS opens HID devices exclusively,
            // so enumerating while holding one can't open it again. (No test runs `Hid`.)
            self.0 = None;
            let mut other = None;
            for d in devices()? {
                let mut b = GetAssertionArgsBuilder::new(RP, &random::<32>()).without_pin_and_uv().without_up();
                for c in creds {
                    b = b.add_credential_id(c);
                }
                match d.get_assertion_with_args(&b.build()) {
                    Ok(a) => {
                        // A key may leave the credential out when there was only one to choose from.
                        let id = a.first().map(|a| a.credential_id.clone()).filter(|c| !c.is_empty()).or_else(|| (creds.len() == 1).then(|| creds[0].clone()));
                        if let Some(id) = id {
                            self.0 = Some(d);
                            return Ok(id);
                        }
                    }
                    Err(e) if e.to_string().contains("NO_CREDENTIALS") => {}
                    Err(e) => other = Some(e),
                }
            }
            Err(other.map_or_else(|| "the security key plugged in isn't set up to unlock this account here".into(), ctap))
        }

        fn secret(&mut self, cred: &[u8], salt: &[u8; 32], pin: &str) -> Res<Zeroizing<[u8; 32]>> {
            self.hmac(cred, salt, Some(pin))?.ok_or_else(|| "the security key gave no hmac-secret output".into())
        }

        fn secret_without_pin(&mut self, cred: &[u8], salt: &[u8; 32]) -> Res<Option<Zeroizing<[u8; 32]>>> {
            match self.hmac(cred, salt, None) {
                // alwaysUv: nothing at all without the PIN. (Not OPERATION_DENIED, which
                // a CTAP 2.0 key also gives when the touch is declined.)
                Err(e) if e.to_string().contains("PIN_REQUIRED") => Ok(None),
                Err(e) if e.to_string().contains("NO_CREDENTIALS") => {
                    Err("this security key hides the credential without its PIN (credProtect), so unlocking couldn't find it; it can't be used here".into())
                }
                Ok(None) => Err("the security key gave no hmac-secret output".into()),
                r => r.map_err(|e| ctap(anyhow::anyhow!(e.to_string()))),
            }
        }

        // The crate hashes what it's given as the challenge into clientDataHash, so
        // passing clientDataJSON itself gives what a browser would sign.
        fn register(&mut self, rp: &str, client_data: &[u8], pin: Option<&str>) -> Res<Vec<u8>> {
            let b = MakeCredentialArgsBuilder::new(rp, client_data);
            let b = match pin {
                Some(p) => b.pin(p),
                None => b.without_pin_and_uv(),
            };
            Ok(self.one()?.make_credential_with_args(&b.build()).map_err(ctap)?.auth_data)
        }

        fn assert(&mut self, rp: &str, creds: &[Vec<u8>], client_data: &[u8]) -> Res<(Vec<u8>, Vec<u8>, Vec<u8>)> {
            let mut b = GetAssertionArgsBuilder::new(rp, client_data).without_pin_and_uv();
            for c in creds {
                b = b.add_credential_id(c);
            }
            let args = b.build();
            // Whichever key is plugged in: with several, the first that holds one of them.
            self.0 = None;
            let mut err = None;
            for d in devices()? {
                match d.get_assertion_with_args(&args) {
                    Ok(a) => {
                        let a = a.into_iter().next().ok_or("the security key gave no answer")?;
                        let id = Some(a.credential_id).filter(|c| !c.is_empty()).or_else(|| (creds.len() == 1).then(|| creds[0].clone())).ok_or("the security key didn't say which credential answered")?;
                        return Ok((id, a.auth_data, a.signature));
                    }
                    Err(e) => err = Some(e),
                }
            }
            Err(err.map_or_else(|| NO_KEY.into(), |e| {
                if e.to_string().contains("NO_CREDENTIALS") { "the security key plugged in isn't one this account signs in with".into() } else { ctap(e) }
            }))
        }
    }

    impl Hid {
        /// Unmapped CTAP errors, so `secret_without_pin` can tell a refusal apart.
        fn hmac(&mut self, cred: &[u8], salt: &[u8; 32], pin: Option<&str>) -> Res<Option<Zeroizing<[u8; 32]>>> {
            let b = GetAssertionArgsBuilder::new(RP, &random::<32>()).credential_id(cred).extensions(&[Gext::HmacSecret(Some(*salt))]);
            let b = match pin {
                Some(p) => b.pin(p),
                None => b.without_pin_and_uv(),
            };
            let a = match self.one()?.get_assertion_with_args(&b.build()) {
                Ok(a) => a,
                Err(e) if pin.is_none() => return Err(e.to_string().into()),
                Err(e) => return Err(ctap(e)),
            };
            Ok(a.iter()
                .flat_map(|a| &a.extensions)
                .find_map(|e| match e {
                    Gext::HmacSecret(Some(o)) => Some(Zeroizing::new(*o)),
                    _ => None,
                }))
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use plaintext_client::plaintext_core::crypto::hmac;

    /// A software authenticator: hmac-secret is HMAC(per-credential secret,
    /// salt), with another secret without the PIN, as CTAP 2.1 has it (one
    /// for both with `ctap20`).
    #[derive(Default)]
    pub struct Soft {
        pub pin: Option<String>,
        pub held: Vec<(Vec<u8>, [u8; 32])>,
        pub touches: usize,
        pub ctap20: bool,
        /// Gives nothing without the PIN (alwaysUv).
        pub always_uv: bool,
        /// Refuses the silent probe (`which`).
        pub no_probe: bool,
        /// Credentials for signing in, with the relying party each was made for.
        pub signin: Vec<(String, plaintext_server::SoftKey)>,
    }

    impl Authenticator for Soft {
        fn has_pin(&mut self) -> Res<bool> {
            Ok(self.pin.is_some())
        }
        fn create(&mut self, exclude: &[Vec<u8>], pin: &str) -> Res<Vec<u8>> {
            self.touches += 1;
            if self.pin.as_deref() != Some(pin) {
                return Err("wrong security key PIN".into());
            }
            if self.held.iter().any(|(c, _)| exclude.contains(c)) {
                return Err("that security key is already set up here".into());
            }
            let cred = random::<16>().to_vec();
            self.held.push((cred.clone(), random()));
            Ok(cred)
        }
        fn which(&mut self, creds: &[Vec<u8>]) -> Res<Vec<u8>> {
            if self.no_probe {
                return Err("operation denied".into());
            }
            self.held.iter().map(|(c, _)| c).find(|c| creds.contains(c)).cloned().ok_or_else(|| "not set up here".into())
        }
        fn secret(&mut self, cred: &[u8], salt: &[u8; 32], pin: &str) -> Res<Zeroizing<[u8; 32]>> {
            self.touches += 1;
            if self.pin.as_deref() != Some(pin) {
                return Err("wrong security key PIN".into());
            }
            self.output(cred, salt, !self.ctap20)
        }
        fn secret_without_pin(&mut self, cred: &[u8], salt: &[u8; 32]) -> Res<Option<Zeroizing<[u8; 32]>>> {
            self.touches += 1;
            if self.always_uv {
                return Ok(None);
            }
            self.output(cred, salt, false).map(Some)
        }
        fn register(&mut self, rp: &str, cd: &[u8], pin: Option<&str>) -> Res<Vec<u8>> {
            Soft::register(self, rp, cd, pin)
        }
        fn assert(&mut self, rp: &str, creds: &[Vec<u8>], cd: &[u8]) -> Res<(Vec<u8>, Vec<u8>, Vec<u8>)> {
            Soft::assert(self, rp, creds, cd)
        }
    }

    impl Soft {
        fn register(&mut self, rp: &str, _: &[u8], pin: Option<&str>) -> Res<Vec<u8>> {
            self.touches += 1;
            if self.pin.as_deref() != pin {
                return Err("wrong security key PIN".into());
            }
            let k = plaintext_server::SoftKey::new();
            let a = k.register(rp);
            self.signin.push((rp.into(), k));
            Ok(a)
        }
        fn assert(&mut self, rp: &str, creds: &[Vec<u8>], client_data: &[u8]) -> Res<(Vec<u8>, Vec<u8>, Vec<u8>)> {
            self.touches += 1;
            let (_, k) = self.signin.iter_mut().find(|(r, k)| r == rp && creds.contains(&k.id)).ok_or("the security key plugged in isn't one this account signs in with")?;
            let a = k.sign(rp, client_data.to_vec());
            Ok((a.id.0, a.auth_data.0, a.signature.0))
        }
        fn output(&self, cred: &[u8], salt: &[u8; 32], uv: bool) -> Res<Zeroizing<[u8; 32]>> {
            let (_, r) = self.held.iter().find(|(c, _)| c == cred).ok_or("not set up here")?;
            Ok(Zeroizing::new(hmac(&[&r[..], &[uv as u8]].concat(), salt)))
        }
    }

    /// A server on a fresh database, as in the client's end-to-end tests.
    fn server() -> (String, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!("plaintext-cli-{}.db", hex::encode(random::<8>())));
        let db = plaintext_server::open_db(path.to_str().unwrap()).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            tokio::runtime::Runtime::new().unwrap().block_on(async move {
                let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                tx.send(l.local_addr().unwrap()).unwrap();
                plaintext_server::serve(l, db, Default::default()).await.unwrap();
            });
        });
        (format!("http://{}", rx.recv().unwrap()), path)
    }

    #[test]
    fn a_touch_unlocks_instead_of_the_password() {
        let home = std::env::temp_dir().join(format!("plaintext-cli-home-{}", hex::encode(random::<8>())));
        // The only test that touches the environment.
        unsafe {
            std::env::set_var("PLAINTEXT_KEYCHAIN", "file");
            std::env::set_var("PLAINTEXT_HOME", &home);
        }
        let (url, db) = server();
        let (sk, s) = Session::signup(state::http(&url).unwrap(), "alice", "correct horse", None, "test").unwrap();
        let first = s.unwrap();
        let cfg = Config { server: url, username: "alice".into() };
        state::save_secret_key(&cfg, &sk).unwrap();

        // Every prompt is recorded; the PIN and the password are answered.
        let asked = std::cell::RefCell::new(Vec::<String>::new());
        let mut ask = |m: &str| -> Res<Zeroizing<String>> {
            asked.borrow_mut().push(m.into());
            Ok(Zeroizing::new(if m.contains("PIN") { "1234" } else { "correct horse" }.into()))
        };
        // A key without a PIN would unlock on a touch alone; it's refused before anything else.
        assert!(add(&cfg, &mut Soft::default(), "nopin", &mut ask).err().unwrap().to_string().contains("no PIN"));
        assert!(asked.take().is_empty());
        let before = first.sessions().unwrap().len();
        // Neither is one whose output doesn't depend on the PIN.
        let mut old = Soft { pin: Some("1234".into()), ctap20: true, ..Default::default() };
        assert!(add(&cfg, &mut old, "old", &mut ask).err().unwrap().to_string().contains("same secret without its PIN"));
        assert_eq!(first.sessions().unwrap().len(), before, "and its session is ended");
        asked.take();
        let mut key = Soft { pin: Some("1234".into()), ..Default::default() };

        let s = add(&cfg, &mut key, "blue", &mut ask).unwrap();
        assert_eq!((key.touches, asked.take()), (3, vec!["Password for alice: ".to_string(), "Security key PIN: ".into()]));
        let listed = first.sessions().unwrap();
        assert!(listed.iter().any(|x| x.device.ends_with("(security key: blue)")), "its own session, named after the key");
        assert!(add(&cfg, &mut key, "blue", &mut ask).is_err(), "names are unique");
        assert!(add(&cfg, &mut key, "again", &mut ask).err().unwrap().to_string().contains("already set up"));
        assert_eq!(first.sessions().unwrap().len(), listed.len(), "a failed add ends the session it made");
        asked.take();

        // What the key gives without its PIN doesn't open the copy: everything rests on that.
        let stored = load(&cfg).unwrap();
        let (cred, sealed) = (hex::decode(&stored.keys[0].cred).unwrap(), hex::decode(&stored.keys[0].sealed).unwrap());
        let bare = key.secret_without_pin(&cred, &stored.salt().unwrap()).unwrap().unwrap();
        assert!(matches!(open_for_security_key(&bare, &s.account.id, &cred, &sealed), Err(plaintext_client::plaintext_core::Error::Tampered)));

        // A touch and the PIN unlock; no password.
        let u = unlock(&cfg, &mut key, &mut ask).unwrap();
        assert_eq!((u.username(), u.account.account_key[..] == s.account.account_key[..]), ("alice", true));
        assert_eq!(asked.take(), ["PIN for security key blue: "]);

        // Locking forgets the session here but leaves the key's copy working.
        state::forget(&cfg, false);
        unlock(&cfg, &mut key, &mut ask).unwrap();
        assert_eq!(asked.take().len(), 1, "still just the PIN");

        // Another key, or the right key with the wrong PIN, opens nothing.
        assert!(unlock(&cfg, &mut Soft::default(), &mut ask).is_err());
        let mut wrong = |m: &str| -> Res<Zeroizing<String>> { Ok(Zeroizing::new(if m.contains("PIN") { "0000" } else { "correct horse" }.into())) };
        assert!(unlock(&cfg, &mut key, &mut wrong).is_err());
        // A copy sealed for another account doesn't open under this one's id.
        let mut moved = load(&cfg).unwrap();
        moved.account_id = hex::encode([9u8; 16]);
        save(&cfg, &moved).unwrap();
        assert!(unlock(&cfg, &mut key, &mut ask).err().unwrap().to_string().contains("doesn't open"));
        moved.account_id = hex::encode(s.account.id);
        save(&cfg, &moved).unwrap();
        asked.take();

        // Once the key's session has ended, the password renews it, once.
        first.end_session(&load(&cfg).unwrap().keys[0].session).unwrap();
        unlock(&cfg, &mut key, &mut ask).unwrap();
        assert_eq!(asked.take(), ["PIN for security key blue: ", "Password for alice: "]);
        unlock(&cfg, &mut key, &mut ask).unwrap();
        assert_eq!(asked.take(), ["PIN for security key blue: "]);

        // A key that gives nothing without its PIN is fine too. Ending both keys'
        // sessions with this terminal's (red's, ended last) drops it here too.
        let mut shy = Soft { pin: Some("1234".into()), no_probe: true, ..Default::default() };
        let before = first.sessions().unwrap().len();
        assert!(add(&cfg, &mut shy, "shy", &mut ask).err().unwrap().to_string().contains("can find it"), "a key unlock couldn't find is refused");
        assert_eq!(first.sessions().unwrap().len(), before, "and its session is ended");
        let mut red = Soft { pin: Some("1234".into()), always_uv: true, ..Default::default() };
        add(&cfg, &mut red, "red", &mut ask).unwrap();
        asked.take();
        state::forget(&cfg, false);
        unlock(&cfg, &mut red, &mut ask).unwrap();
        assert_eq!(asked.take(), ["PIN for security key red: "]);
        let ids: Vec<String> = load(&cfg).unwrap().keys.into_iter().map(|k| k.session).collect();
        assert!(state::end_sessions(&cfg, ids.clone()));
        assert!(first.sessions().unwrap().iter().all(|x| !ids.contains(&x.id)));
        assert!(state::entry(&cfg, "session").unwrap().get().is_err(), "this terminal's session was red's");

        // Removing deletes the copy.
        remove(&cfg, "blue").unwrap();
        remove(&cfg, "red").unwrap();
        assert!(load(&cfg).unwrap().keys.is_empty());
        assert!(unlock(&cfg, &mut key, &mut ask).is_err());
        clear(&cfg).unwrap();

        // A list that can't be read is an error, not "no keys" for `add` to
        // overwrite, and one that can't be deleted isn't reported as removed.
        let state::Store::File(p) = state::entry(&cfg, "security-keys").unwrap() else { unreachable!() };
        std::fs::create_dir_all(p.join("x")).unwrap();
        assert!(load(&cfg).is_err());
        assert!(add(&cfg, &mut key, "green", &mut ask).is_err());
        assert!(clear(&cfg).is_err());
        std::fs::remove_dir_all(p).unwrap();

        // Signing in with a key on top of the password (DESIGN "Signing in with a security key").
        let mut yubi = Soft { pin: Some("1234".into()), ..Default::default() };
        let codes = add_for_sign_in(&cfg, &first, &mut yubi, "yubi", &mut ask).unwrap();
        assert_eq!((codes.len(), yubi.touches), (10, 2));
        assert_eq!(asked.take(), ["Password for alice: ", "Security key PIN: "]);
        let d = derive("correct horse", &sk);
        // The computer that added it isn't asked for it.
        sign_in(&cfg, &d, "test", &mut Soft::default(), &mut ask).unwrap();
        // Another one: a touch, no PIN. Then it's remembered.
        state::entry(&cfg, "trust").unwrap().delete().unwrap();
        sign_in(&cfg, &d, "test", &mut yubi, &mut ask).unwrap();
        assert_eq!((yubi.touches, asked.take().len()), (3, 0));
        sign_in(&cfg, &d, "test", &mut Soft::default(), &mut ask).unwrap();
        // Adding an unlock key signs in too: on a trusted computer without the key,
        // on another with the same key that's being added.
        add(&cfg, &mut key, "blue", &mut ask).unwrap();
        state::entry(&cfg, "trust").unwrap().delete().unwrap();
        add(&cfg, &mut yubi, "yubi", &mut ask).unwrap();
        assert_eq!(yubi.touches, 3 + 1 + 3, "one touch to sign in, three to add");
        asked.take();
        // Without the key, a recovery code (the prompt also offers the approval page).
        state::entry(&cfg, "trust").unwrap().delete().unwrap();
        let mut code = |m: &str| -> Res<Zeroizing<String>> {
            asked.borrow_mut().push(m.into());
            Ok(Zeroizing::new(codes[0].clone()))
        };
        sign_in(&cfg, &d, "test", &mut Soft::default(), &mut code).unwrap();
        assert!(asked.take()[0].contains("/v1/login/key#"));
        // Removing the last key turns it off.
        let id = first.signin_keys().unwrap().keys[0].id.clone();
        change_sign_in(&cfg, &first, SigninKeyAction::Remove { id }, &mut ask).unwrap();
        state::entry(&cfg, "trust").unwrap().delete().unwrap();
        sign_in(&cfg, &d, "test", &mut Soft::default(), &mut ask).unwrap();
        let _ = std::fs::remove_dir_all(home);
        let _ = std::fs::remove_file(db);
    }
}
