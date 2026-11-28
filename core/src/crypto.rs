//! Key derivation, the Secret Key, and sealed blobs. Everything here is pinned by
//! protocol version: the server supplies no parameters, salts or ids that feed a key.

use crate::Error;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

pub type Key = Zeroizing<[u8; 32]>;
pub type Id = [u8; 16];

/// Blob format version, the first byte of every sealed blob.
const V1: u8 = 1;
/// Argon2id cost. Pinned: a server can't downgrade it because it never sends it.
/// The Secret Key carries the real entropy; this only slows down someone who
/// already stole a device's Secret Key.
const ARGON_M_KIB: u32 = 64 * 1024;
const ARGON_T: u32 = 3;
const ARGON_P: u32 = 1;

pub fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("OS RNG unavailable");
    b
}

pub fn random_key() -> Key {
    Zeroizing::new(random())
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

// ---------- Secret Key ----------

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// 128 random bits generated on the first device. Never sent to the server.
/// Shown as `A1-XXXXXXX-XXXXXXX-XXXXXXX-XXXXXXX` (26 data chars + 2 check chars).
#[derive(Clone)]
pub struct SecretKey(pub Zeroizing<[u8; 16]>);

impl SecretKey {
    pub fn generate() -> Self {
        Self(Zeroizing::new(random()))
    }

    pub fn encode(&self) -> String {
        let mut chars = base32(&self.0[..]);
        let check = sha256(&self.0[..]);
        chars.push(CROCKFORD[(check[0] >> 3) as usize] as char);
        chars.push(CROCKFORD[(check[1] >> 3) as usize] as char);
        let groups: Vec<&str> = (0..4).map(|i| &chars[i * 7..i * 7 + 7]).collect();
        format!("A1-{}", groups.join("-"))
    }

    /// Accepts any case, spaces or dashes, and Crockford's O/I/L look-alikes.
    pub fn parse(s: &str) -> Result<Self, Error> {
        let clean: String = s
            .chars()
            .filter(|c| !matches!(c, '-' | ' '))
            .map(|c| match c.to_ascii_uppercase() {
                'O' => '0',
                'I' | 'L' => '1',
                c => c,
            })
            .collect();
        let body = clean.strip_prefix("A1").ok_or(Error::BadSecretKey)?;
        if body.len() != 28 {
            return Err(Error::BadSecretKey);
        }
        let mut bytes = Zeroizing::new([0u8; 16]);
        let (mut acc, mut n, mut i) = (0u32, 0, 0);
        for c in body[..26].bytes() {
            let v = CROCKFORD.iter().position(|&x| x == c).ok_or(Error::BadSecretKey)? as u32;
            acc = (acc << 5) | v;
            n += 5;
            if n >= 8 {
                n -= 8;
                bytes[i] = (acc >> n) as u8;
                i += 1;
            }
        }
        let sk = SecretKey(bytes);
        // Re-encoding catches non-zero padding bits and a wrong check pair (a typo).
        if sk.encode().replace('-', "") != format!("A1{body}") {
            return Err(Error::BadSecretKey);
        }
        Ok(sk)
    }
}

fn base32(data: &[u8]) -> String {
    let mut out = String::new();
    let (mut acc, mut n) = (0u32, 0);
    for &b in data {
        acc = (acc << 8) | b as u32;
        n += 8;
        while n >= 5 {
            n -= 5;
            out.push(CROCKFORD[((acc >> n) & 31) as usize] as char);
        }
    }
    if n > 0 {
        out.push(CROCKFORD[((acc << (5 - n)) & 31) as usize] as char);
    }
    out
}

// ---------- Key derivation ----------

/// Everything derived from (password, Secret Key).
pub struct Derived {
    pub account_id: Id,
    /// Account Unlock Key: wraps the Account Key.
    pub unlock_key: Key,
    /// Signs logins. The server only ever sees its public half.
    pub auth: SigningKey,
}

/// The account id depends only on the Secret Key, so a device can find its
/// account without the server choosing anything that feeds key derivation.
pub fn account_id(sk: &SecretKey) -> Id {
    let mut id = [0u8; 16];
    Hkdf::<Sha256>::new(None, &sk.0[..])
        .expand(b"plaintext/v1/account-id", &mut id)
        .expect("valid length");
    id
}

pub fn derive(password: &str, sk: &SecretKey) -> Derived {
    let stretched = stretch(password, &sha256(&[b"plaintext/v1/argon-salt".as_slice(), &sk.0[..]].concat()));
    // The Secret Key is the HKDF salt: without it, the password alone yields nothing.
    expand_keys(&Hkdf::<Sha256>::new(Some(&sk.0[..]), &stretched[..]), account_id(sk))
}

fn stretch(password: &str, salt: &[u8]) -> Key {
    // NFKD so the same password typed on macOS, Windows and Android matches.
    let password = Zeroizing::new(password.nfkd().collect::<String>());
    let params = Params::new(ARGON_M_KIB, ARGON_T, ARGON_P, Some(32)).expect("valid params");
    let mut stretched = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, &mut stretched[..])
        .expect("argon2");
    stretched
}

/// The Secret Key as a browser extension keeps it between unlocks, which have
/// only the password: sealed under the password, stretched with a random salt.
/// Apps keep it in the OS keychain instead; a browser profile has nothing like
/// that, so someone who copies the profile can guess the password offline at
/// Argon2 speed, as they could with the server's database and the Secret Key.
pub fn seal_secret_key(password: &str, sk: &SecretKey) -> Vec<u8> {
    let salt: [u8; 16] = random();
    [&salt[..], &seal(&stretch(password, &salt), &ad("local-secret-key", &[]), &sk.0[..])].concat()
}

/// `Tampered` means the wrong password (or a damaged blob).
pub fn open_secret_key(password: &str, blob: &[u8]) -> Result<SecretKey, Error> {
    let (salt, sealed) = blob.split_at_checked(16).ok_or(Error::Tampered)?;
    let raw = open(&stretch(password, salt), &ad("local-secret-key", &[]), sealed)?;
    Ok(SecretKey(Zeroizing::new(raw[..].try_into().map_err(|_| Error::Tampered)?)))
}

/// What a security key unlocks on one device: the Account Key and a session
/// token, sealed with a key from the authenticator's hmac-secret output for the
/// device's salt. The AD names the account and the credential, so a sealed copy
/// can't be moved to another account or key.
pub fn seal_for_security_key(output: &[u8; 32], account_id: &Id, cred: &[u8], account_key: &Key, token: &str) -> Vec<u8> {
    seal(&security_key_key(output), &[&ad("security-key", &[account_id])[..], cred].concat(), &Zeroizing::new([&account_key[..], token.as_bytes()].concat()))
}

/// `Tampered` means another key, another credential, or a damaged blob.
pub fn open_for_security_key(output: &[u8; 32], account_id: &Id, cred: &[u8], blob: &[u8]) -> Result<(Key, Zeroizing<String>), Error> {
    let raw = open(&security_key_key(output), &[&ad("security-key", &[account_id])[..], cred].concat(), blob)?;
    let (key, token) = raw.split_at_checked(32).ok_or(Error::Tampered)?;
    let token = Zeroizing::new(String::from_utf8(token.to_vec()).map_err(|_| Error::Tampered)?);
    Ok((Zeroizing::new(key.try_into().expect("32 bytes")), token))
}

fn security_key_key(output: &[u8; 32]) -> Key {
    let mut k = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, output).expand(b"plaintext/v1/security-key", &mut k[..]).expect("valid length");
    k
}

fn expand_keys(hk: &Hkdf<Sha256>, account_id: Id) -> Derived {
    let mut unlock_key = Zeroizing::new([0u8; 32]);
    let mut auth_seed = Zeroizing::new([0u8; 32]);
    hk.expand(b"plaintext/v1/unlock", &mut unlock_key[..]).expect("valid length");
    hk.expand(b"plaintext/v1/auth", &mut auth_seed[..]).expect("valid length");
    Derived { account_id, unlock_key, auth: SigningKey::from_bytes(&auth_seed) }
}

// ---------- Agent keys ----------

/// An agent's whole credential: 256 random bits, shown once as `ptk_…`. It has
/// full entropy, so it needs no password stretching.
#[derive(Clone)]
pub struct AgentKey(pub Zeroizing<[u8; 32]>);

impl AgentKey {
    pub fn generate() -> Self {
        Self(Zeroizing::new(random()))
    }

    pub fn encode(&self) -> String {
        format!("ptk_{}", base32(&self.0[..]).to_lowercase())
    }

    pub fn parse(s: &str) -> Result<Self, Error> {
        let body = s.trim().strip_prefix("ptk_").ok_or(Error::BadSecretKey)?.to_ascii_uppercase();
        if body.len() != 52 {
            return Err(Error::BadSecretKey);
        }
        let mut out = Zeroizing::new([0u8; 32]);
        let (mut acc, mut n, mut i) = (0u32, 0, 0);
        for c in body.bytes() {
            let v = CROCKFORD.iter().position(|&x| x == c).ok_or(Error::BadSecretKey)? as u32;
            acc = (acc << 5) | v;
            n += 5;
            if n >= 8 {
                n -= 8;
                out[i] = (acc >> n) as u8;
                i += 1;
            }
        }
        let k = AgentKey(out);
        if k.encode()[4..] != body.to_lowercase() {
            return Err(Error::BadSecretKey);
        }
        Ok(k)
    }
}

pub fn derive_agent(k: &AgentKey) -> Derived {
    let hk = Hkdf::<Sha256>::new(Some(b"plaintext/v1/agent"), &k.0[..]);
    let mut id = [0u8; 16];
    hk.expand(b"plaintext/v1/account-id", &mut id).expect("valid length");
    expand_keys(&hk, id)
}

// ---------- Public-key crypto ----------

pub fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    use hmac::Mac;
    let mut m = <hmac::Hmac<Sha256> as Mac>::new_from_slice(key).expect("any key length");
    m.update(data);
    m.finalize().into_bytes().into()
}

/// Sign `plaintext/v1/<domain> ‖ msg`, so a signature for one purpose is never valid for another.
pub fn sign(key: &SigningKey, domain: &str, msg: &[u8]) -> [u8; 64] {
    key.sign(&[format!("plaintext/v1/{domain}").as_bytes(), msg].concat()).to_bytes()
}

pub fn verify(pk: &[u8], domain: &str, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
    let pk: [u8; 32] = pk.try_into().map_err(|_| Error::BadSignature)?;
    let pk = ed25519_dalek::VerifyingKey::from_bytes(&pk).map_err(|_| Error::BadSignature)?;
    let sig = ed25519_dalek::Signature::from_slice(sig).map_err(|_| Error::BadSignature)?;
    pk.verify_strict(&[format!("plaintext/v1/{domain}").as_bytes(), msg].concat(), &sig)
        .map_err(|_| Error::BadSignature)
}

/// Seal to an X25519 public key: `ephemeral_pk(32) ‖ seal(k, ad, pt)` where k comes
/// from ECDH with a fresh ephemeral key. Anyone can seal, so authenticity comes
/// from whatever signs or commits to the result.
pub fn seal_to(recipient: &[u8], ad: &[u8], pt: &[u8]) -> Result<Vec<u8>, Error> {
    let rpk: [u8; 32] = recipient.try_into().map_err(|_| Error::Tampered)?;
    let eph = x25519_dalek::StaticSecret::from(random::<32>());
    let epk = x25519_dalek::PublicKey::from(&eph);
    let shared = eph.diffie_hellman(&x25519_dalek::PublicKey::from(rpk));
    if !shared.was_contributory() {
        return Err(Error::Tampered);
    }
    let k = seal_to_key(shared.as_bytes(), epk.as_bytes(), &rpk);
    Ok([&epk.as_bytes()[..], &seal(&k, ad, pt)].concat())
}

pub fn open_from(sk: &x25519_dalek::StaticSecret, ad: &[u8], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    if blob.len() < 32 {
        return Err(Error::Tampered);
    }
    let epk: [u8; 32] = blob[..32].try_into().expect("32 bytes");
    let shared = sk.diffie_hellman(&x25519_dalek::PublicKey::from(epk));
    if !shared.was_contributory() {
        return Err(Error::Tampered);
    }
    let rpk = x25519_dalek::PublicKey::from(sk);
    open(&seal_to_key(shared.as_bytes(), &epk, rpk.as_bytes()), ad, &blob[32..])
}

fn seal_to_key(shared: &[u8; 32], epk: &[u8; 32], rpk: &[u8; 32]) -> Key {
    let mut k = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(&[&epk[..], &rpk[..]].concat()), shared)
        .expand(b"plaintext/v1/seal-to", &mut k[..])
        .expect("valid length");
    k
}

/// What two people compare to be sure they see each other's real keys.
pub fn fingerprint(username: &str, sign_pk: &[u8], enc_pk: &[u8]) -> String {
    let h = sha256(&[b"plaintext/v1/fingerprint".as_slice(), username.as_bytes(), &[0], sign_pk, enc_pk].concat());
    let s = base32(&h[..15]);
    (0..4).map(|i| &s[i * 6..i * 6 + 6]).collect::<Vec<_>>().join(" ")
}

pub fn password_change_message(account_id: &Id, ts: u64, new_auth: &[u8], new_account_key: &[u8]) -> Vec<u8> {
    [b"plaintext/v1/password-change".as_slice(), account_id, &ts.to_be_bytes(), new_auth, &sha256(new_account_key)].concat()
}

/// Signed by the login key to delete the account, so a stolen session token alone
/// can't. Names the server's host like a login, so a look-alike can't relay it.
pub fn account_delete_message(account_id: &Id, ts: u64, host: &str) -> Vec<u8> {
    [b"plaintext/v1/account-delete".as_slice(), account_id, &ts.to_be_bytes(), host.as_bytes()].concat()
}

/// A server address reduced to what both sides can agree on: lowercase host and
/// port, no scheme, path or default port. `https://Vault.Example.com:443/` and the
/// `Host` header `vault.example.com` both give `vault.example.com`.
pub fn server_host(url: &str) -> String {
    let rest = url.trim().split_once("://").map_or(url.trim(), |(_, r)| r);
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default().to_ascii_lowercase();
    host.strip_suffix(":443").or_else(|| host.strip_suffix(":80")).map(String::from).unwrap_or(host)
}

/// Signed at login. The host binds the signature to the server the client meant
/// to reach, so a look-alike server can't relay it to the real one for a session.
pub fn login_message(account_id: &Id, ts: u64, host: &str) -> Vec<u8> {
    [b"plaintext/v1/login".as_slice(), account_id, &ts.to_be_bytes(), host.as_bytes()].concat()
}

pub fn sign_login(d: &Derived, ts: u64, host: &str) -> [u8; 64] {
    d.auth.sign(&login_message(&d.account_id, ts, host)).to_bytes()
}

// ---------- Sealed blobs ----------

/// Associated data names what a blob is and where it lives, so the server can't
/// move a blob to another item, vault or role.
pub fn ad(kind: &str, ids: &[&Id]) -> Vec<u8> {
    let mut v = format!("plaintext/v1/{kind}").into_bytes();
    for id in ids {
        v.extend_from_slice(&id[..]);
    }
    v
}

/// `V1 || nonce(24) || XChaCha20-Poly1305(ciphertext || tag)`.
pub fn seal(key: &Key, ad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let nonce: [u8; 24] = random();
    let aad = [&[V1][..], ad].concat();
    let ct = XChaCha20Poly1305::new(key.as_ref().into())
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad: &aad })
        .expect("encrypt");
    [&[V1][..], &nonce, &ct].concat()
}

pub fn open(key: &Key, ad: &[u8], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    if blob.len() < 1 + 24 + 16 || blob[0] != V1 {
        return Err(Error::Tampered);
    }
    let aad = [&[V1][..], ad].concat();
    XChaCha20Poly1305::new(key.as_ref().into())
        .decrypt(XNonce::from_slice(&blob[1..25]), Payload { msg: &blob[25..], aad: &aad })
        .map(Zeroizing::new)
        .map_err(|_| Error::Tampered)
}

pub fn seal_key(wrapping: &Key, ad: &[u8], key: &Key) -> Vec<u8> {
    seal(wrapping, ad, &key[..])
}

pub fn open_key(wrapping: &Key, ad: &[u8], blob: &[u8]) -> Result<Key, Error> {
    let raw = open(wrapping, ad, blob)?;
    let arr: [u8; 32] = raw[..].try_into().map_err(|_| Error::Tampered)?;
    Ok(Zeroizing::new(arr))
}
