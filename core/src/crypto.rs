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
    // NFKD so the same password typed on macOS, Windows and Android matches.
    let password = Zeroizing::new(password.nfkd().collect::<String>());
    let salt = sha256(&[b"plaintext/v1/argon-salt".as_slice(), &sk.0[..]].concat());
    let params = Params::new(ARGON_M_KIB, ARGON_T, ARGON_P, Some(32)).expect("valid params");
    let mut stretched = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), &salt, &mut stretched[..])
        .expect("argon2");
    // The Secret Key is the HKDF salt: without it, the password alone yields nothing.
    let hk = Hkdf::<Sha256>::new(Some(&sk.0[..]), &stretched[..]);
    let mut unlock_key = Zeroizing::new([0u8; 32]);
    let mut auth_seed = Zeroizing::new([0u8; 32]);
    hk.expand(b"plaintext/v1/unlock", &mut unlock_key[..]).expect("valid length");
    hk.expand(b"plaintext/v1/auth", &mut auth_seed[..]).expect("valid length");
    Derived { account_id: account_id(sk), unlock_key, auth: SigningKey::from_bytes(&auth_seed) }
}

pub fn login_message(account_id: &Id, ts: u64) -> Vec<u8> {
    [b"plaintext/v1/login".as_slice(), account_id, &ts.to_be_bytes()].concat()
}

pub fn sign_login(d: &Derived, ts: u64) -> [u8; 64] {
    d.auth.sign(&login_message(&d.account_id, ts)).to_bytes()
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
