//! Checking security-key responses for sign-in (DESIGN "Signing in with a
//! security key"). Only what that needs: ES256 and EdDSA credentials, no
//! attestation (the request adding a key is signed by the login key already).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use plaintext_core::api::Assertion;
use plaintext_core::crypto::sha256;

pub type Res<T> = Result<T, &'static str>;

const UP: u8 = 0x01;
const AT: u8 = 0x40;

/// authenticatorData made for `rp_id` with a touch; returns its signature counter.
fn auth_data(a: &[u8], rp_id: &str) -> Res<u32> {
    if a.len() < 37 || a[..32] != sha256(rp_id.as_bytes()) {
        return Err("the security key answered for another server");
    }
    if a[32] & UP == 0 {
        return Err("the security key wasn't touched");
    }
    Ok(u32::from_be_bytes(a[33..37].try_into().expect("4 bytes")))
}

/// The credential id and COSE public key in a new credential's authenticatorData.
pub fn registration(a: &[u8], rp_id: &str) -> Res<(Vec<u8>, Vec<u8>)> {
    auth_data(a, rp_id)?;
    let bad = "malformed security key registration";
    if a[32] & AT == 0 || a.len() < 55 {
        return Err(bad);
    }
    let n = u16::from_be_bytes([a[53], a[54]]) as usize;
    let id = a.get(55..55 + n).ok_or(bad)?.to_vec();
    let rest = &a[55 + n..];
    let mut r = rest;
    let _: ciborium::Value = ciborium::from_reader(&mut r).map_err(|_| bad)?;
    let cose = rest[..rest.len() - r.len()].to_vec();
    PublicKey::parse(&cose)?;
    if id.is_empty() || id.len() > 1023 {
        return Err(bad);
    }
    Ok((id, cose))
}

enum PublicKey {
    Es256(p256::ecdsa::VerifyingKey),
    EdDsa(ed25519_dalek::VerifyingKey),
}

impl PublicKey {
    fn parse(cose: &[u8]) -> Res<Self> {
        let bad = "unsupported security key (it needs ES256 or EdDSA)";
        let v: ciborium::Value = ciborium::from_reader(cose).map_err(|_| bad)?;
        let map = v.into_map().map_err(|_| bad)?;
        let get = |k: i64| map.iter().find(|(key, _)| key.as_integer().is_some_and(|i| i128::from(i) == k as i128)).map(|(_, v)| v);
        let int = |k: i64| get(k).and_then(|v| v.as_integer()).map(i128::from);
        let bytes = |k: i64| get(k).and_then(|v| v.as_bytes()).filter(|b| b.len() == 32);
        match (int(1), int(3), int(-1)) {
            (Some(2), Some(-7), Some(1)) => {
                let point = [&[4u8][..], bytes(-2).ok_or(bad)?, bytes(-3).ok_or(bad)?].concat();
                Ok(PublicKey::Es256(p256::ecdsa::VerifyingKey::from_sec1_bytes(&point).map_err(|_| bad)?))
            }
            (Some(1), Some(-8), Some(6)) => {
                let x: [u8; 32] = bytes(-2).ok_or(bad)?.as_slice().try_into().map_err(|_| bad)?;
                Ok(PublicKey::EdDsa(ed25519_dalek::VerifyingKey::from_bytes(&x).map_err(|_| bad)?))
            }
            _ => Err(bad),
        }
    }

    fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        match self {
            PublicKey::Es256(k) => {
                use p256::ecdsa::signature::Verifier;
                p256::ecdsa::Signature::from_der(sig).is_ok_and(|s| k.verify(msg, &s).is_ok())
            }
            PublicKey::EdDsa(k) => ed25519_dalek::Signature::from_slice(sig).is_ok_and(|s| k.verify_strict(msg, &s).is_ok()),
        }
    }
}

/// Checks that `a` answers `challenge` for `rp_id`, from an origin `origin_ok`
/// accepts, with a touch, signed by the credential `cose`. Returns the new
/// signature counter, which must have grown past `count` if the key keeps one.
pub fn check(a: &Assertion, cose: &[u8], rp_id: &str, challenge: &[u8], origin_ok: impl Fn(&str) -> bool, count: u32) -> Res<u32> {
    #[derive(serde::Deserialize)]
    struct ClientData {
        #[serde(rename = "type")]
        kind: String,
        challenge: String,
        origin: String,
    }
    let cd: ClientData = serde_json::from_slice(&a.client_data.0).map_err(|_| "malformed security key answer")?;
    if cd.kind != "webauthn.get" || URL_SAFE_NO_PAD.decode(cd.challenge.trim_end_matches('=')).ok().as_deref() != Some(challenge) {
        return Err("the security key answered another request");
    }
    if !origin_ok(&cd.origin) {
        return Err("the security key was asked by another site");
    }
    let n = auth_data(&a.auth_data.0, rp_id)?;
    let msg = [&a.auth_data.0[..], &sha256(&a.client_data.0)].concat();
    if !PublicKey::parse(cose)?.verify(&msg, &a.signature.0) {
        return Err("the security key's signature doesn't check out");
    }
    // A counter that doesn't grow means a copy of the key (where it keeps one at all).
    if (n != 0 || count != 0) && n <= count {
        return Err("this security key's counter went backwards; it may have been copied");
    }
    Ok(n)
}

/// A software security key for tests (here, the client's and the CLI's): one
/// P-256 credential, with a counter.
pub mod soft {
    use super::*;
    use p256::ecdsa::signature::Signer;
    use plaintext_core::api::B64;
    use plaintext_core::crypto::client_data;

    pub struct SoftKey {
        pub id: Vec<u8>,
        key: p256::ecdsa::SigningKey,
        pub count: u32,
    }

    impl Default for SoftKey {
        fn default() -> Self {
            Self::new()
        }
    }

    impl SoftKey {
        pub fn new() -> Self {
            let key = p256::ecdsa::SigningKey::from_slice(&plaintext_core::crypto::random::<32>()).expect("valid scalar");
            SoftKey { id: plaintext_core::crypto::random::<16>().to_vec(), key, count: 0 }
        }

        fn cose(&self) -> Vec<u8> {
            let p = self.key.verifying_key().to_encoded_point(false);
            let i = |n: i64| ciborium::Value::Integer(n.into());
            let m = ciborium::Value::Map(vec![
                (i(1), i(2)),
                (i(3), i(-7)),
                (i(-1), i(1)),
                (i(-2), ciborium::Value::Bytes(p.x().expect("x").to_vec())),
                (i(-3), ciborium::Value::Bytes(p.y().expect("y").to_vec())),
            ]);
            let mut out = vec![];
            ciborium::into_writer(&m, &mut out).expect("cbor");
            out
        }

        /// authenticatorData of a new credential for `rp_id`.
        pub fn register(&self, rp_id: &str) -> Vec<u8> {
            [&sha256(rp_id.as_bytes())[..], &[UP | AT], &0u32.to_be_bytes(), &[0u8; 16], &(self.id.len() as u16).to_be_bytes(), &self.id, &self.cose()].concat()
        }

        pub fn assert(&mut self, rp_id: &str, challenge: &[u8], origin: &str) -> Assertion {
            self.sign(rp_id, client_data("webauthn.get", challenge, origin))
        }

        /// An answer to clientDataJSON `cd`, as a CTAP client gets it.
        pub fn sign(&mut self, rp_id: &str, cd: Vec<u8>) -> Assertion {
            self.count += 1;
            let ad = [&sha256(rp_id.as_bytes())[..], &[UP], &self.count.to_be_bytes()].concat();
            let sig: p256::ecdsa::Signature = self.key.sign(&[&ad[..], &sha256(&cd)].concat());
            Assertion { id: B64(self.id.clone()), client_data: B64(cd), auth_data: B64(ad), signature: B64(sig.to_der().as_bytes().to_vec()) }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::soft::SoftKey;
    use super::*;
    use plaintext_core::crypto::client_data;

    #[test]
    fn assertions_are_checked() {
        let mut k = SoftKey::new();
        let (id, cose) = registration(&k.register("vault.example"), "vault.example").unwrap();
        assert_eq!(id, k.id);
        assert!(registration(&k.register("evil.example"), "vault.example").is_err());
        let ok = |o: &str| o == "https://vault.example";
        let a = k.assert("vault.example", b"challenge", "https://vault.example");
        assert_eq!(check(&a, &cose, "vault.example", b"challenge", ok, 0), Ok(1));
        // The counter must grow.
        assert!(check(&a, &cose, "vault.example", b"challenge", ok, 1).is_err());
        assert!(check(&a, &cose, "vault.example", b"other", ok, 0).is_err());
        assert!(check(&a, &cose, "vault.example", b"challenge", |_| false, 0).is_err());
        assert!(check(&k.assert("evil.example", b"challenge", "https://vault.example"), &cose, "vault.example", b"challenge", ok, 0).is_err());
        let mut forged = k.assert("vault.example", b"challenge", "https://vault.example");
        forged.auth_data.0[36] ^= 1;
        assert!(check(&forged, &cose, "vault.example", b"challenge", ok, 0).is_err());
        let mut untouched = k.assert("vault.example", b"challenge", "https://vault.example");
        untouched.auth_data.0[32] = 0;
        assert!(check(&untouched, &cose, "vault.example", b"challenge", ok, 0).is_err());
        let mut create = k.assert("vault.example", b"challenge", "https://vault.example");
        create.client_data.0 = client_data("webauthn.create", b"challenge", "https://vault.example");
        assert!(check(&create, &cose, "vault.example", b"challenge", ok, 0).is_err());
        let other = SoftKey::new();
        let (_, other_cose) = registration(&other.register("vault.example"), "vault.example").unwrap();
        assert!(check(&k.assert("vault.example", b"challenge", "https://vault.example"), &other_cose, "vault.example", b"challenge", ok, 0).is_err());
    }
}
