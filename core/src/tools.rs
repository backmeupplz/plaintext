//! Password generator, one-time codes and Watchtower checks. All local: the only
//! network check (breached passwords) sends just 5 hex chars of a SHA-1 hash.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::api::Hex;
use crate::item::Item;

const WORDS: &str = include_str!("eff_words.txt");

/// A uniformly random index below `n` (rejection sampling, no modulo bias).
fn below(n: u32) -> u32 {
    let zone = u32::MAX - (u32::MAX % n);
    loop {
        let r = u32::from_le_bytes(crate::crypto::random());
        if r < zone {
            return r % n;
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Recipe {
    Random { length: u32, digits: bool, symbols: bool },
    /// Words from the EFF large list (12.9 bits each).
    Memorable { words: u32, separator: String, capitalize: bool },
    Pin { length: u32 },
}

impl Default for Recipe {
    fn default() -> Self {
        Recipe::Random { length: 20, digits: true, symbols: true }
    }
}

pub fn generate(r: &Recipe) -> String {
    match r {
        Recipe::Random { length, digits, symbols } => {
            // Look-alikes (0/O, 1/l/I) left out so passwords can be read aloud and typed.
            let mut sets = vec!["abcdefghijkmnopqrstuvwxyz", "ABCDEFGHJKLMNPQRSTUVWXYZ"];
            if *digits {
                sets.push("23456789");
            }
            if *symbols {
                sets.push("!@#$%^&*-_=+?");
            }
            let all: Vec<char> = sets.concat().chars().collect();
            let length = (*length).clamp(sets.len() as u32, 128);
            loop {
                let pw: String = (0..length).map(|_| all[below(all.len() as u32) as usize]).collect();
                // Every chosen class appears at least once (re-roll otherwise; rare).
                if sets.iter().all(|s| pw.chars().any(|c| s.contains(c))) {
                    return pw;
                }
            }
        }
        Recipe::Memorable { words, separator, capitalize } => {
            let list: Vec<&str> = WORDS.lines().collect();
            (0..(*words).clamp(3, 20))
                .map(|_| {
                    let w = list[below(list.len() as u32) as usize];
                    if *capitalize {
                        let mut c = w.chars();
                        c.next().map(|f| f.to_uppercase().chain(c).collect()).unwrap_or_default()
                    } else {
                        w.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join(separator)
        }
        Recipe::Pin { length } => (0..(*length).clamp(4, 32)).map(|_| char::from(b'0' + below(10) as u8)).collect(),
    }
}

/// Rough guessing entropy in bits: character-class size × length, minus
/// repeats and runs. ponytail: no dictionary, so "Password1!" scores higher than
/// it should; swap in a zxcvbn-style estimator if Watchtower needs to be sharper.
pub fn strength_bits(pw: &str) -> f64 {
    let pool: u32 = [
        (pw.chars().any(|c| c.is_ascii_lowercase()), 26),
        (pw.chars().any(|c| c.is_ascii_uppercase()), 26),
        (pw.chars().any(|c| c.is_ascii_digit()), 10),
        (pw.chars().any(|c| c.is_ascii_punctuation() || c == ' '), 33),
        (!pw.is_ascii(), 100),
    ]
    .iter()
    .filter(|(has, _)| *has)
    .map(|(_, n)| n)
    .sum();
    let chars: Vec<char> = pw.chars().collect();
    let mut effective = 0.0;
    for (i, c) in chars.iter().enumerate() {
        let repeat = i > 0 && chars[i - 1] == *c;
        let run = i > 0 && (*c as i64 - chars[i - 1] as i64).abs() == 1;
        effective += if repeat || run { 0.25 } else { 1.0 };
    }
    if pool == 0 { 0.0 } else { effective * (pool as f64).log2() }
}

// ---------- One-time codes ----------

fn base32_rfc4648(s: &str) -> Option<Vec<u8>> {
    let (mut acc, mut n, mut out) = (0u32, 0, Vec::new());
    for c in s.chars().filter(|c| !matches!(c, ' ' | '-' | '=')) {
        let v = match c.to_ascii_uppercase() {
            c @ 'A'..='Z' => c as u32 - 'A' as u32,
            c @ '2'..='7' => c as u32 - '2' as u32 + 26,
            _ => return None,
        };
        acc = (acc << 5) | v;
        n += 5;
        if n >= 8 {
            n -= 8;
            out.push((acc >> n) as u8);
        }
    }
    (!out.is_empty()).then_some(out)
}

/// The current code for an `otpauth://totp/…` URI or a bare base32 secret, and
/// the seconds it stays valid.
pub fn totp(spec: &str, now: u64) -> Option<(String, u64)> {
    let (mut secret, mut digits, mut period, mut algo) = (spec.trim().to_string(), 6u32, 30u64, "SHA1".to_string());
    let t = spec.trim();
    let uri = t.get(..15).is_some_and(|p| p.eq_ignore_ascii_case("otpauth://totp/"));
    if let Some((_, q)) = uri.then(|| t[15..].split_once('?')).flatten() {
        for kv in q.split('&') {
            let Some((k, v)) = kv.split_once('=') else { continue };
            let v = v.replace("%3D", "=");
            match k.to_lowercase().as_str() {
                "secret" => secret = v,
                "digits" => digits = v.parse().ok()?,
                "period" => period = v.parse().ok()?,
                "algorithm" => algo = v.to_uppercase(),
                _ => {}
            }
        }
    }
    if !(6..=10).contains(&digits) || period == 0 {
        return None;
    }
    let key = base32_rfc4648(&secret)?;
    let counter = (now / period).to_be_bytes();
    use hmac::{Hmac, Mac};
    let mac = match algo.as_str() {
        "SHA1" => <Hmac<sha1::Sha1> as Mac>::new_from_slice(&key).ok()?.chain_update(counter).finalize().into_bytes().to_vec(),
        "SHA256" => <Hmac<sha2::Sha256> as Mac>::new_from_slice(&key).ok()?.chain_update(counter).finalize().into_bytes().to_vec(),
        "SHA512" => <Hmac<sha2::Sha512> as Mac>::new_from_slice(&key).ok()?.chain_update(counter).finalize().into_bytes().to_vec(),
        _ => return None,
    };
    let off = (mac[mac.len() - 1] & 0xf) as usize;
    let bin = u32::from_be_bytes(mac[off..off + 4].try_into().ok()?) & 0x7fff_ffff;
    let code = bin as u64 % 10u64.pow(digits);
    Some((format!("{code:0width$}", width = digits as usize), period - now % period))
}

// ---------- Watchtower ----------

/// The first 5 hex chars go to the breach service; the rest stays here.
pub fn breach_prefix(password: &str) -> (String, String) {
    use sha1::Digest;
    let h = hex::encode_upper(sha1::Sha1::digest(password.as_bytes()));
    (h[..5].to_string(), h[5..].to_string())
}

/// Whether a Have I Been Pwned range response (`SUFFIX:COUNT` lines) lists our suffix.
pub fn breach_count(range_response: &str, suffix: &str) -> u64 {
    range_response
        .lines()
        .filter_map(|l| l.trim().split_once(':'))
        .find(|(s, _)| s.eq_ignore_ascii_case(suffix))
        .and_then(|(_, n)| n.trim().parse().ok())
        .unwrap_or(0)
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Finding {
    Weak,
    Reused,
    /// A login on a plain `http://` address.
    Unsecured,
    /// No one-time code saved for a login (2FA may be available).
    NoTwoFactor,
}

/// Local Watchtower checks over items (archived ones skipped).
pub fn watchtower<'a>(items: impl IntoIterator<Item = (Hex, &'a Item)>) -> BTreeMap<Hex, Vec<Finding>> {
    let items: Vec<(Hex, &Item)> = items.into_iter().filter(|(_, i)| !i.archived).collect();
    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
    for (_, i) in &items {
        if !i.password.is_empty() {
            *seen.entry(i.password.as_str()).or_default() += 1;
        }
    }
    let mut out = BTreeMap::new();
    for (id, i) in items {
        let mut f = Vec::new();
        if !i.password.is_empty() && strength_bits(&i.password) < 50.0 {
            f.push(Finding::Weak);
        }
        if seen.get(i.password.as_str()).is_some_and(|n| *n > 1) {
            f.push(Finding::Reused);
        }
        if i.urls.iter().any(|u| u.starts_with("http://")) {
            f.push(Finding::Unsecured);
        }
        if i.kind == "login" && i.totp.is_empty() && !i.urls.is_empty() {
            f.push(Finding::NoTwoFactor);
        }
        if !f.is_empty() {
            out.insert(id, f);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generator_recipes() {
        let pw = generate(&Recipe::default());
        assert_eq!(pw.chars().count(), 20);
        assert!(strength_bits(&pw) > 100.0);
        let m = generate(&Recipe::Memorable { words: 5, separator: "-".into(), capitalize: true });
        assert_eq!(m.split('-').count(), 5);
        assert!(m.split('-').all(|w| w.chars().next().unwrap().is_uppercase()));
        let p = generate(&Recipe::Pin { length: 6 });
        assert!(p.len() == 6 && p.chars().all(|c| c.is_ascii_digit()));
        assert_ne!(generate(&Recipe::default()), generate(&Recipe::default()));
        assert_eq!(WORDS.lines().count(), 7776);
    }

    #[test]
    fn strength_orders_sensibly() {
        assert!(strength_bits("aaaaaaaa") < strength_bits("password"));
        assert!(strength_bits("123456") < 30.0);
        assert!(strength_bits("correct-horse-battery-staple") > 100.0);
    }

    /// RFC 6238 appendix B vectors (SHA-1 and SHA-256, 8 digits).
    #[test]
    fn totp_rfc6238() {
        let sha1 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"; // "12345678901234567890"
        let uri = |algo: &str, secret: &str| format!("otpauth://totp/x?secret={secret}&digits=8&algorithm={algo}");
        assert_eq!(totp(&uri("SHA1", sha1), 59).unwrap().0, "94287082");
        assert_eq!(totp(&uri("SHA1", sha1), 1111111109).unwrap().0, "07081804");
        let sha256 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA"; // 32 bytes
        assert_eq!(totp(&uri("SHA256", sha256), 59).unwrap().0, "46119246");
        let (code, left) = totp(sha1, 59).unwrap();
        assert_eq!((code.as_str(), left), ("287082", 1));
        // A trailing `&`, a bare flag and an upper-case scheme still parse.
        assert_eq!(totp(&format!("OTPAuth://TOTP/x?secret={sha1}&flag&"), 59).unwrap().0, "287082");
    }

    #[test]
    fn breach_check_shape() {
        let (prefix, suffix) = breach_prefix("password");
        assert_eq!(prefix, "5BAA6");
        assert_eq!(breach_count(&format!("0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n{suffix}:9659365\r\n"), &suffix), 9659365);
    }

    #[test]
    fn watchtower_flags() {
        let a = Item { kind: "login".into(), password: "hunter2".into(), urls: vec!["http://old.example".into()], ..Default::default() };
        let b = Item { kind: "login".into(), password: "hunter2".into(), ..Default::default() };
        let c = Item { kind: "login".into(), password: generate(&Recipe::default()), totp: "X".into(), urls: vec!["https://ok".into()], ..Default::default() };
        let r = watchtower([(Hex([1; 16]), &a), (Hex([2; 16]), &b), (Hex([3; 16]), &c)]);
        assert_eq!(r[&Hex([1; 16])], vec![Finding::Weak, Finding::Reused, Finding::Unsecured, Finding::NoTwoFactor]);
        assert_eq!(r[&Hex([2; 16])], vec![Finding::Weak, Finding::Reused]);
        assert!(!r.contains_key(&Hex([3; 16])));
    }
}
