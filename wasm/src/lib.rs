//! Plaintext core for browsers (wasm-bindgen, `--target web`). Each export is a
//! thin wrapper over a plain function, so the logic builds and tests natively;
//! later exports (sessions, sync over fetch) follow the same pattern.

use base64::{Engine, engine::general_purpose::STANDARD};
use plaintext_core::api::Hex;
use wasm_bindgen::prelude::*;

/// Decrypt a share link. `blob_b64` is the string `GET /v1/links/{id}` returned.
/// Gives the item as JSON, or the error code `bad_link` (malformed id),
/// `tampered` (wrong key, or the blob was altered) or `unreadable` (it decrypted
/// but isn't an item this version understands).
pub fn open_link_json(id_hex: &str, blob_b64: &str, key_hex: &str) -> Result<String, &'static str> {
    let id: Hex = id_hex.parse().map_err(|_| "bad_link")?;
    let blob = STANDARD.decode(blob_b64).map_err(|_| "tampered")?;
    let item = plaintext_core::open_link(&id, &blob, key_hex).map_err(|e| match e {
        plaintext_core::Error::BadJson => "unreadable",
        _ => "tampered",
    })?;
    Ok(serde_json::to_string(&item).expect("serializable"))
}

/// The current one-time code and the seconds it stays valid, as `["123456",17]`.
pub fn totp_json(spec: &str, now_secs: u64) -> Option<String> {
    plaintext_core::tools::totp(spec, now_secs).map(|(code, left)| serde_json::json!([code, left]).to_string())
}

#[wasm_bindgen(js_name = open_link)]
pub fn js_open_link(id_hex: &str, blob_b64: &str, key_hex: &str) -> Result<String, JsError> {
    open_link_json(id_hex, blob_b64, key_hex).map_err(JsError::new)
}

#[wasm_bindgen(js_name = totp)]
pub fn js_totp(spec: &str, now_secs: f64) -> Option<String> {
    totp_json(spec, now_secs as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use plaintext_core::item::Item;

    #[test]
    fn link_round_trip() {
        let item = Item { title: "Bank".into(), password: "hunter2".into(), ..Default::default() };
        let (link, key) = plaintext_core::create_link(&item, 0, Some(1));
        let (id, blob) = (link.id.to_string(), STANDARD.encode(&link.blob.0));

        let json = open_link_json(&id, &blob, &key).unwrap();
        assert_eq!(serde_json::from_str::<Item>(&json).unwrap(), item);

        let wrong = format!("{}{}", &key[..63], if key.ends_with('0') { '1' } else { '0' });
        assert_eq!(open_link_json(&id, &blob, &wrong), Err("tampered"));
        let mut flipped = link.blob.0.clone();
        flipped[30] ^= 1;
        assert_eq!(open_link_json(&id, &STANDARD.encode(flipped), &key), Err("tampered"));
        assert_eq!(open_link_json(&id, "not base64!", &key), Err("tampered"));
        assert_eq!(open_link_json("abc", &blob, &key), Err("bad_link"));
        let other = plaintext_core::new_item_id().to_string();
        assert_eq!(open_link_json(&other, &blob, &key), Err("tampered"));

        // Sealed under the link's key, but not an item.
        use plaintext_core::crypto::{Key, ad, seal};
        let raw: [u8; 32] = std::array::from_fn(|i| u8::from_str_radix(&key[2 * i..2 * i + 2], 16).unwrap());
        let junk = seal(&Key::new(raw), &ad("link", &[&link.id.0]), b"[1,2]");
        assert_eq!(open_link_json(&id, &STANDARD.encode(junk), &key), Err("unreadable"));
    }

    #[test]
    fn totp_shape() {
        // RFC 6238 SHA-1 vector at t = 59.
        assert_eq!(totp_json("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59).as_deref(), Some(r#"["287082",1]"#));
        assert_eq!(totp_json("not base32!", 59), None);
    }
}
