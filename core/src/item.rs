//! What's inside a sealed item. Mirrors 1Password's model (a category, the login
//! designations, then free-form sections of typed fields) so imports are lossless.
//! Unknown fields are kept, so an older client never drops data a newer one wrote.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::api::B64;

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Item {
    /// `login`, `password`, `note`, `card`, `identity`, `document`, `bank`,
    /// `database`, `server`, `ssh_key`, `api_credential`, `wifi`, `passport`,
    /// `license`, `membership`, `crypto_wallet`, … (see DESIGN.md).
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub title: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub username: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub password: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub urls: Vec<String>,
    /// `otpauth://` URI or a base32 secret.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub totp: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notes: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sections: Vec<Section>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub favorite: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub archived: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<FileRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub passkeys: Vec<Passkey>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub password_history: Vec<OldPassword>,
    /// Earlier versions of this item (without their own history), newest first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub history: Vec<Value>,
    /// Unix milliseconds.
    #[serde(default)]
    pub created: u64,
    #[serde(default)]
    pub updated: u64,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Section {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub title: String,
    #[serde(default)]
    pub fields: Vec<Field>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Field {
    pub label: String,
    /// `text`, `concealed`, `url`, `email`, `phone`, `date`, `month_year`, `otp`,
    /// `address`, `menu`, `card_number`, `card_type`, `ssh_key`, `boolean`.
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub value: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// An attachment. The file is sealed with its own random key, stored here, so a
/// vault key change never has to re-upload files.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FileRef {
    pub id: crate::api::Hex,
    pub name: String,
    pub size: u64,
    pub key: B64,
    /// SHA-256 of the sealed upload.
    pub hash: B64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Passkey {
    pub rp_id: String,
    pub credential_id: B64,
    pub user_handle: B64,
    #[serde(default)]
    pub user_name: String,
    /// PKCS#8 private key.
    pub private_key: B64,
    #[serde(default)]
    pub counter: u32,
    #[serde(default)]
    pub created: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct OldPassword {
    pub password: String,
    pub changed: u64,
}

const HISTORY: usize = 10;

impl Item {
    /// Replace this item with `next`, keeping the old version in `history` and the
    /// old password in `password_history`.
    pub fn edit(&mut self, mut next: Item, now_ms: u64) {
        let mut old = std::mem::take(self);
        next.history = std::mem::take(&mut old.history);
        next.password_history = std::mem::take(&mut old.password_history);
        if !old.password.is_empty() && old.password != next.password {
            next.password_history.insert(0, OldPassword { password: old.password.clone(), changed: now_ms });
        }
        if let Ok(v) = serde_json::to_value(&old) {
            next.history.insert(0, v);
        }
        next.history.truncate(HISTORY);
        next.created = old.created;
        next.updated = now_ms;
        *self = next;
    }

    /// Every concealed value, for Watchtower-style checks and search exclusion.
    pub fn secrets(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.password.as_str())
            .chain(self.sections.iter().flat_map(|s| &s.fields).filter(|f| f.kind == "concealed").map(|f| f.value.as_str()))
            .filter(|s| !s.is_empty())
    }

    /// Case-insensitive match on title, username, URLs, tags and non-secret fields.
    pub fn matches(&self, query: &str) -> bool {
        let q = query.to_lowercase();
        let hit = |s: &str| s.to_lowercase().contains(&q);
        hit(&self.title)
            || hit(&self.username)
            || self.urls.iter().any(|u| hit(u))
            || self.tags.iter().any(|t| hit(t))
            || hit(&self.notes)
            || self.sections.iter().flat_map(|s| &s.fields).any(|f| f.kind != "concealed" && (hit(&f.label) || hit(&f.value)))
    }

    /// A field by label (case-insensitive), or one of the built-ins.
    pub fn field(&self, name: &str) -> Option<&str> {
        match name.to_lowercase().as_str() {
            "title" => Some(&self.title),
            "username" => Some(&self.username),
            "password" => Some(&self.password),
            "notes" => Some(&self.notes),
            "url" => self.urls.first().map(String::as_str),
            "totp" | "otp" => Some(&self.totp),
            n => self.sections.iter().flat_map(|s| &s.fields).find(|f| f.label.to_lowercase() == n).map(|f| f.value.as_str()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edit_keeps_history() {
        let mut it = Item { title: "a".into(), password: "one".into(), created: 5, ..Default::default() };
        it.edit(Item { title: "a".into(), password: "two".into(), ..Default::default() }, 10);
        it.edit(Item { title: "b".into(), password: "two".into(), ..Default::default() }, 20);
        assert_eq!(it.password_history.len(), 1);
        assert_eq!(it.password_history[0].password, "one");
        assert_eq!(it.history.len(), 2);
        assert_eq!(it.history[0]["title"], "a");
        assert_eq!((it.created, it.updated), (5, 20));
        assert!(it.history[0].get("history").is_none());
    }

    #[test]
    fn unknown_fields_survive() {
        let item: Item = serde_json::from_str(r#"{"title":"t","future":{"x":1},"sections":[{"fields":[{"label":"l","type":"text","value":"v","new":true}]}]}"#).unwrap();
        let out = serde_json::to_string(&item).unwrap();
        assert!(out.contains("future") && out.contains("\"new\":true"));
    }
}
