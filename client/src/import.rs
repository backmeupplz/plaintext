//! Importers for 1Password (.1pux), Bitwarden/Vaultwarden (unencrypted .json) and
//! CSV (1Password, Bitwarden, Chrome, Firefox, Safari, generic), plus a Bitwarden
//! JSON exporter. Pure parsing on the device: nothing here touches the network.

use std::collections::BTreeMap;
use std::io::Read;

use plaintext_core::item::{Field, Item, OldPassword, Section};
use serde_json::{Value, json};

/// One vault's worth of imported items, with attachment bytes to upload.
pub struct Imported {
    /// The source vault's name, or empty to use the default vault.
    pub name: String,
    pub items: Vec<(Item, Vec<Attachment>)>,
}

/// An attachment's file name and bytes.
pub type Attachment = (String, Vec<u8>);

#[derive(Debug)]
pub struct ImportError(pub String);

impl std::fmt::Display for ImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "couldn't import: {}", self.0)
    }
}
impl std::error::Error for ImportError {}

fn err(s: impl Into<String>) -> ImportError {
    ImportError(s.into())
}

fn s(v: &Value, k: &str) -> String {
    v.get(k).and_then(Value::as_str).unwrap_or_default().to_string()
}

fn field(label: &str, kind: &str, value: impl Into<String>) -> Field {
    Field { label: label.into(), kind: kind.into(), value: value.into(), ..Default::default() }
}

// ---------- 1Password 1PUX ----------

/// 1Password's category ids, mapped to our item kinds.
fn category(uuid: &str) -> &'static str {
    match uuid {
        "001" => "login",
        "002" => "card",
        "003" => "note",
        "004" => "identity",
        "005" => "password",
        "006" => "document",
        "100" => "software_license",
        "101" => "bank",
        "102" => "database",
        "103" => "driver_license",
        "104" => "outdoor_license",
        "105" => "membership",
        "106" => "passport",
        "107" => "reward_program",
        "108" => "ssn",
        "109" => "wifi",
        "110" => "server",
        "111" => "email",
        "112" => "api_credential",
        "113" => "medical_record",
        "114" => "ssh_key",
        "115" => "crypto_wallet",
        _ => "login",
    }
}

pub fn days_to_date(days: i64) -> String {
    // Civil-from-days (Howard Hinnant), proleptic Gregorian.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

/// A 1PUX field value (`{"concealed": "…"}`, `{"email": {"email_address": …}}`, …)
/// as (our field type, text).
fn onepux_value(v: &Value) -> Option<(&'static str, String)> {
    let (k, x) = v.as_object()?.iter().next()?;
    let text = |x: &Value| x.as_str().map(String::from).unwrap_or_else(|| if x.is_null() { String::new() } else { x.to_string() });
    Some(match k.as_str() {
        "concealed" => ("concealed", text(x)),
        "totp" => ("otp", text(x)),
        "url" => ("url", text(x)),
        "phone" => ("phone", text(x)),
        "menu" => ("menu", text(x)),
        "creditCardNumber" => ("card_number", text(x)),
        "creditCardType" => ("card_type", text(x)),
        "email" => ("email", x.get("email_address").map(text).unwrap_or_else(|| text(x))),
        "date" => ("date", x.as_i64().map(|t| days_to_date(t.div_euclid(86400))).unwrap_or_else(|| text(x))),
        "monthYear" => ("month_year", x.as_i64().map(|n| format!("{:04}-{:02}", n / 100, n % 100)).unwrap_or_else(|| text(x))),
        "address" => (
            "address",
            ["street", "city", "state", "zip", "country"].iter().filter_map(|f| x.get(f).and_then(Value::as_str)).filter(|s| !s.is_empty()).collect::<Vec<_>>().join(", "),
        ),
        // metadata.privateKey is PKCS#8 PEM; the top-level one varies in format.
        "sshKey" => ("ssh_key", x.pointer("/metadata/privateKey").or_else(|| x.get("privateKey")).map(text).unwrap_or_default()),
        "file" => return None,
        _ => ("text", text(x)),
    })
}

fn onepux_item(it: &Value) -> Item {
    let ov = &it["overview"];
    let d = &it["details"];
    let mut item = Item {
        kind: category(it.get("categoryUuid").and_then(Value::as_str).unwrap_or("001")).into(),
        title: s(ov, "title"),
        notes: s(d, "notesPlain"),
        favorite: it.get("favIndex").and_then(Value::as_i64).is_some_and(|i| i > 0),
        archived: s(it, "state") == "archived",
        created: it.get("createdAt").and_then(Value::as_u64).unwrap_or_default() * 1000,
        updated: it.get("updatedAt").and_then(Value::as_u64).unwrap_or_default() * 1000,
        tags: ov.get("tags").and_then(Value::as_array).map(|t| t.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default(),
        ..Default::default()
    };
    let mut urls: Vec<String> = ov.get("urls").and_then(Value::as_array).map(|u| u.iter().map(|x| s(x, "url")).filter(|u| !u.is_empty()).collect()).unwrap_or_default();
    let main = s(ov, "url");
    if !main.is_empty() && !urls.contains(&main) {
        urls.insert(0, main);
    }
    item.urls = urls;
    let mut extra_login = Vec::new();
    for f in d.get("loginFields").and_then(Value::as_array).into_iter().flatten() {
        match s(f, "designation").as_str() {
            "username" => item.username = s(f, "value"),
            "password" => item.password = s(f, "value"),
            _ if !s(f, "value").is_empty() => {
                let kind = if s(f, "fieldType") == "P" { "concealed" } else { "text" };
                extra_login.push(field(&s(f, "name"), kind, s(f, "value")));
            }
            _ => {}
        }
    }
    if let Some(p) = d.get("password").and_then(Value::as_str).filter(|p| !p.is_empty()) {
        item.password = p.into();
    }
    if !extra_login.is_empty() {
        item.sections.push(Section { title: String::new(), fields: extra_login });
    }
    for sec in d.get("sections").and_then(Value::as_array).into_iter().flatten() {
        let mut fields = Vec::new();
        for f in sec.get("fields").and_then(Value::as_array).into_iter().flatten() {
            let Some((kind, value)) = f.get("value").and_then(onepux_value) else { continue };
            if value.is_empty() {
                continue;
            }
            // The first one-time code becomes the item's TOTP, so it shows up everywhere.
            if kind == "otp" && item.totp.is_empty() {
                item.totp = value;
                continue;
            }
            let mut label = s(f, "title");
            if label.is_empty() {
                label = kind.replace('_', " ");
            }
            fields.push(field(&label, kind, value));
        }
        if !fields.is_empty() {
            item.sections.push(Section { title: s(sec, "title"), fields });
        }
    }
    item.password_history = d
        .get("passwordHistory")
        .and_then(Value::as_array)
        .map(|h| h.iter().map(|p| OldPassword { password: s(p, "value"), changed: p.get("time").and_then(Value::as_u64).unwrap_or_default() * 1000 }).collect())
        .unwrap_or_default();
    item
}

/// A 1Password export (.1pux: a zip with export.data and files/).
pub fn onepux(zip_bytes: &[u8]) -> Result<Vec<Imported>, ImportError> {
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(zip_bytes)).map_err(|e| err(format!("not a .1pux file ({e})")))?;
    let mut data = String::new();
    zip.by_name("export.data").map_err(|_| err("no export.data in the .1pux file"))?.read_to_string(&mut data).map_err(|e| err(e.to_string()))?;
    let export: Value = serde_json::from_str(&data).map_err(|e| err(format!("export.data isn't valid JSON ({e})")))?;
    let mut files: BTreeMap<String, (String, Vec<u8>)> = BTreeMap::new();
    for i in 0..zip.len() {
        let mut f = zip.by_index(i).map_err(|e| err(e.to_string()))?;
        let Some(name) = f.name().strip_prefix("files/").map(String::from) else { continue };
        if let Some((doc_id, file_name)) = name.split_once("__") {
            let mut bytes = Vec::new();
            f.read_to_end(&mut bytes).map_err(|e| err(e.to_string()))?;
            files.insert(doc_id.to_string(), (file_name.trim_start_matches('_').to_string(), bytes));
        }
    }
    let mut out = Vec::new();
    for account in export.get("accounts").and_then(Value::as_array).into_iter().flatten() {
        for vault in account.get("vaults").and_then(Value::as_array).into_iter().flatten() {
            let mut items = Vec::new();
            for it in vault.get("items").and_then(Value::as_array).into_iter().flatten() {
                if s(it, "state") == "deleted" {
                    continue;
                }
                let item = onepux_item(it);
                let mut attached = Vec::new();
                let mut doc_ids: Vec<String> = it["details"].get("documentAttributes").map(|a| s(a, "documentId")).into_iter().collect();
                for sec in it["details"].get("sections").and_then(Value::as_array).into_iter().flatten() {
                    for f in sec.get("fields").and_then(Value::as_array).into_iter().flatten() {
                        if let Some(file) = f.get("value").and_then(|v| v.get("file")) {
                            doc_ids.push(s(file, "documentId"));
                        }
                    }
                }
                for id in doc_ids.iter().filter(|i| !i.is_empty()) {
                    if let Some(f) = files.get(id) {
                        attached.push(f.clone());
                    }
                }
                items.push((item, attached));
            }
            out.push(Imported { name: s(&vault["attrs"], "name"), items });
        }
    }
    if out.is_empty() {
        return Err(err("the export has no vaults"));
    }
    Ok(out)
}

// ---------- Bitwarden JSON ----------

/// A Bitwarden/Vaultwarden unencrypted JSON export. Folders become tags.
pub fn bitwarden(bytes: &[u8]) -> Result<Vec<Imported>, ImportError> {
    let v: Value = serde_json::from_slice(bytes).map_err(|e| err(format!("not JSON ({e})")))?;
    if v.get("encrypted").and_then(Value::as_bool) == Some(true) {
        return Err(err("this is an encrypted Bitwarden export; export again as unencrypted JSON"));
    }
    let folders: BTreeMap<String, String> =
        v.get("folders").and_then(Value::as_array).into_iter().flatten().map(|f| (s(f, "id"), s(f, "name"))).collect();
    let mut items = Vec::new();
    for b in v.get("items").and_then(Value::as_array).into_iter().flatten() {
        let mut it = Item {
            title: s(b, "name"),
            notes: s(b, "notes"),
            favorite: b.get("favorite").and_then(Value::as_bool).unwrap_or(false),
            ..Default::default()
        };
        if let Some(f) = b.get("folderId").and_then(Value::as_str).and_then(|id| folders.get(id)) {
            it.tags.push(f.clone());
        }
        let mut fields = Vec::new();
        let mut put = |label: &str, kind: &str, x: &Value, key: &str| {
            let val = s(x, key);
            if !val.is_empty() {
                fields.push(field(label, kind, val));
            }
        };
        match b.get("type").and_then(Value::as_u64).unwrap_or(1) {
            1 => {
                let l = &b["login"];
                it.kind = "login".into();
                it.username = s(l, "username");
                it.password = s(l, "password");
                it.totp = s(l, "totp");
                it.urls = l.get("uris").and_then(Value::as_array).map(|u| u.iter().map(|x| s(x, "uri")).filter(|u| !u.is_empty()).collect()).unwrap_or_default();
            }
            2 => it.kind = "note".into(),
            3 => {
                let c = &b["card"];
                it.kind = "card".into();
                put("cardholder name", "text", c, "cardholderName");
                put("type", "card_type", c, "brand");
                put("number", "card_number", c, "number");
                put("verification number", "concealed", c, "code");
                let (m, y) = (s(c, "expMonth"), s(c, "expYear"));
                if !y.is_empty() {
                    fields.push(field("expiry date", "month_year", format!("{y}-{m:0>2}")));
                }
            }
            4 => {
                let i = &b["identity"];
                it.kind = "identity".into();
                for (label, key) in [
                    ("title", "title"), ("first name", "firstName"), ("middle name", "middleName"), ("last name", "lastName"),
                    ("company", "company"), ("email", "email"), ("phone", "phone"), ("username", "username"),
                    ("address", "address1"), ("address 2", "address2"), ("address 3", "address3"), ("city", "city"),
                    ("state", "state"), ("postal code", "postalCode"), ("country", "country"),
                    ("passport number", "passportNumber"), ("license number", "licenseNumber"),
                ] {
                    put(label, "text", i, key);
                }
                put("social security number", "concealed", i, "ssn");
            }
            5 => {
                let k = &b["sshKey"];
                it.kind = "ssh_key".into();
                put("private key", "ssh_key", k, "privateKey");
                put("public key", "text", k, "publicKey");
                put("fingerprint", "text", k, "keyFingerprint");
            }
            _ => it.kind = "note".into(),
        }
        for f in b.get("fields").and_then(Value::as_array).into_iter().flatten() {
            let kind = match f.get("type").and_then(Value::as_u64) {
                Some(1) => "concealed",
                Some(2) => "boolean",
                _ => "text",
            };
            let val = f.get("value").map(|x| x.as_str().map(String::from).unwrap_or_else(|| if x.is_null() { String::new() } else { x.to_string() })).unwrap_or_default();
            fields.push(field(&s(f, "name"), kind, val));
        }
        if !fields.is_empty() {
            it.sections.push(Section { title: String::new(), fields });
        }
        it.password_history = b
            .get("passwordHistory")
            .and_then(Value::as_array)
            .map(|h| h.iter().map(|p| OldPassword { password: s(p, "password"), changed: 0 }).collect())
            .unwrap_or_default();
        items.push((it, vec![]));
    }
    Ok(vec![Imported { name: String::new(), items }])
}

/// Items as an unencrypted Bitwarden JSON export, for leaving to any other manager.
pub fn to_bitwarden(items: &[&Item]) -> Value {
    let list: Vec<Value> = items
        .iter()
        .map(|i| {
            let fields: Vec<Value> = i
                .sections
                .iter()
                .flat_map(|s| &s.fields)
                .map(|f| json!({"name": f.label, "value": f.value, "type": if f.kind == "concealed" { 1 } else { 0 }}))
                .collect();
            let mut v = json!({"type": if i.kind == "note" { 2 } else { 1 }, "name": i.title, "notes": i.notes, "favorite": i.favorite, "fields": fields});
            if i.kind != "note" {
                v["login"] = json!({"username": i.username, "password": i.password, "totp": i.totp, "uris": i.urls.iter().map(|u| json!({"uri": u, "match": null})).collect::<Vec<_>>()});
            }
            v
        })
        .collect();
    json!({"encrypted": false, "folders": [], "items": list})
}

// ---------- CSV ----------

/// RFC 4180 rows: quoted fields may hold commas, quotes ("") and newlines.
fn csv_rows(text: &str) -> Vec<Vec<String>> {
    let (mut rows, mut row, mut cell) = (Vec::new(), Vec::new(), String::new());
    let mut chars = text.trim_start_matches('\u{feff}').chars().peekable();
    let mut quoted = false;
    while let Some(c) = chars.next() {
        match (quoted, c) {
            (true, '"') if chars.peek() == Some(&'"') => {
                cell.push('"');
                chars.next();
            }
            (true, '"') => quoted = false,
            (true, c) => cell.push(c),
            (false, '"') => quoted = true,
            (false, ',') => row.push(std::mem::take(&mut cell)),
            (false, '\r') => {}
            (false, '\n') => {
                row.push(std::mem::take(&mut cell));
                rows.push(std::mem::take(&mut row));
            }
            (false, c) => cell.push(c),
        }
    }
    if !cell.is_empty() || !row.is_empty() {
        row.push(cell);
        rows.push(row);
    }
    rows.retain(|r| r.iter().any(|c| !c.trim().is_empty()));
    rows
}

/// A CSV export from 1Password, Bitwarden, Chrome, Firefox, Safari or anything
/// with recognizable headers (title/name, username, password, url, notes, totp).
pub fn csv(text: &str) -> Result<Vec<Imported>, ImportError> {
    let rows = csv_rows(text);
    let (header, body) = rows.split_first().ok_or_else(|| err("the file is empty"))?;
    let h: Vec<String> = header.iter().map(|c| c.trim().to_lowercase().replace([' ', '-'], "_")).collect();
    let col = |names: &[&str]| names.iter().find_map(|n| h.iter().position(|c| c == n));
    let title = col(&["title", "name"]);
    let user = col(&["username", "login_username", "user", "login", "email"]);
    let pass = col(&["password", "login_password"]);
    let url = col(&["url", "login_uri", "website", "uri", "origin_url"]);
    let notes = col(&["notes", "note", "extra", "comment"]);
    let totp = col(&["otpauth", "totp", "login_totp", "otp", "otp_auth"]);
    let tags = col(&["tags", "folder", "grouping"]);
    let fav = col(&["favorite", "fav"]);
    if pass.is_none() && notes.is_none() {
        return Err(err("couldn't find a password or notes column in the header"));
    }
    let get = |r: &Vec<String>, i: Option<usize>| i.and_then(|i| r.get(i)).map(|s| s.trim().to_string()).unwrap_or_default();
    let mut items = Vec::new();
    for r in body {
        let url_v = get(r, url);
        let mut it = Item {
            kind: if get(r, pass).is_empty() && get(r, user).is_empty() { "note".into() } else { "login".into() },
            title: get(r, title),
            username: get(r, user),
            password: get(r, pass),
            notes: get(r, notes),
            totp: get(r, totp),
            favorite: matches!(get(r, fav).to_lowercase().as_str(), "1" | "true" | "yes"),
            urls: if url_v.is_empty() { vec![] } else { vec![url_v.clone()] },
            tags: get(r, tags).split([',', ';']).map(str::trim).filter(|t| !t.is_empty()).map(String::from).collect(),
            ..Default::default()
        };
        if it.title.is_empty() {
            it.title = url_v.split("//").nth(1).unwrap_or(&url_v).split('/').next().unwrap_or_default().to_string();
        }
        items.push((it, vec![]));
    }
    Ok(vec![Imported { name: String::new(), items }])
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn csv_formats() {
        let chrome = "name,url,username,password,note\nexample.com,https://example.com/login,me@x.com,\"p,a\"\"ss\",\"multi\nline\"\n";
        let v = csv(chrome).unwrap();
        let it = &v[0].items[0].0;
        assert_eq!((it.title.as_str(), it.password.as_str(), it.notes.as_str()), ("example.com", "p,a\"ss", "multi\nline"));
        let op = "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\nGitHub,https://github.com,me,pw,otpauth://totp/x?secret=ABC,true,false,\"dev,work\",\n";
        let it = &csv(op).unwrap()[0].items[0].0;
        assert_eq!((it.totp.as_str(), it.favorite, it.tags.len()), ("otpauth://totp/x?secret=ABC", true, 2));
        let bw = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\nWork,1,login,Jira,,,0,https://jira.example,me,secret,\n";
        let it = &csv(bw).unwrap()[0].items[0].0;
        assert_eq!((it.title.as_str(), it.username.as_str(), it.tags[0].as_str()), ("Jira", "me", "Work"));
        assert!(csv("a,b\n1,2\n").is_err());
    }

    #[test]
    fn bitwarden_json_roundtrip() {
        let json = r#"{"encrypted":false,"folders":[{"id":"f1","name":"Work"}],"items":[
          {"type":1,"name":"GitHub","folderId":"f1","favorite":true,"notes":"n","login":{"username":"me","password":"pw","totp":"JBSWY3DPEHPK3PXP","uris":[{"uri":"https://github.com","match":null}]},
           "fields":[{"name":"recovery","value":"abc","type":1}],"passwordHistory":[{"password":"old","lastUsedDate":"2024-01-01T00:00:00Z"}]},
          {"type":3,"name":"Visa","card":{"cardholderName":"A B","brand":"Visa","number":"4111111111111111","expMonth":"3","expYear":"2030","code":"123"}},
          {"type":2,"name":"Note","notes":"hello","secureNote":{"type":0}}]}"#;
        let v = bitwarden(json.as_bytes()).unwrap();
        let items: Vec<&Item> = v[0].items.iter().map(|(i, _)| i).collect();
        assert_eq!((items[0].password.as_str(), items[0].tags[0].as_str(), items[0].favorite), ("pw", "Work", true));
        assert_eq!(items[0].sections[0].fields[0].kind, "concealed");
        assert_eq!(items[0].password_history[0].password, "old");
        assert_eq!(items[1].field("expiry date"), Some("2030-03"));
        assert_eq!(items[2].kind, "note");
        let back = to_bitwarden(&items);
        assert_eq!(bitwarden(back.to_string().as_bytes()).unwrap()[0].items[0].0.password, "pw");
        assert!(bitwarden(br#"{"encrypted":true}"#).is_err());
    }

    pub fn onepux_fixture() -> Vec<u8> {
        let data = include_str!("../tests/fixtures/export.data");
        let mut buf = std::io::Cursor::new(Vec::new());
        let mut z = zip::ZipWriter::new(&mut buf);
        let o = zip::write::SimpleFileOptions::default();
        z.start_file("export.attributes", o).unwrap();
        z.write_all(br#"{"version":3,"description":"1Password Unencrypted Export","createdAt":1700000000}"#).unwrap();
        z.start_file("files/oakiw7lqbp53fgqrxrk63su2gu__keepassxc.png", o).unwrap();
        z.write_all(b"\x89PNG logo").unwrap();
        z.start_file("export.data", o).unwrap();
        z.write_all(data.as_bytes()).unwrap();
        z.finish().unwrap();
        buf.into_inner()
    }

    /// The fixture is assembled from real 1PUX exports (KeePassXC's and Proton
    /// Pass's importer test data), values unedited.
    #[test]
    fn onepux_fixture_imports() {
        let v = onepux(&onepux_fixture()).unwrap();
        assert_eq!(v.iter().map(|x| x.name.as_str()).collect::<Vec<_>>(), ["Personal", "Shared"]);
        let by = |t: &str| v.iter().flat_map(|x| &x.items).find(|(i, _)| i.title == t).unwrap();
        let (login, _) = by("Login");
        assert_eq!((login.username.as_str(), login.password.as_str()), ("team@keepassxc.org", "password"));
        assert_eq!(login.urls, ["https://keepassxc.org", "https://twitter.com"]);
        assert_eq!(login.totp, "DFDFDEF");
        assert_eq!(login.field("one-time password"), Some("DFDFDEFDEF"), "the second TOTP stays a field");
        assert_eq!(login.field("email"), Some("team@keepassxc.org"));
        assert_eq!(login.tags, ["website"]);
        let (card, _) = by("Credit Card");
        assert_eq!(card.kind, "card");
        assert_eq!((card.field("number"), card.field("expiry date"), card.field("type")), (Some("1234567890"), Some("2022-06"), Some("mc")));
        assert!(card.field("PIN").is_none(), "empty template fields are skipped");
        let (doc, files) = by("KeePassXC Logo");
        assert_eq!((doc.kind.as_str(), files[0].0.as_str()), ("document", "keepassxc.png"));
        assert_eq!(by("Login item with Password only").0.password, "f@LGRHG7BEcByVy--xTV8X4U");
        let (archived, _) = by("Login item archived");
        assert!(archived.archived);
        assert_eq!(archived.password_history.len(), 2);
        assert_eq!(by("Identity").0.kind, "identity");
        assert_eq!(days_to_date(1451649660 / 86400), "2016-01-01");
    }
}
