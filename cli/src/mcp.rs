//! `plaintext mcp`: a Model Context Protocol server on stdio.
//!
//! Safe by default: the model can search, read non-secret fields, and run commands
//! with secrets injected as environment variables (scrubbed from the output), but
//! it never sees a secret unless `PLAINTEXT_MCP_REVEAL=1` is set. What it can reach
//! at all is decided by the agent account's vault access, enforced by keys.

use std::io::{BufRead, Write};

use plaintext_client::plaintext_core::Content;
use plaintext_client::plaintext_core::item::Item;
use plaintext_client::plaintext_core::tools::{self, Recipe};
use plaintext_client::plaintext_core::new_item_id as new_id;
use plaintext_client::{now, now_ms};
use serde_json::{Value, json};

use crate::state::{self, Res, S};

fn reveal() -> bool {
    std::env::var("PLAINTEXT_MCP_REVEAL").is_ok_and(|v| v == "1")
}

fn tools_list() -> Value {
    let mut tools = vec![
        json!({"name": "list_vaults", "description": "Vaults this account can use, with its role in each.", "inputSchema": {"type": "object", "properties": {}}}),
        json!({"name": "search_items", "description": "Find items by title, username, URL or tag. Returns no secrets.",
            "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}, "vault": {"type": "string"}}}}),
        json!({"name": "get_item", "description": "An item's fields with secret values hidden. Use the returned pt:// references with run_with_secrets.",
            "inputSchema": {"type": "object", "properties": {"item": {"type": "string"}, "vault": {"type": "string"}}, "required": ["item"]}}),
        json!({"name": "run_with_secrets", "description": "Run a command (argv, no shell) with environment variables set from pt://Vault/Item/field references. Secret values are scrubbed from the output, so you can use credentials without ever seeing them.",
            "inputSchema": {"type": "object", "properties": {
                "command": {"type": "array", "items": {"type": "string"}},
                "env": {"type": "object", "additionalProperties": {"type": "string"}, "description": "VAR → pt://Vault/Item/field"},
                "cwd": {"type": "string"}}, "required": ["command", "env"]}}),
        json!({"name": "generate_password", "description": "A strong random password (or memorable words).",
            "inputSchema": {"type": "object", "properties": {"length": {"type": "integer"}, "words": {"type": "integer"}}}}),
        json!({"name": "create_item", "description": "Save a new login (for example, an account you just created). Set generate=true to have a strong password made and stored without you seeing it; it's returned as a pt:// reference.",
            "inputSchema": {"type": "object", "properties": {
                "title": {"type": "string"}, "username": {"type": "string"}, "password": {"type": "string"}, "generate": {"type": "boolean"},
                "url": {"type": "string"}, "notes": {"type": "string"}, "vault": {"type": "string"}}, "required": ["title"]}}),
        json!({"name": "request_access", "description": "Ask a human (usually your owner) for access to something you can't reach. They see it in their Plaintext inbox.",
            "inputSchema": {"type": "object", "properties": {"to": {"type": "string"}, "text": {"type": "string"}}, "required": ["to", "text"]}}),
    ];
    if reveal() {
        tools.push(json!({"name": "read_secret", "description": "The value of one pt://Vault/Item/field reference (one-time codes too: field totp).",
            "inputSchema": {"type": "object", "properties": {"reference": {"type": "string"}}, "required": ["reference"]}}));
    }
    json!({ "tools": tools })
}

fn arg<'a>(a: &'a Value, k: &str) -> Option<&'a str> {
    a.get(k).and_then(Value::as_str)
}

use plaintext_client::plaintext_core::item::SECRET_KINDS;

fn hide(item: &Item, vault: &str) -> Value {
    let reference = |f: &str| format!("pt://{vault}/{}/{f}", item.title);
    let mut fields = vec![];
    for s in &item.sections {
        for f in &s.fields {
            let v = if SECRET_KINDS.contains(&f.kind.as_str()) { json!({"secret": reference(&f.label)}) } else { json!(f.value) };
            fields.push(json!({"label": f.label, "value": v}));
        }
    }
    // Notes hold recovery codes, keys and the like as often as not, and are the
    // whole secret of a secure note: a reference too.
    json!({
        "title": item.title, "kind": item.kind, "vault": vault, "username": item.username, "urls": item.urls,
        "password": (!item.password.is_empty()).then(|| reference("password")),
        "one_time_code": (!item.totp.is_empty()).then(|| reference("totp")),
        "fields": fields, "tags": item.tags,
        "notes": (!item.notes.is_empty()).then(|| reference("notes")),
        "files": item.files.iter().map(|f| &f.name).collect::<Vec<_>>(),
    })
}

/// A secret as it may appear in a command's output: as is, base64-encoded (as in
/// an HTTP Basic header, alone or as `username:secret`), or percent-encoded.
fn spellings(secret: &str, username: &str) -> Vec<String> {
    use base64::Engine;
    let e = base64::engine::general_purpose::STANDARD;
    let u = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut out = vec![secret.to_string()];
    for raw in [secret.to_string(), format!("{username}:{secret}")] {
        out.push(e.encode(&raw));
        out.push(e.encode(&raw).trim_end_matches('=').to_string());
        out.push(u.encode(&raw));
    }
    let pct: String = secret.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect();
    out.push(pct);
    out
}

fn call(s: &mut S, name: &str, a: &Value) -> Res<String> {
    // A change held back (a full account, a race) waits, as in the CLI; the rest still work.
    match s.sync() {
        Err(e) if e.held_back() => {}
        r => r?,
    }
    let vault = arg(a, "vault").map(|v| s.vault(v)).transpose()?;
    Ok(match name {
        "list_vaults" => {
            let me = s.username().to_string();
            let v: Vec<Value> = s
                .vaults
                .values()
                .map(|v| json!({"name": v.meta.name, "role": v.role(&me, now()), "items": v.items().count()}))
                .collect();
            let mut out = serde_json::to_string_pretty(&v)?;
            for p in &s.problems {
                out.push_str(&format!("\nwarning: {}", crate::clean(p)));
            }
            out
        }
        "search_items" => {
            let hits: Vec<Value> = match arg(a, "query") {
                // Only on what the model may see: searching notes or secret fields would
                // let it learn them a character at a time.
                Some(q) => s
                    .vaults
                    .iter()
                    .filter(|(id, _)| vault.is_none_or(|w| w == **id))
                    .flat_map(|(_, v)| v.items().filter(|(_, i)| i.matches_shown(q)).map(move |(_, i)| json!({"title": i.title, "vault": v.meta.name, "username": i.username, "urls": i.urls, "kind": i.kind})))
                    .collect(),
                None => s
                    .vaults
                    .iter()
                    .filter(|(id, _)| vault.is_none_or(|w| w == **id))
                    .flat_map(|(_, v)| v.items().map(move |(_, i)| json!({"title": i.title, "vault": v.meta.name, "username": i.username, "urls": i.urls, "kind": i.kind})))
                    .collect(),
            };
            serde_json::to_string_pretty(&hits)?
        }
        "get_item" => {
            // (secret values come back as pt:// references; see `hide`)
            let (vid, _, it) = s.one(arg(a, "item").ok_or("item is required")?, vault.as_ref())?;
            serde_json::to_string_pretty(&hide(&it, &s.vaults[&vid].meta.name))?
        }
        "read_secret" if reveal() => crate::resolve(s, arg(a, "reference").ok_or("reference is required")?)?,
        "run_with_secrets" => {
            let argv: Vec<String> = serde_json::from_value(a.get("command").cloned().unwrap_or_default())?;
            let env: std::collections::BTreeMap<String, String> = serde_json::from_value(a.get("env").cloned().unwrap_or_default())?;
            let (prog, rest) = argv.split_first().ok_or("command is empty")?;
            let mut c = std::process::Command::new(prog);
            c.args(rest).env_remove("PLAINTEXT_AGENT_KEY").stdin(std::process::Stdio::null());
            if let Some(d) = arg(a, "cwd") {
                c.current_dir(d);
            }
            let mut secrets = Vec::new();
            for (k, r) in env {
                let v = crate::resolve(s, &r)?;
                let username = crate::resolve(s, &format!("{}/username", r.rsplit_once('/').map_or(r.as_str(), |(item, _)| item))).unwrap_or_default();
                secrets.extend(spellings(&v, &username));
                c.env(k, v);
            }
            let out = c.output()?;
            let mut text = format!("exit code {}\n{}{}", out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
            // Longest first, so a secret inside a longer encoded form doesn't break the match.
            secrets.sort_by_key(|v| std::cmp::Reverse(v.len()));
            for v in secrets.iter().filter(|v| v.len() >= 4) {
                text = text.replace(v.as_str(), "[secret]");
            }
            text.chars().take(20_000).collect()
        }
        "generate_password" => match a.get("words").and_then(Value::as_u64) {
            Some(w) => tools::generate(&Recipe::Memorable { words: w as u32, separator: "-".into(), capitalize: false }),
            None => tools::generate(&Recipe::Random { length: a.get("length").and_then(Value::as_u64).unwrap_or(20) as u32, digits: true, symbols: true }),
        },
        "create_item" => {
            let vid = match vault {
                Some(v) => v,
                None => s.default_vault()?,
            };
            let generated = a.get("generate").and_then(Value::as_bool).unwrap_or(false);
            let item = Item {
                kind: "login".into(),
                title: arg(a, "title").ok_or("title is required")?.into(),
                username: arg(a, "username").unwrap_or_default().into(),
                password: if generated { tools::generate(&Recipe::default()) } else { arg(a, "password").unwrap_or_default().into() },
                urls: arg(a, "url").map(|u| vec![u.to_string()]).unwrap_or_default(),
                notes: arg(a, "notes").unwrap_or_default().into(),
                created: now_ms(),
                updated: now_ms(),
                ..Default::default()
            };
            let reference = format!("pt://{}/{}/password", s.vaults[&vid].meta.name, item.title);
            s.put_item(&vid, new_id(), item)?;
            state::save(s)?;
            format!("Saved. The password is available as {reference}")
        }
        "request_access" => {
            let to = arg(a, "to").ok_or("to is required")?;
            s.send(to, &Content::Request(arg(a, "text").ok_or("text is required")?.into()), Some(now() + 7 * 86400))?;
            format!("Asked {to}. They'll see it in their Plaintext inbox.")
        }
        _ => return Err(format!("unknown tool {name}").into()),
    })
}

pub fn serve() -> Res<()> {
    // Only ever as an agent: a person's own session would hand the model every
    // vault they have, so it isn't offered here (it's tied to a terminal anyway).
    if std::env::var("PLAINTEXT_AGENT_KEY").is_err() {
        return Err("plaintext mcp runs as an agent: set PLAINTEXT_SERVER and PLAINTEXT_AGENT_KEY (make a key with `plaintext agent create NAME --vault VAULT`)".into());
    }
    let mut s = state::open()?;
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let Ok(req) = serde_json::from_str::<Value>(&line) else { continue };
        let Some(id) = req.get("id").cloned() else { continue }; // notifications need no answer
        let method = req.get("method").and_then(Value::as_str).unwrap_or_default();
        let result = match method {
            "initialize" => json!({
                "protocolVersion": req["params"].get("protocolVersion").cloned().unwrap_or(json!("2025-06-18")),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "plaintext", "version": env!("CARGO_PKG_VERSION")},
                "instructions": "Plaintext password manager. Use run_with_secrets to use credentials without seeing them. If you lack access, use request_access."
            }),
            "ping" => json!({}),
            "tools/list" => tools_list(),
            "tools/call" => {
                let p = &req["params"];
                let name = p.get("name").and_then(Value::as_str).unwrap_or_default();
                match call(&mut s, name, p.get("arguments").unwrap_or(&json!({}))) {
                    Ok(text) => json!({"content": [{"type": "text", "text": text}]}),
                    Err(e) => json!({"content": [{"type": "text", "text": e.to_string()}], "isError": true}),
                }
            }
            _ => {
                writeln!(out, "{}", json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "method not found"}}))?;
                out.flush()?;
                continue;
            }
        };
        writeln!(out, "{}", json!({"jsonrpc": "2.0", "id": id, "result": result}))?;
        out.flush()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn scrubs_encoded_secrets() {
        let curl_v = "> Authorization: Basic YWxpY2U6aHVudGVyMi1pcy1sb25n\n> GET /?token=s3cr%3At HTTP/1.1";
        let mut text = curl_v.to_string();
        let mut all = super::spellings("hunter2-is-long", "alice");
        all.extend(super::spellings("s3cr:t", ""));
        all.sort_by_key(|v| std::cmp::Reverse(v.len()));
        for v in all.iter().filter(|v| v.len() >= 4) {
            text = text.replace(v.as_str(), "[secret]");
        }
        assert!(!text.contains("YWxpY2U6aHVudGVyMi1pcy1sb25n") && !text.contains("s3cr%3At"), "{text}");
    }
}
