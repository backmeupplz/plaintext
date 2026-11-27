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

fn hide(item: &Item, vault: &str) -> Value {
    let reference = |f: &str| format!("pt://{vault}/{}/{f}", item.title);
    let mut fields = vec![];
    for s in &item.sections {
        for f in &s.fields {
            let v = if f.kind == "concealed" { json!({"secret": reference(&f.label)}) } else { json!(f.value) };
            fields.push(json!({"label": f.label, "value": v}));
        }
    }
    json!({
        "title": item.title, "kind": item.kind, "vault": vault, "username": item.username, "urls": item.urls,
        "password": (!item.password.is_empty()).then(|| reference("password")),
        "one_time_code": (!item.totp.is_empty()).then(|| reference("totp")),
        "fields": fields, "tags": item.tags, "notes": item.notes,
        "files": item.files.iter().map(|f| &f.name).collect::<Vec<_>>(),
    })
}

fn call(s: &mut S, name: &str, a: &Value) -> Res<String> {
    s.sync()?;
    let vault = arg(a, "vault").map(|v| s.vault(v)).transpose()?;
    Ok(match name {
        "list_vaults" => {
            let me = s.username().to_string();
            let v: Vec<Value> = s
                .vaults
                .values()
                .map(|v| json!({"name": v.meta.name, "role": v.role(&me, now()), "items": v.items().count()}))
                .collect();
            serde_json::to_string_pretty(&v)?
        }
        "search_items" => {
            let hits: Vec<Value> = match arg(a, "query") {
                Some(q) => s.find(q, vault.as_ref()).into_iter().map(|(v, _, i)| json!({"title": i.title, "vault": s.vaults[&v].meta.name, "username": i.username, "urls": i.urls, "kind": i.kind})).collect(),
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
                secrets.push(v.clone());
                c.env(k, v);
            }
            let out = c.output()?;
            let mut text = format!("exit code {}\n{}{}", out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
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
