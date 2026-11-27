//! `plaintext`: the command line for people and agents, and an MCP server.

mod mcp;
mod state;

use std::io::{Read, Write};

use clap::{Parser, Subcommand};
use plaintext_client::plaintext_core::api::{Hex, Kind, Role};
use plaintext_client::plaintext_core::item::{Field, Item, Section};
use plaintext_client::plaintext_core::tools::{self, Recipe};
use plaintext_client::plaintext_core::{Content, new_item_id};
use plaintext_client::{Http, Session, import, now, now_ms};
use state::{Config, Res, S};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "plaintext", version, about = "End-to-end encrypted password manager. Your server only ever sees ciphertext.")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create an account on a server (the first account becomes its admin)
    Signup {
        #[arg(long)]
        server: String,
        #[arg(long)]
        username: String,
        /// Invite code from an admin (not needed for the first account)
        #[arg(long)]
        invite: Option<String>,
    },
    /// Sign in on this computer
    Signin {
        #[arg(long)]
        server: Option<String>,
        #[arg(long)]
        username: Option<String>,
    },
    /// Forget the unlocked session (the Secret Key stays in the keychain)
    Lock,
    /// Who you're signed in as, and your fingerprint
    Whoami,
    /// List items, optionally matching a search
    Ls {
        query: Option<String>,
        #[arg(long)]
        vault: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Show an item, or one field of it
    Get {
        item: String,
        #[arg(long)]
        field: Option<String>,
        #[arg(long)]
        vault: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Print one secret reference: pt://Vault/Item/field
    Read { reference: String },
    /// Add an item
    Add {
        title: String,
        #[command(flatten)]
        fields: Fields,
        #[arg(long)]
        vault: Option<String>,
    },
    /// Change an item (only the flags you pass)
    Edit {
        item: String,
        #[arg(long)]
        title: Option<String>,
        #[command(flatten)]
        fields: Fields,
        #[arg(long)]
        vault: Option<String>,
    },
    /// Delete an item
    Rm {
        item: String,
        #[arg(long)]
        vault: Option<String>,
    },
    /// Make a password
    Generate {
        #[arg(long, default_value_t = 20)]
        length: u32,
        #[arg(long)]
        no_symbols: bool,
        /// Memorable: this many words
        #[arg(long)]
        words: Option<u32>,
        /// Digits only, this long
        #[arg(long)]
        pin: Option<u32>,
    },
    /// The current one-time code for an item
    Totp { item: String },
    /// Weak, reused and unsecured passwords; --breaches also checks Have I Been Pwned
    Watchtower {
        #[arg(long)]
        breaches: bool,
    },
    #[command(subcommand)]
    Vault(VaultCmd),
    #[command(subcommand)]
    User(UserCmd),
    #[command(subcommand)]
    Agent(AgentCmd),
    /// Send an item to someone's inbox, sealed to their key
    Send {
        item: String,
        #[arg(long)]
        to: String,
        /// e.g. 7d, 12h
        #[arg(long)]
        expires: Option<String>,
    },
    /// Make a link anyone can open (no account needed)
    Link {
        item: String,
        #[arg(long, default_value = "7d")]
        expires: String,
        #[arg(long)]
        views: Option<u32>,
    },
    /// Your inbox: shared items and agents' access requests
    Inbox {
        /// Save this message's item into a vault
        #[arg(long)]
        save: Option<String>,
        #[arg(long)]
        vault: Option<String>,
        #[arg(long)]
        delete: Option<String>,
    },
    /// Ask a human for access (for agents)
    Request {
        text: String,
        #[arg(long)]
        to: String,
    },
    /// Run a command with pt:// references in its environment replaced by secrets
    Run {
        /// Also load variables from this file (KEY=value lines)
        #[arg(long)]
        env_file: Option<String>,
        #[arg(trailing_var_arg = true, required = true)]
        cmd: Vec<String>,
    },
    /// Replace {{ pt://Vault/Item/field }} in a template (stdin to stdout by default)
    Inject {
        #[arg(short, long)]
        input: Option<String>,
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Attach a file to an item
    Attach { item: String, file: String },
    /// Save an item's attachment
    Download {
        item: String,
        name: String,
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Import from 1Password (.1pux), Bitwarden (.json) or CSV
    Import {
        #[arg(value_parser = ["1pux", "bitwarden", "csv"])]
        format: String,
        file: String,
        #[arg(long)]
        vault: Option<String>,
    },
    /// Export a vault as an unencrypted Bitwarden JSON file (handle with care)
    Export {
        #[arg(long)]
        vault: Option<String>,
    },
    /// Change your password
    Passwd,
    /// Devices signed in to your account
    Sessions {
        #[arg(long)]
        end: Option<String>,
    },
    /// Open a share link (https://getplaintext.org/s/#…) and show the item
    Open { link: String },
    /// Serve the Model Context Protocol on stdio, for AI agents
    Mcp,
}

#[derive(clap::Args, Default)]
struct Fields {
    #[arg(long)]
    kind: Option<String>,
    #[arg(long)]
    username: Option<String>,
    #[arg(long)]
    password: Option<String>,
    /// Generate a strong password
    #[arg(long)]
    generate: bool,
    #[arg(long)]
    url: Vec<String>,
    #[arg(long)]
    notes: Option<String>,
    /// otpauth:// URI or base32 secret
    #[arg(long)]
    totp: Option<String>,
    #[arg(long)]
    tag: Vec<String>,
    /// label=value
    #[arg(long)]
    field: Vec<String>,
    /// label=value, hidden by default
    #[arg(long)]
    concealed: Vec<String>,
}

#[derive(Subcommand)]
enum VaultCmd {
    /// Your vaults
    Ls,
    Create { name: String },
    Rename { vault: String, name: String },
    /// Who has access, with fingerprints
    Members { vault: String },
    /// Give someone access: --role reader|writer|owner, --expires 30d
    Share {
        vault: String,
        user: String,
        #[arg(long, default_value = "writer")]
        role: String,
        #[arg(long)]
        expires: Option<String>,
    },
    /// Remove someone and replace the vault key
    Revoke { vault: String, user: String },
    /// Who read or wrote what (owners)
    Audit { vault: String },
}

#[derive(Subcommand)]
enum UserCmd {
    /// Everyone on this server
    Ls,
    /// An invite code for someone new (admins)
    Invite,
    /// Show a user's fingerprint; with --yes, mark it verified after comparing
    Verify {
        user: String,
        #[arg(long)]
        yes: bool,
    },
    /// Stop an account (admins, or the owner of an agent)
    Disable { user: String },
}

#[derive(Subcommand)]
enum AgentCmd {
    /// Create an agent; optionally give it access to a vault right away
    Create {
        name: String,
        #[arg(long)]
        vault: Option<String>,
        #[arg(long, default_value = "reader")]
        role: String,
        #[arg(long)]
        expires: Option<String>,
    },
}

fn main() {
    if let Err(e) = run(Cli::parse()) {
        eprintln!("plaintext: {e}");
        std::process::exit(1);
    }
}

pub fn duration(s: &str) -> Res<u64> {
    let (n, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: u64 = n.parse().map_err(|_| format!("bad duration {s}; use e.g. 30m, 12h, 7d"))?;
    Ok(n * match unit {
        "m" => 60,
        "h" | "" => 3600,
        "d" => 86400,
        "w" => 7 * 86400,
        _ => return Err(format!("bad duration {s}; use e.g. 30m, 12h, 7d").into()),
    })
}

fn role(s: &str) -> Res<Role> {
    Ok(serde_json::from_value(serde_json::Value::String(s.into())).map_err(|_| "role is reader, writer or owner")?)
}

fn password_twice() -> Res<Zeroizing<String>> {
    let a = Zeroizing::new(rpassword::prompt_password("New password: ")?);
    let b = Zeroizing::new(rpassword::prompt_password("Again: ")?);
    if *a != *b {
        return Err("the passwords don't match".into());
    }
    if tools::strength_bits(&a) < 50.0 {
        eprintln!("That password is on the weak side. Your Secret Key still protects you if the server is breached, but not if someone steals this device.");
    }
    Ok(a)
}

fn vault_opt(s: &S, v: &Option<String>) -> Res<Option<Hex>> {
    Ok(v.as_deref().map(|v| s.vault(v)).transpose()?)
}

fn apply_fields(item: &mut Item, f: &Fields) -> Res<()> {
    if let Some(k) = &f.kind {
        item.kind = k.clone();
    }
    if let Some(u) = &f.username {
        item.username = u.clone();
    }
    if let Some(p) = &f.password {
        item.password = p.clone();
    }
    if f.generate {
        item.password = tools::generate(&Recipe::default());
    }
    if !f.url.is_empty() {
        item.urls = f.url.clone();
    }
    if let Some(n) = &f.notes {
        item.notes = n.clone();
    }
    if let Some(t) = &f.totp {
        item.totp = t.clone();
    }
    if !f.tag.is_empty() {
        item.tags = f.tag.clone();
    }
    for (list, kind) in [(&f.field, "text"), (&f.concealed, "concealed")] {
        for kv in list {
            let (label, value) = kv.split_once('=').ok_or("fields are label=value")?;
            let fields = &mut item.sections.iter_mut().find(|s| s.title.is_empty()).map(|s| &mut s.fields);
            let field = Field { label: label.into(), kind: kind.into(), value: value.into(), ..Default::default() };
            match fields {
                Some(fs) => {
                    fs.retain(|x| x.label != label);
                    fs.push(field);
                }
                None => item.sections.push(Section { title: String::new(), fields: vec![field] }),
            }
        }
    }
    Ok(())
}

fn show(item: &Item, vault: &str) {
    println!("{}  ({}, in {vault})", item.title, if item.kind.is_empty() { "item" } else { &item.kind });
    let row = |k: &str, v: &str| {
        if !v.is_empty() {
            println!("  {k:<12} {v}");
        }
    };
    row("username", &item.username);
    row("password", &item.password);
    for u in &item.urls {
        row("url", u);
    }
    if let Some((code, left)) = tools::totp(&item.totp, now()) {
        row("one-time", &format!("{code} ({left}s)"));
    }
    for s in &item.sections {
        if !s.title.is_empty() {
            println!("  [{}]", s.title);
        }
        for f in &s.fields {
            row(&f.label, &f.value);
        }
    }
    row("tags", &item.tags.join(", "));
    for f in &item.files {
        row("file", &format!("{} ({} bytes)", f.name, f.size));
    }
    if !item.passkeys.is_empty() {
        row("passkeys", &item.passkeys.iter().map(|p| p.rp_id.as_str()).collect::<Vec<_>>().join(", "));
    }
    row("notes", &item.notes);
}

/// Resolve `pt://Vault/Item/field` (item by title or id; field by label).
pub fn resolve(s: &S, reference: &str) -> Res<String> {
    let rest = reference.strip_prefix("pt://").ok_or("references look like pt://Vault/Item/field")?;
    // Vault names have no slash; the field is the last segment; titles may contain '/'.
    let (vault, rest) = rest.split_once('/').ok_or("references look like pt://Vault/Item/field")?;
    let (item, field) = rest.rsplit_once('/').ok_or("references look like pt://Vault/Item/field")?;
    let vid = s.vault(vault)?;
    let (_, _, it) = s.one(item, Some(&vid))?;
    if field.eq_ignore_ascii_case("totp") || field.eq_ignore_ascii_case("otp") {
        return Ok(tools::totp(&it.totp, now()).ok_or("no one-time code on that item")?.0);
    }
    Ok(it.field(field).filter(|v| !v.is_empty()).ok_or(format!("no field {field} on {item}"))?.to_string())
}

fn run(cli: Cli) -> Res<()> {
    match cli.cmd {
        Cmd::Signup { server, username, invite } => {
            let pw = password_twice()?;
            let cfg = Config { server: server.trim_end_matches('/').into(), username: username.clone() };
            let (sk, s) = Session::signup(Http::new(&cfg.server), &username, &pw, invite.as_deref(), &state::device())?;
            state::save_config(&cfg)?;
            state::save_secret_key(&cfg, &sk)?;
            state::remember(&cfg, &s)?;
            println!("Welcome, {username}.{}\n", if s.admin { " You're this server's admin." } else { "" });
            println!("Your Secret Key: {}\n", sk.encode());
            println!("Write it down with your server address ({}) and keep it somewhere safe.", cfg.server);
            println!("You need it with your password to sign in on a new device, and nobody can recover it for you.");
            println!("It's saved in this computer's keychain.\nYour fingerprint: {}", s.me().fingerprint());
        }
        Cmd::Signin { server, username } => {
            let old = state::load_config().ok();
            let cfg = Config {
                server: server.or(old.as_ref().map(|c| c.server.clone())).ok_or("--server is needed the first time")?,
                username: username.or(old.map(|c| c.username)).ok_or("--username is needed the first time")?,
            };
            state::save_config(&cfg)?;
            let s = state::sign_in(&cfg)?;
            println!("Signed in as {} until you run `plaintext lock` (or 12 hours pass).", s.username());
        }
        Cmd::Lock => {
            state::forget(&state::load_config()?);
            println!("Locked.");
        }
        Cmd::Whoami => {
            let s = state::open()?;
            println!("{}{}  fingerprint {}", s.username(), if s.admin { " (admin)" } else { "" }, s.me().fingerprint());
        }
        Cmd::Ls { query, vault, json } => {
            let s = state::open()?;
            let v = vault_opt(&s, &vault)?;
            let mut rows: Vec<(Hex, Hex, &Item)> = match &query {
                Some(q) => s.find(q, v.as_ref()),
                None => s.vaults.iter().filter(|(id, _)| v.is_none_or(|w| w == **id)).flat_map(|(vid, vl)| vl.items().map(move |(i, it)| (*vid, *i, it))).collect(),
            };
            rows.sort_by_key(|(_, _, i)| i.title.to_lowercase());
            if json {
                let out: Vec<_> = rows
                    .iter()
                    .map(|(vid, id, i)| serde_json::json!({"id": id, "vault": s.vaults[vid].meta.name, "title": i.title, "kind": i.kind, "username": i.username, "urls": i.urls}))
                    .collect();
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                for (vid, id, i) in rows {
                    println!("{}  {:<32} {:<24} {}", &id.to_string()[..8], i.title, i.username, s.vaults[&vid].meta.name);
                }
            }
        }
        Cmd::Get { item, field, vault, json } => {
            let s = state::open()?;
            let (vid, _, it) = s.one(&item, vault_opt(&s, &vault)?.as_ref())?;
            match (field, json) {
                (Some(f), _) => println!("{}", resolve(&s, &format!("pt://{}/{}/{f}", vid, it.title))?),
                (None, true) => println!("{}", serde_json::to_string_pretty(&it)?),
                (None, false) => show(&it, &s.vaults[&vid].meta.name),
            }
        }
        Cmd::Read { reference } => println!("{}", resolve(&state::open()?, &reference)?),
        Cmd::Add { title, fields, vault } => {
            let mut s = state::open()?;
            let vid = match vault_opt(&s, &vault)? {
                Some(v) => v,
                None => s.default_vault()?,
            };
            let mut item = Item { kind: "login".into(), title, created: now_ms(), updated: now_ms(), ..Default::default() };
            apply_fields(&mut item, &fields)?;
            let id = new_item_id();
            s.put_item(&vid, id, item)?;
            state::save(&s)?;
            println!("Added {} to {}.", &id.to_string()[..8], s.vaults[&vid].meta.name);
        }
        Cmd::Edit { item, title, fields, vault } => {
            let mut s = state::open()?;
            let (vid, id, old) = s.one(&item, vault_opt(&s, &vault)?.as_ref())?;
            let mut next = old.clone();
            next.history.clear();
            if let Some(t) = title {
                next.title = t;
            }
            apply_fields(&mut next, &fields)?;
            let mut it = old;
            it.edit(next, now_ms());
            s.put_item(&vid, id, it)?;
            state::save(&s)?;
            println!("Saved.");
        }
        Cmd::Rm { item, vault } => {
            let mut s = state::open()?;
            let (vid, id, it) = s.one(&item, vault_opt(&s, &vault)?.as_ref())?;
            s.delete_item(&vid, id)?;
            state::save(&s)?;
            println!("Deleted {}.", it.title);
        }
        Cmd::Generate { length, no_symbols, words, pin } => {
            let r = match (words, pin) {
                (Some(w), _) => Recipe::Memorable { words: w, separator: "-".into(), capitalize: false },
                (_, Some(p)) => Recipe::Pin { length: p },
                _ => Recipe::Random { length, digits: true, symbols: !no_symbols },
            };
            println!("{}", tools::generate(&r));
        }
        Cmd::Totp { item } => {
            let s = state::open()?;
            let (_, _, it) = s.one(&item, None)?;
            let (code, left) = tools::totp(&it.totp, now()).ok_or("no one-time code on that item")?;
            println!("{code}  ({left}s left)");
        }
        Cmd::Watchtower { breaches } => {
            let s = state::open()?;
            let all: Vec<(Hex, Hex, &Item)> = s.vaults.iter().flat_map(|(v, vl)| vl.items().map(move |(i, it)| (*v, *i, it))).collect();
            let found = tools::watchtower(all.iter().map(|(_, i, it)| (*i, *it)));
            for (vid, id, it) in &all {
                let mut f: Vec<String> = found.get(id).map(|f| f.iter().map(|x| format!("{x:?}").to_lowercase()).collect()).unwrap_or_default();
                if breaches && !it.password.is_empty() {
                    let (prefix, suffix) = tools::breach_prefix(&it.password);
                    let (_, body) = plaintext_client::Transport::send(&Http::new("https://api.pwnedpasswords.com"), "GET", &format!("/range/{prefix}"), None, None)?;
                    let n = tools::breach_count(&String::from_utf8_lossy(&body), &suffix);
                    if n > 0 {
                        f.insert(0, format!("breached ({n} times)"));
                    }
                }
                if !f.is_empty() {
                    println!("{:<32} {:<12} {}", it.title, s.vaults[vid].meta.name, f.join(", ").replace("notwofactor", "no 2FA code saved"));
                }
            }
        }
        Cmd::Vault(v) => vault_cmd(v)?,
        Cmd::User(u) => user_cmd(u)?,
        Cmd::Agent(AgentCmd::Create { name, vault, role: r, expires }) => {
            let mut s = state::open()?;
            let key = s.create_agent(&name)?;
            if let Some(v) = vault {
                let vid = s.vault(&v)?;
                let exp = expires.as_deref().map(duration).transpose()?.map(|d| now() + d);
                s.share_vault(&vid, &name, role(&r)?, exp)?;
                println!("{name} can now {} {v}{}.", if role(&r)? == Role::Reader { "read" } else { "use" }, if exp.is_some() { " until it expires" } else { "" });
            }
            println!("\nAgent key (shown once; store it in the agent's secret store):\n{}\n", key.encode());
            println!("Use it with:\n  PLAINTEXT_SERVER={} PLAINTEXT_AGENT_KEY=ptk_… plaintext run -- your-command", state::load_config()?.server);
        }
        Cmd::Send { item, to, expires } => {
            let mut s = state::open()?;
            let (_, _, it) = s.one(&item, None)?;
            let exp = expires.as_deref().map(duration).transpose()?.map(|d| now() + d);
            s.send(&to, &Content::Item(Box::new(it.clone())), exp)?;
            println!("Sent {} to {to}. {to}'s fingerprint: {}", it.title, s.fingerprint(&to).unwrap_or_default());
        }
        Cmd::Link { item, expires, views } => {
            let s = state::open()?;
            let (_, _, it) = s.one(&item, None)?;
            let cfg = state::load_config()?;
            println!("{}", s.create_link(&cfg.server, &it, now() + duration(&expires)?, views)?);
            if !it.files.is_empty() || !it.passkeys.is_empty() {
                eprintln!("Attachments and passkeys aren't included in share links.");
            }
        }
        Cmd::Inbox { save, vault, delete } => {
            let mut s = state::open()?;
            let inbox = s.inbox()?;
            for (from, r) in &inbox {
                match r {
                    Ok((m, Content::Item(it))) => {
                        let id = m.id.to_string();
                        if save.as_deref().is_some_and(|x| id.starts_with(x)) {
                            let vid = match vault_opt(&s, &vault)? {
                                Some(v) => v,
                                None => s.default_vault()?,
                            };
                            s.put_item(&vid, new_item_id(), (**it).clone())?;
                            s.delete_message(&m.id)?;
                            println!("Saved {} from {from}.", it.title);
                        } else {
                            println!("{}  item     from {from:<16} {}", &id[..8], it.title);
                        }
                    }
                    Ok((m, Content::Request(text))) => println!("{}  request  from {from:<16} {text}", &m.id.to_string()[..8]),
                    Err(e) => println!("?         unreadable from {from}: {e}"),
                }
                if let (Some(d), Ok((m, _))) = (&delete, r)
                    && m.id.to_string().starts_with(d.as_str())
                {
                    s.delete_message(&m.id)?;
                    println!("Deleted.");
                }
            }
            state::save(&s)?;
        }
        Cmd::Request { text, to } => {
            let mut s = state::open()?;
            s.send(&to, &Content::Request(text), Some(now() + 7 * 86400))?;
            println!("Asked {to}.");
        }
        Cmd::Run { env_file, cmd } => {
            let s = state::open()?;
            let mut vars: Vec<(String, String)> = std::env::vars().collect();
            if let Some(f) = env_file {
                for line in std::fs::read_to_string(f)?.lines() {
                    if let Some((k, v)) = line.split_once('=').filter(|_| !line.trim_start().starts_with('#')) {
                        vars.push((k.trim().into(), v.trim().trim_matches('"').into()));
                    }
                }
            }
            let mut c = std::process::Command::new(&cmd[0]);
            c.args(&cmd[1..]);
            for (k, v) in vars {
                if v.starts_with("pt://") {
                    c.env(k, resolve(&s, &v)?);
                } else {
                    c.env(k, v);
                }
            }
            c.env_remove("PLAINTEXT_AGENT_KEY");
            std::process::exit(c.status()?.code().unwrap_or(1));
        }
        Cmd::Inject { input, output } => {
            let s = state::open()?;
            let mut tpl = String::new();
            match input {
                Some(f) => tpl = std::fs::read_to_string(f)?,
                None => {
                    std::io::stdin().read_to_string(&mut tpl)?;
                }
            }
            let mut out = String::new();
            let mut rest = tpl.as_str();
            while let Some(start) = rest.find("{{") {
                let end = rest[start..].find("}}").ok_or("unclosed {{")? + start;
                out.push_str(&rest[..start]);
                out.push_str(&resolve(&s, rest[start + 2..end].trim())?);
                rest = &rest[end + 2..];
            }
            out.push_str(rest);
            match output {
                Some(f) => {
                    #[cfg(unix)]
                    use std::os::unix::fs::OpenOptionsExt;
                    let mut o = std::fs::OpenOptions::new();
                    o.write(true).create(true).truncate(true);
                    #[cfg(unix)]
                    o.mode(0o600);
                    o.open(f)?.write_all(out.as_bytes())?;
                }
                None => std::io::stdout().write_all(out.as_bytes())?,
            }
        }
        Cmd::Attach { item, file } => {
            let mut s = state::open()?;
            let (vid, id, mut it) = s.one(&item, None)?;
            let data = std::fs::read(&file)?;
            let name = std::path::Path::new(&file).file_name().and_then(|n| n.to_str()).unwrap_or("file").to_string();
            let f = s.upload_file(&vid, &name, &data)?;
            it.files.push(f);
            s.put_item(&vid, id, it)?;
            state::save(&s)?;
            println!("Attached {name}.");
        }
        Cmd::Download { item, name, output } => {
            let s = state::open()?;
            let (vid, _, it) = s.one(&item, None)?;
            let f = it.files.iter().find(|f| f.name == name).ok_or("no attachment with that name")?;
            std::fs::write(output.unwrap_or(name.clone()), s.download_file(&vid, f)?)?;
            println!("Saved {name}.");
        }
        Cmd::Import { format, file, vault } => {
            let mut s = state::open()?;
            let data = std::fs::read(&file)?;
            let imported = match format.as_str() {
                "1pux" => import::onepux(&data)?,
                "bitwarden" => import::bitwarden(&data)?,
                _ => import::csv(&String::from_utf8_lossy(&data))?,
            };
            let n = imported.iter().map(|v| v.items.len()).sum::<usize>();
            for v in imported {
                let vid = match (&vault, v.name.is_empty()) {
                    (Some(name), _) => s.vault(name)?,
                    (None, true) => s.default_vault()?,
                    (None, false) if v.name.eq_ignore_ascii_case("personal") => s.default_vault()?,
                    (None, false) => match s.own_vault(&v.name) {
                        Some(id) => id,
                        None => s.create_vault(&v.name)?,
                    },
                };
                for (it, files) in v.items {
                    let mut it = it;
                    for (name, bytes) in files {
                        it.files.push(s.upload_file(&vid, &name, &bytes)?);
                    }
                    s.vaults.get_mut(&vid).ok_or("vault vanished")?.put(new_item_id(), it);
                }
                s.sync_vault(&vid)?;
            }
            state::save(&s)?;
            println!("Imported {n} items. Delete {file} now: it holds your passwords unencrypted.");
        }
        Cmd::Export { vault } => {
            let s = state::open()?;
            let v = vault_opt(&s, &vault)?;
            let items: Vec<&Item> = s.vaults.iter().filter(|(id, _)| v.is_none_or(|w| w == **id)).flat_map(|(_, vl)| vl.items().map(|(_, i)| i)).collect();
            println!("{}", serde_json::to_string_pretty(&import::to_bitwarden(&items))?);
        }
        Cmd::Passwd => {
            let s = state::open()?;
            let cfg = state::load_config()?;
            let sk = state::secret_key(&cfg)?;
            let old = Zeroizing::new(rpassword::prompt_password("Current password: ")?);
            let new = password_twice()?;
            s.change_password(&plaintext_client::plaintext_core::crypto::derive(&old, &sk), &sk, &new)?;
            state::forget(&cfg);
            println!("Password changed. Other devices need to sign in again.");
        }
        Cmd::Sessions { end } => {
            let s = state::open()?;
            if let Some(id) = end {
                s.end_session(&id)?;
                println!("Signed that device out.");
            }
            for d in s.sessions()? {
                println!("{}  {:<32} {}", d.id, d.device, if d.current { "(this one)" } else { "" });
            }
        }
        Cmd::Open { link } => {
            let frag = link.split_once('#').map(|(_, f)| f).ok_or("that's not a Plaintext share link")?;
            let (server_and_id, key) = frag.rsplit_once('/').ok_or("that's not a Plaintext share link")?;
            let (server, id) = server_and_id.rsplit_once('/').ok_or("that's not a Plaintext share link")?;
            let item = plaintext_client::open_link(&Http::new(server), &id.parse()?, key)?;
            show(&item, "a share link");
        }
        Cmd::Mcp => mcp::serve()?,
    }
    Ok(())
}

fn vault_cmd(v: VaultCmd) -> Res<()> {
    let mut s = state::open()?;
    match v {
        VaultCmd::Ls => {
            let me = s.username().to_string();
            for (id, vl) in &s.vaults {
                let role = vl.role(&me, now()).map(|r| format!("{r:?}").to_lowercase()).unwrap_or_default();
                let members = vl.roster.as_ref().map_or(0, |r| r.members.len());
                println!("{}  {:<24} {:<7} {} items, {} members", &id.to_string()[..8], vl.meta.name, role, vl.items().count(), members);
            }
        }
        VaultCmd::Create { name } => {
            s.create_vault(&name)?;
            println!("Created {name}.");
        }
        VaultCmd::Rename { vault, name } => {
            let id = s.vault(&vault)?;
            let mut meta = s.vaults[&id].meta.clone();
            meta.name = name;
            s.rename_vault(&id, meta)?;
            println!("Renamed.");
        }
        VaultCmd::Members { vault } => {
            let id = s.vault(&vault)?;
            for m in s.vaults[&id].roster.as_ref().map(|r| r.members.clone()).unwrap_or_default() {
                let verified = m.username == s.username() || s.keyring.contacts.get(&m.username).is_some_and(|c| c.verified);
                let exp = m.expires.map(|e| format!(" until {}", e)).unwrap_or_default();
                println!(
                    "{:<20} {:<7}{exp}  {}  {}",
                    m.username,
                    format!("{:?}", m.role).to_lowercase(),
                    s.fingerprint(&m.username).unwrap_or_default(),
                    if verified { "verified" } else { "not verified" }
                );
            }
        }
        VaultCmd::Share { vault, user, role: r, expires } => {
            let id = s.vault(&vault)?;
            let exp = expires.as_deref().map(duration).transpose()?.map(|d| now() + d);
            s.share_vault(&id, &user, role(&r)?, exp)?;
            let verified = s.keyring.contacts.get(&user).is_some_and(|c| c.verified);
            println!("Shared {vault} with {user} as {r}.");
            if !verified {
                println!("{user} isn't verified yet. Compare this fingerprint with them: {}", s.fingerprint(&user).unwrap_or_default());
                println!("then run `plaintext user verify {user} --yes`.");
            }
        }
        VaultCmd::Revoke { vault, user } => {
            let id = s.vault(&vault)?;
            s.revoke(&id, &user)?;
            println!("Removed {user} and replaced the vault key.");
        }
        VaultCmd::Audit { vault } => {
            let id = s.vault(&vault)?;
            for e in s.audit(&id)? {
                let t = e.ts as i64;
                let date = plaintext_client::import::days_to_date(t.div_euclid(86400));
                println!("{date} {:02}:{:02} UTC  {:<20} {}", t.rem_euclid(86400) / 3600, t.rem_euclid(3600) / 60, e.username, e.action);
            }
        }
    }
    state::save(&s)
}

fn user_cmd(u: UserCmd) -> Res<()> {
    let mut s = state::open()?;
    match u {
        UserCmd::Ls => {
            for u in s.users()? {
                let id: plaintext_client::plaintext_core::api::Identity = serde_json::from_slice(&u.identity.body.0)?;
                let tag = match (id.kind, &id.owner) {
                    (Kind::Agent, Some(o)) => format!("agent of {o}"),
                    _ if u.admin => "admin".into(),
                    _ => String::new(),
                };
                let verified = s.keyring.contacts.get(&id.username).is_some_and(|c| c.verified);
                println!("{:<20} {:<16} {}{}", id.username, tag, if verified { "verified" } else { "" }, if u.disabled { " disabled" } else { "" });
            }
        }
        UserCmd::Invite => {
            let code = s.invite()?;
            let cfg = state::load_config()?;
            println!("Send this to the person you're inviting (valid 7 days, one use):\n");
            println!("  plaintext signup --server {} --username THEIR_NAME --invite {code}\n", cfg.server);
            println!("When they join, your devices verify their keys automatically.");
        }
        UserCmd::Verify { user, yes } => {
            if !s.keyring.contacts.contains_key(&user) {
                s.pin_user(&user)?;
            }
            println!("{user}: {}", s.fingerprint(&user).unwrap_or_default());
            if yes {
                s.mark_verified(&user)?;
                println!("Marked verified.");
            } else {
                println!("Compare this with {user}'s `plaintext whoami`; if it matches, run again with --yes.");
            }
        }
        UserCmd::Disable { user } => {
            s.disable_user(&user)?;
            println!("Disabled {user}: they can't sign in any more.");
            println!("They still know the keys of vaults they were in; run `plaintext vault revoke VAULT {user}` to replace those keys.");
        }
    }
    Ok(())
}
