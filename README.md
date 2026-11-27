# Plaintext

A self-hosted password manager for a server you don't trust. Every item is encrypted on your devices with a key derived from your password and a 128-bit Secret Key that never leaves them, so a stolen database, a curious admin or a compromised host sees only ciphertext and can't brute-force your password offline. Vaults can be shared with family, teammates and AI agents, with roles, expiry and an audit log, and the server can't swap anyone's keys to read along.

Site: https://getplaintext.org. Status: the protocol, server, command line and MCP server work and are tested end to end; the iPhone, Mac, Android and browser apps are being built. Read [DESIGN.md](DESIGN.md) for the threat model and protocol, [UI.md](UI.md) for how the apps look and behave, and [PARITY.md](PARITY.md) for coverage of 1Password's features.

## Run the server

```sh
docker build -t plaintext .
docker run -d --name plaintext -v plaintext:/data -p 8080:8080 plaintext
```

Put it behind HTTPS at any address you like: your own domain, a LAN address or a Tailscale name. The first account to sign up becomes the admin; everyone after that needs an invite from an admin (`plaintext user invite`). Settings, all optional:

| Variable | |
|---|---|
| `PLAINTEXT_SETUP_CODE` | On a server reachable from the internet, set it to a random string so nobody can sign up before you, and pass it as `--invite` when you create the first account. |
| `PLAINTEXT_URL` | The address clients use, such as `https://vault.example.com` (comma-separate several). Logins are signed for the server's address, and the server refuses logins signed for any other. Set it whenever the server's port is reachable without going through your proxy. |
| `PLAINTEXT_SIGNUP=open` | Anyone can sign up without an invite, for running a hosted service. People are then found by exact username, and nobody but admins can list everyone. |
| `PLAINTEXT_ADDR`, `PLAINTEXT_DB` | Listen address (`0.0.0.0:8080`) and database path (`plaintext.db`). |

Share links open on a static page at getplaintext.org that decrypts in the browser; your server never sees the key. To use your own domain for that too, host a copy of `docs/s/` anywhere except the vault server itself and set `PLAINTEXT_LINK_PAGE=https://your.page/s/`. Keep the trailing `/`, since the page loads its files from next to itself.

### Backups

Back up the `plaintext` volume. Copying a live SQLite database file by file can catch it halfway through a write, so the server also writes a consistent copy of itself to `/data/backup/plaintext.db` when it starts and every hour after that, replacing the previous copy in one step. Every backup of the volume therefore holds a whole database that is at most an hour old, even if the live files in it don't match.

To restore, stop the server first and keep it stopped until the copy is in place, because a running server would overwrite the good copy with one of the restored live files. Put the volume back from your backup, then replace the live database with the copy and delete the live write-ahead log next to it, since SQLite would otherwise replay the old log onto the restored file:

```sh
docker stop plaintext
# restore the plaintext volume from your backup here
docker run --rm -v plaintext:/data busybox sh -c 'rm -f /data/plaintext.db-wal /data/plaintext.db-shm && cp /data/backup/plaintext.db /data/plaintext.db && chown -R 65532:65532 /data'
docker start plaintext
```

## The command line

```sh
cargo install --path cli        # installs `plaintext`
plaintext signup --server https://vault.example.com --username alice
plaintext add GitHub --username alice --generate --url https://github.com
plaintext get github
plaintext vault create Family && plaintext vault share Family bob --role writer
plaintext import 1pux ~/Downloads/export.1pux    # also: bitwarden, csv
```

You can have accounts on several servers, such as your family's and a work one. Each `signup` or `signin` adds an account and makes it the default. `plaintext account ls` lists them, `plaintext account use NAME` switches, and `--account alice@vault.example.com` (or `PLAINTEXT_ACCOUNT`) picks one for a single command.

Your Secret Key and unlocked session live in the OS keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service). On machines without a keychain, `PLAINTEXT_KEYCHAIN=file` keeps them in 0600 files instead.

- **Per terminal.** Unlocking lasts 12 hours, and only in the terminal you unlocked in, like `sudo`. A command with no terminal, such as a script, a background job, or anything an AI tool runs, can't use it and should use an agent key.
- **Locking.** `plaintext lock` ends the session on the server too.
- **Secrets stay out of arguments.** Pass `--password` with no value to be asked (or to read it from stdin), because other users of the computer can see arguments. `plaintext` refuses plain `http://` except on your own machine and private networks.

## Agents

Agents get their own accounts, owned by a person, with access to only the vaults you give them:

```sh
plaintext agent create deploy-bot --vault Infra --role reader --expires 30d   # prints a ptk_… key once
```

On the agent's machine, secrets are used without being printed:

```sh
export PLAINTEXT_SERVER=https://vault.example.com PLAINTEXT_AGENT_KEY=ptk_…
DATABASE_URL="pt://Infra/Prod DB/password" plaintext run -- ./migrate
plaintext inject -i config.tpl -o config.yml       # {{ pt://Infra/Prod DB/password }}
```

`plaintext mcp` is a Model Context Protocol server for AI agents, and it runs only with an agent key (`PLAINTEXT_SERVER` and `PLAINTEXT_AGENT_KEY`), never with your own session. It can search items and read their non-secret fields (passwords, hidden fields, keys, card numbers and notes come back as `pt://` references), run commands with secrets injected (scrubbed from the output), save new logins with generated passwords, and ask the owner for access. It doesn't hand secret values to the model unless `PLAINTEXT_MCP_REVEAL=1`, which keeps them out of transcripts by accident; a model that runs commands can still reach anything in the vaults its agent account can read, so give agents only the vaults they need. Every agent read is in the vault's audit log (`plaintext vault audit Infra`).

## Develop

```sh
cargo test                      # core, client end-to-end over HTTP, importers
python3 tools/kat.py            # independent check of the crypto vectors (argon2-cffi, cryptography, pynacl)
wasm/build.sh                   # rebuild the browser core into docs/s/ (CI checks it matches)
```

The share-link viewer at `getplaintext.org/s/` is `docs/s/`: a static page that decrypts with the core compiled to WebAssembly. `wasm/build.sh` builds on linux/amd64 like CI (in Docker elsewhere), so the committed `.wasm` matches byte for byte.
