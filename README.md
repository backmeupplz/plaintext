# Plaintext

A self-hosted password manager for a server you don't trust. Every item is encrypted on your devices with a key derived from your password and a 128-bit Secret Key that never leaves them, so a stolen database, a curious admin or a compromised host sees only ciphertext and can't brute-force your password offline. Vaults can be shared with family, teammates and AI agents, with roles, expiry and an audit log, and the server can't swap anyone's keys to read along. Vault keys and shared items are sealed with X25519 and ML-KEM-768 together, so what the server stores stays sealed against a future quantum computer.

Site: https://getplaintext.org. Status: the protocol, server, command line and MCP server work and are tested end to end; the iPhone, Mac, Android and browser apps are being built. Read [DESIGN.md](DESIGN.md) for the threat model and protocol, [UI.md](UI.md) for how the apps look and behave, and [PARITY.md](PARITY.md) for coverage of 1Password's features.

## Run the server

```sh
docker run -d --name plaintext -v plaintext:/data -p 127.0.0.1:8080:8080 \
  -e PLAINTEXT_URL=https://vault.example.com \
  -e PLAINTEXT_SETUP_CODE=a-long-random-string ghcr.io/backmeupplz/plaintext-server
```

The image (amd64 and arm64) holds only the static server binary, and `docker build -t plaintext .` builds an image from source instead. Each [release](https://github.com/backmeupplz/plaintext/releases/latest) also has `plaintext-server` binaries for Linux (static) and macOS, which read the same settings as the image.

Put it behind HTTPS at any address you like (your own domain, a LAN address or a Tailscale name) and set `PLAINTEXT_URL` to that address. The port above only listens on the machine itself, so drop the `127.0.0.1:` if your proxy runs somewhere else. The first account to sign up becomes the admin; everyone after that needs an invite from an admin (`plaintext user invite`). Settings, all optional except `PLAINTEXT_URL` on anything but your own machine:

| Variable | |
|---|---|
| `PLAINTEXT_SETUP_CODE` | On a server reachable from the internet, set it to a random string without dots so nobody can sign up before you, and pass it as `--invite` when you create the first account. |
| `PLAINTEXT_URL` | The address clients use, such as `https://vault.example.com` (comma-separate several). Logins are signed for the server's address, and the server refuses logins signed for any other. Without it, only `localhost` can sign in. An `https://` address also makes every response send `Strict-Transport-Security`. |
| `PLAINTEXT_SIGNUP=open` | Anyone can sign up without an invite, for running a hosted service. People are then found by exact username, nobody but admins can list everyone, and each address gets at most 10 signups and 30 failed logins an hour. Needs `PLAINTEXT_SETUP_CODE` too. |
| `PLAINTEXT_TRUST_PROXY=1` | The server sits behind one reverse proxy that sets `X-Forwarded-For`, so rate limits count the address the proxy saw rather than the proxy's own. Leave it unset if clients can reach the server directly, or they could pick their own address. |
| `PLAINTEXT_QUOTA_MB` | How much each account may store: items and attachments in the vaults it created (with each vault's current roster and manifest), and the share links and messages it and its agents sent. Writes past it are refused, while reading, deleting and removing people from vaults keep working; a deleted item's attachments are freed about a week later. Unset means unlimited. |
| `PLAINTEXT_ADDR`, `PLAINTEXT_DB` | Listen address (`0.0.0.0:8080`) and database path (`plaintext.db`, or `/data/plaintext.db` in the image). |

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
curl -fsSL https://getplaintext.org/install | sh   # macOS and Linux, or: brew install backmeupplz/tap/plaintext
plaintext signup --server https://vault.example.com --username alice
plaintext add GitHub --username alice --generate --url https://github.com
plaintext get github
plaintext vault create Family && plaintext vault share Family bob --role writer
plaintext import 1pux ~/Downloads/export.1pux    # also: bitwarden, csv
```

You can have accounts on several servers, such as your family's and a work one. Each `signup` or `signin` adds an account and makes it the default. `plaintext account ls` lists them, `plaintext account use NAME` switches, and `--account alice@vault.example.com` (or `PLAINTEXT_ACCOUNT`) picks one for a single command. `plaintext account delete` deletes the account from its server for good, after asking for your password and username; vaults you share stay with the others.

Windows builds are on the releases page, and `cargo install --locked --path cli` builds it from source. Your Secret Key and unlocked session live in the OS keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service). On machines without a keychain, `PLAINTEXT_KEYCHAIN=file` keeps them in 0600 files instead.

- **Per terminal.** Unlocking lasts 12 hours, and on macOS and Linux only in the terminal you unlocked in, like `sudo`. A command with no terminal, such as a script, a background job, or anything an AI tool runs, can't use it and should use an agent key. On Windows the session is shared by all of your user's programs for now.
- **Locking.** `plaintext lock` ends the session on the server too (except a security key's, which stays with the key).
- **Security keys.** On a computer that's already signed in, `plaintext key add NAME` sets up the FIDO2 security key plugged in, such as a YubiKey. The key needs a FIDO2 PIN, so a touch alone never unlocks (on a key with a fingerprint reader, an enrolled finger does); for a YubiKey, `ykman fido access change-pin` sets one. Adding asks for your password once, the PIN and three touches. After that, `plaintext unlock` (or any command) in a new terminal asks for the key's PIN and a touch instead of your password. `plaintext key ls` lists the keys and `plaintext key remove NAME` removes one. Losing a key costs nothing, because your password still unlocks, and a new device still needs your password and Secret Key. This works in the macOS build and in Linux builds from source, which need libudev (`libudev-dev` on Debian and Ubuntu; Arch already has it). The static Linux release and Windows can't use security keys yet. On Linux your user needs access to `/dev/hidraw*`: systemd gives it to whoever is logged in at the computer, and `libfido2` (on Arch) adds udev rules for other setups.
- **Secrets stay out of arguments.** `--password`, `--totp` and `--concealed LABEL` (without `=value`) ask for the secret, or, when stdin is piped, read one line each in that order. An empty answer to `--totp` removes the one-time code. Other users of the computer can see arguments. `plaintext` refuses plain `http://` except on your own machine and private networks.

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

`plaintext mcp` is a Model Context Protocol server for AI agents, and it runs only with an agent key (`PLAINTEXT_SERVER` and `PLAINTEXT_AGENT_KEY`), never with your own session. It can search items and read their non-secret fields (passwords, hidden fields, keys, card numbers and notes come back as `pt://` references), run commands with secrets injected (scrubbed from the output), save new logins with generated passwords, and ask the owner for access. It doesn't hand secret values to the model unless `PLAINTEXT_MCP_REVEAL=1`, which keeps them out of transcripts by accident; a model that runs commands can still reach anything in the vaults its agent account can read, so give agents only the vaults they need. Every agent read is in the vault's audit log (`plaintext vault audit Infra`). To add it to Claude Code:

```sh
claude mcp add plaintext -e PLAINTEXT_SERVER=https://vault.example.com -e PLAINTEXT_AGENT_KEY=ptk_… -- plaintext mcp
```

Claude Desktop (`claude_desktop_config.json`) and Cursor (`~/.cursor/mcp.json`) take the same server under `mcpServers`: `{"plaintext": {"command": "plaintext", "args": ["mcp"], "env": {"PLAINTEXT_SERVER": "https://vault.example.com", "PLAINTEXT_AGENT_KEY": "ptk_…"}}}`. Use the full path to `plaintext` if the app doesn't see your shell's PATH.

## Develop

```sh
cargo test                      # core, client end-to-end over HTTP, importers
python3 tools/kat.py            # independent check of the crypto vectors (argon2-cffi, cryptography, pynacl)
wasm/build.sh                   # rebuild the browser core into docs/s/ (CI checks it matches)
```

The share-link viewer at `getplaintext.org/s/` is `docs/s/`: a static page that decrypts with the core compiled to WebAssembly. `wasm/build.sh` builds on linux/amd64 like CI (in Docker elsewhere), so the committed `.wasm` matches byte for byte.

Releases: bump `version` in Cargo.toml (and Cargo.lock with it), merge, wait until the merge commit shows on github.com (the release job needs the tag on the GitHub mirror, and a push right after the merge can be rejected), then publish the release with `tea release create --repo backmeupplz/plaintext --tag vX.Y.Z --title vX.Y.Z`. `.forgejo/workflows/release.yml` builds every platform, attaches the files with SHA256SUMS and its signature to that release and to the GitHub one, updates the Homebrew tap and pushes the image to GHCR. The signature is an SSH signature by the release key, whose private half is the repo secret `RELEASE_SIGNING_KEY` and whose public half is `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN/TcFdPnP6bWhdxrnNt1Ef2hEAmCgB+kRyGWOmpZqQC` (the `key=` line in `docs/install`, which the installer, the Homebrew job and the Docker job all check it against).
