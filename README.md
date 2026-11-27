# Plaintext

A self-hosted password manager for a server you don't trust. Every item is encrypted on your devices with a key derived from your password and a 128-bit Secret Key that never leaves them, so a stolen database, a curious admin or a compromised host sees only ciphertext and can't brute-force your password offline. Vaults can be shared with family, teammates and AI agents, with roles, expiry and an audit log, and the server can't swap anyone's keys to read along.

Site: https://getplaintext.org. Status: the protocol, server, command line and MCP server work and are tested end to end; the iPhone, Mac, Android and browser apps are being built. Read [DESIGN.md](DESIGN.md) for the threat model and protocol, [UI.md](UI.md) for how the apps look and behave, and [PARITY.md](PARITY.md) for coverage of 1Password's features.

## Run the server

```sh
docker build -t plaintext .
docker run -d -v plaintext:/data -p 8080:8080 plaintext
```

Put it behind HTTPS. The first account to sign up becomes the admin; everyone after that needs an invite from an admin (`plaintext user invite`). On a server reachable from the internet, set `PLAINTEXT_SETUP_CODE` to a random string so nobody can sign up before you, and pass it as `--invite` when you create the first account.

## The command line

```sh
cargo install --path cli        # installs `plaintext`
plaintext signup --server https://vault.example.com --username alice
plaintext add GitHub --username alice --generate --url https://github.com
plaintext get github
plaintext vault create Family && plaintext vault share Family bob --role writer
plaintext import 1pux ~/Downloads/export.1pux    # also: bitwarden, csv
```

Your Secret Key and unlocked session live in the OS keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service). `plaintext lock` forgets the session. On machines without a keychain, `PLAINTEXT_KEYCHAIN=file` keeps them in 0600 files instead.

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

`plaintext mcp` is a Model Context Protocol server for AI agents. It can search items and read their non-secret fields, run commands with secrets injected (scrubbed from the output), save new logins with generated passwords, and ask the owner for access. It never returns a secret to the model unless `PLAINTEXT_MCP_REVEAL=1`. Every agent read is in the vault's audit log (`plaintext vault audit Infra`).

## Develop

```sh
cargo test                      # core, client end-to-end over HTTP, importers
python3 tools/kat.py            # independent check of the crypto vectors (argon2-cffi, cryptography, pynacl)
```
