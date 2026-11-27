# Plaintext

A self-hosted password manager for a server you don't trust. Every item is encrypted on your devices with a key derived from your password and a 128-bit Secret Key that never leaves them, so a stolen database, a curious admin or a compromised host sees only ciphertext and can't brute-force your password offline. The server is one small Rust binary on SQLite.

Status: the core crypto library and the server work and are tested end to end; the apps and extensions come next. Read [DESIGN.md](DESIGN.md) for the threat model, key hierarchy and protocol.

## Run the server

```sh
docker build -t plaintext .
docker run -v plaintext:/data -p 8080:8080 plaintext
```

The first account can sign up freely. Set `PLAINTEXT_INVITE=<code>` to let more people join with that code. Put it behind HTTPS.

## Develop

```sh
cargo test                      # core unit tests + two-device end-to-end test
python3 tools/kat.py            # independent check of the key-derivation vectors (needs argon2-cffi, cryptography)
```
