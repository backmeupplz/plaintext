#!/bin/sh
# Fill and save, end to end, in Chrome and Firefox, against a fresh local server.
#   npm ci --prefix extension/test/browsers
#   CHROME_PATH=... FIREFOX_PATH=... extension/test/browsers/run.sh [shots dir]
# Needs extension/dist (wasm/build.sh extension && python3 extension/package.py).
# Uses ports 8080 (server), 8090 and 8091 (test sites).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
shots=${1:-$here/shots}
tmp=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$tmp"' EXIT
(cd "$root" && cargo build -q -p plaintext-server)
node "$here/site.mjs" 8090 8091 >"$tmp/site.log" 2>&1 &
server=
# A fresh server and demo account; its Secret Key goes to $tmp/sk.
seed() {
  if [ -n "$server" ]; then kill "$server"; wait "$server" 2>/dev/null || true; fi
  rm -f "$tmp"/pt.db*
  PLAINTEXT_ADDR=127.0.0.1:8080 PLAINTEXT_DB="$tmp/pt.db" "$root/target/debug/plaintext-server" >"$tmp/server.log" 2>&1 &
  server=$!
  sleep 1
  (cd "$root" && PLAINTEXT_SEED=http://localhost:8080 cargo test -q -p plaintext-wasm --test extension seed -- --ignored --nocapture 2>/dev/null) >"$tmp/seed"
  sed -n 's/^secret key //p' "$tmp/seed" >"$tmp/sk"
  # A second account with its own password, for unlocking accounts one at a time.
  BOB_SK=$(sed -n 's/^bob secret key //p' "$tmp/seed")
  export BOB_SK
}
pw='correct horse battery staple'
seed
node "$here/chrome.mjs" chrome "$root/extension/dist/chrome" http://localhost:8080 "$(cat "$tmp/sk")" "$pw" "$shots/chrome"
seed
node "$here/firefox.mjs" "$(ls "$root"/extension/dist/plaintext-firefox-*.xpi | head -1)" http://localhost:8080 "$(cat "$tmp/sk")" "$pw" "$shots/firefox"
