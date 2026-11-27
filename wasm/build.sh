#!/bin/sh
# Rebuild the browser core into docs/s/ (the share-link viewer). CI runs this and
# fails if the committed files differ, so every tool version is pinned here.
#
# The committed build comes from linux/amd64, like CI: Cargo mixes the host
# triple into symbol hashes, so other hosts produce different (equally valid)
# bytes. Elsewhere this script reruns itself in a linux/amd64 container.
set -eu

RUST=1.99.1
BINDGEN=0.2.130 # same as the wasm-bindgen crate in wasm/Cargo.toml
BINARYEN=133

root=$(cd "$(dirname "$0")/.." && pwd)

if [ "$(uname -s)-$(uname -m)" != Linux-x86_64 ]; then
  mkdir -p "$root/target/linux-amd64"
  exec docker run --rm --platform linux/amd64 -v "$root:/src" -w /src \
    -v "$root/target/linux-amd64:/src/target" -v plaintext-wasm-cargo:/usr/local/cargo/registry \
    "rust:$RUST-slim-bookworm@sha256:f2c004e3d2d8b547e8cf7ffbc29205385f4e71d23e53e4e383065db5e9f822cd" sh -c 'command -v curl >/dev/null || { apt-get update -qq && apt-get install -qq -y curl; } >/dev/null; wasm/build.sh'
fi

tools="$root/target/wasm-tools"
out="$root/docs/s"
mkdir -p "$tools"

fetch() { # url sha256 -> unpacked into $tools
  f="$tools/$(basename "$1")"
  curl -fsSL -o "$f" "$1"
  echo "$2  $f" | sha256sum -c - >/dev/null || { echo "checksum mismatch: $1" >&2; exit 1; }
  tar -xzf "$f" -C "$tools" && rm "$f"
}
bindgen="$tools/wasm-bindgen-$BINDGEN-x86_64-unknown-linux-musl/wasm-bindgen"
wasm_opt="$tools/binaryen-version_$BINARYEN/bin/wasm-opt"
[ -x "$bindgen" ] || fetch "https://github.com/wasm-bindgen/wasm-bindgen/releases/download/$BINDGEN/wasm-bindgen-$BINDGEN-x86_64-unknown-linux-musl.tar.gz" \
  9687f3bb551b9f66f37ed32a40d7913a00f7962db653054e56857bc306c3227f
[ -x "$wasm_opt" ] || fetch "https://github.com/WebAssembly/binaryen/releases/download/version_$BINARYEN/binaryen-version_$BINARYEN-x86_64-linux.tar.gz" \
  2dc9c7813f5375db93d96ead4b78222fcc3e2677bbb832297af4797782a37489

rustup toolchain install "$RUST" --profile minimal --target wasm32-unknown-unknown >/dev/null 2>&1 ||
  rustup target add --toolchain "$RUST" wasm32-unknown-unknown

# No local paths in the binary.
cargo_home=${CARGO_HOME:-$HOME/.cargo}
RUSTC=$(rustup which --toolchain "$RUST" rustc) \
RUSTFLAGS="--remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$root=/src" \
  "$(rustup which --toolchain "$RUST" cargo)" build --locked -p plaintext-wasm --profile wasm --target wasm32-unknown-unknown

"$bindgen" --target web --no-typescript --out-dir "$out" "$root/target/wasm32-unknown-unknown/wasm/plaintext_wasm.wasm"
"$wasm_opt" -Oz --strip-debug --strip-producers "$out/plaintext_wasm_bg.wasm" -o "$out/plaintext_wasm_bg.wasm"
sha256sum "$out/plaintext_wasm_bg.wasm"
wc -c <"$out/plaintext_wasm_bg.wasm"
