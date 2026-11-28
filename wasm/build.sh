#!/bin/sh
# Rebuild the browser core:
#   wasm/build.sh            into docs/s/, the share-link viewer. CI runs this and
#                            fails if the committed files differ, so every tool
#                            version is pinned here.
#   wasm/build.sh extension  into extension/pkg/, the browser extension's core
#                            (with the `extension` feature; built, not committed).
#
# The committed build is linux/amd64's: Cargo mixes the host triple into symbol
# hashes, so other hosts produce different (equally valid) bytes. Apple-silicon
# Macs (CI's runners) give Cargo a rustc that names linux/amd64 as its host,
# which yields the same bytes; other hosts rerun this in a linux/amd64 container.
set -eu

RUST=1.99.1
BINDGEN=0.2.130 # same as the wasm-bindgen crate in wasm/Cargo.toml
BINARYEN=133

root=$(cd "$(dirname "$0")/.." && pwd)
mode=${1:-viewer}
case $mode in
viewer) out="$root/docs/s" features=--no-default-features ;;
extension) out="$root/extension/pkg" features= ;;
*) echo "usage: wasm/build.sh [extension]" >&2 && exit 2 ;;
esac

host="$(uname -s)-$(uname -m)"
case $host in
Linux-x86_64) bindgen_os=x86_64-unknown-linux-musl bindgen_sha=9687f3bb551b9f66f37ed32a40d7913a00f7962db653054e56857bc306c3227f
  binaryen_os=x86_64-linux binaryen_sha=2dc9c7813f5375db93d96ead4b78222fcc3e2677bbb832297af4797782a37489 ;;
Darwin-arm64) bindgen_os=aarch64-apple-darwin bindgen_sha=b90ddb9357f584b1af897d58ad77e4cce2b48fc17e2a967bc249a87f72809444
  binaryen_os=arm64-macos binaryen_sha=ad66da82ac13f163e424b1643f16c6dfcccc98b5966296b43e52d3cab04f84a8 ;;
esac
if [ -z "${bindgen_os:-}" ]; then
  mkdir -p "$root/target/linux-amd64"
  exec docker run --rm --platform linux/amd64 -v "$root:/src" -w /src \
    -v "$root/target/linux-amd64:/src/target" -v plaintext-wasm-cargo:/usr/local/cargo/registry \
    "rust:$RUST-slim-bookworm@sha256:f2c004e3d2d8b547e8cf7ffbc29205385f4e71d23e53e4e383065db5e9f822cd" sh -c 'command -v curl >/dev/null || { apt-get update -qq && apt-get install -qq -y curl; } >/dev/null; wasm/build.sh "$0"' "$mode"
fi

tools="$root/target/wasm-tools"
mkdir -p "$tools" "$out"

fetch() { # url sha256 -> unpacked into $tools
  f="$tools/$(basename "$1")"
  curl -fsSL -o "$f" "$1"
  echo "$2  $f" | sha256sum -c - >/dev/null || { echo "checksum mismatch: $1" >&2; exit 1; }
  tar -xzf "$f" -C "$tools" && rm "$f"
}
bindgen="$tools/wasm-bindgen-$BINDGEN-$bindgen_os/wasm-bindgen"
wasm_opt="$tools/binaryen-$BINARYEN-$binaryen_os/bin/wasm-opt"
[ -x "$bindgen" ] || fetch "https://github.com/wasm-bindgen/wasm-bindgen/releases/download/$BINDGEN/wasm-bindgen-$BINDGEN-$bindgen_os.tar.gz" "$bindgen_sha"
[ -x "$wasm_opt" ] || { fetch "https://github.com/WebAssembly/binaryen/releases/download/version_$BINARYEN/binaryen-version_$BINARYEN-$binaryen_os.tar.gz" "$binaryen_sha" &&
  mv "$tools/binaryen-version_$BINARYEN" "$tools/binaryen-$BINARYEN-$binaryen_os"; }

rustup toolchain install "$RUST" --profile minimal --target wasm32-unknown-unknown >/dev/null 2>&1 ||
  rustup target add --toolchain "$RUST" wasm32-unknown-unknown

rustc=$(rustup which --toolchain "$RUST" rustc)
if [ "$host" != Linux-x86_64 ]; then
  printf '#!/bin/sh\nif [ "$1" = -vV ]; then "%s" -vV | sed "s/^host: .*/host: x86_64-unknown-linux-gnu/"; exit; fi\nexec "%s" "$@"\n' "$rustc" "$rustc" >"$tools/rustc"
  chmod +x "$tools/rustc" && rustc="$tools/rustc"
fi

# No local paths in the binary.
cargo_home=${CARGO_HOME:-$HOME/.cargo}
RUSTC=$rustc \
RUSTFLAGS="--remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$root=/src" \
  "$(rustup which --toolchain "$RUST" cargo)" build --locked -p plaintext-wasm $features --profile wasm --target wasm32-unknown-unknown

"$bindgen" --target web --no-typescript --out-dir "$out" "$root/target/wasm32-unknown-unknown/wasm/plaintext_wasm.wasm"
"$wasm_opt" -Oz --strip-debug --strip-producers "$out/plaintext_wasm_bg.wasm" -o "$out/plaintext_wasm_bg.wasm"
sha256sum "$out/plaintext_wasm_bg.wasm"
wc -c <"$out/plaintext_wasm_bg.wasm"
