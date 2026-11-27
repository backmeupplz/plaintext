#!/bin/sh
# Builds apple/PlaintextFFI.xcframework (iOS, iOS Simulator, macOS universal) from
# the ffi crate, and the Swift bindings in apple/Generated. Run it before opening
# the Xcode project, and again after changing anything in Rust.
# PROFILE=dev builds faster unoptimized libraries for local iteration.
set -eu
cd "$(dirname "$0")/.."
profile="${PROFILE:-release}"
dir=$([ "$profile" = dev ] && echo debug || echo "$profile")
targets="aarch64-apple-ios aarch64-apple-ios-sim aarch64-apple-darwin x86_64-apple-darwin"
# Homebrew's Rust has no iOS targets: put rustup's toolchain first when it's around.
if command -v rustup >/dev/null 2>&1; then
  PATH="$(dirname "$(rustup which cargo)"):$PATH"
  rustup target add $targets >/dev/null
fi
cargo=cargo
target_dir="${CARGO_TARGET_DIR:-target}"

export IPHONEOS_DEPLOYMENT_TARGET=17.0 MACOSX_DEPLOYMENT_TARGET=14.0
for t in $targets; do
  $cargo build --locked -p plaintext-ffi --lib --profile "$profile" --target "$t"
done

out=apple/Generated
rm -rf "$out" apple/PlaintextFFI.xcframework
mkdir -p "$out/headers"
lib() { echo "$target_dir/$1/$dir/libplaintext_ffi.a"; }
$cargo run --locked -q -p plaintext-ffi --features bindgen --bin uniffi-bindgen-swift -- \
  "$(lib aarch64-apple-darwin)" "$out" --swift-sources --headers
$cargo run --locked -q -p plaintext-ffi --features bindgen --bin uniffi-bindgen-swift -- \
  "$(lib aarch64-apple-darwin)" "$out/headers" --modulemap --xcframework --modulemap-filename module.modulemap
mv "$out"/*.h "$out/headers/"

mkdir -p "$target_dir/universal-macos"
lipo -create "$(lib aarch64-apple-darwin)" "$(lib x86_64-apple-darwin)" -output "$target_dir/universal-macos/libplaintext_ffi.a"
xcodebuild -create-xcframework \
  -library "$(lib aarch64-apple-ios)" -headers "$out/headers" \
  -library "$(lib aarch64-apple-ios-sim)" -headers "$out/headers" \
  -library "$target_dir/universal-macos/libplaintext_ffi.a" -headers "$out/headers" \
  -output apple/PlaintextFFI.xcframework >/dev/null
echo "Built apple/PlaintextFFI.xcframework and $out/plaintext_ffi.swift ($profile)"
