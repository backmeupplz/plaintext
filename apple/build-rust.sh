#!/bin/sh
# Builds apple/PlaintextFFI.xcframework (iOS, iOS Simulator, macOS universal) from
# the ffi crate, and the Swift bindings in apple/Generated. Run it before opening
# the Xcode project, and again after changing anything in Rust.
# PROFILE=dev builds faster unoptimized libraries for local iteration, and
# TARGETS narrows the slices (CI: "aarch64-apple-ios-sim aarch64-apple-darwin").
set -eu
cd "$(dirname "$0")/.."
profile="${PROFILE:-release}"
dir=$([ "$profile" = dev ] && echo debug || echo "$profile")
targets="${TARGETS:-aarch64-apple-ios aarch64-apple-ios-sim aarch64-apple-darwin x86_64-apple-darwin}"
# Homebrew's Rust has no iOS targets: put rustup's toolchain first when it's around.
if command -v rustup >/dev/null 2>&1; then
  PATH="$(dirname "$(rustup which cargo)"):$PATH"
  rustup target add $targets >/dev/null
fi
cargo=cargo
target_dir="${CARGO_TARGET_DIR:-target}"

export IPHONEOS_DEPLOYMENT_TARGET=17.0 MACOSX_DEPLOYMENT_TARGET=14.0
set --
for t in $targets; do set -- "$@" --target "$t"; done
$cargo build --locked -p plaintext-ffi --lib --profile "$profile" "$@" # all targets in one go, built side by side

out=apple/Generated
rm -rf "$out" apple/PlaintextFFI.xcframework
mkdir -p "$out/headers"
lib() { echo "$target_dir/$1/$dir/libplaintext_ffi.a"; }
$cargo run --locked -q -p uniffi-bindgen-kotlin --bin uniffi-bindgen-swift -- \
  "$(lib ${targets%% *})" "$out" --swift-sources --headers
$cargo run --locked -q -p uniffi-bindgen-kotlin --bin uniffi-bindgen-swift -- \
  "$(lib ${targets%% *})" "$out/headers" --modulemap --module-name plaintext_ffiFFI --modulemap-filename module.modulemap
mv "$out"/*.h "$out/headers/"

# One library per platform: the two Mac architectures are merged into one.
set --
macs=""
for t in $targets; do
  case $t in
    *-apple-darwin) macs="$macs $(lib "$t")" ;;
    *) set -- "$@" -library "$(lib "$t")" -headers "$out/headers" ;;
  esac
done
if [ -n "$macs" ]; then
  mkdir -p "$target_dir/universal-macos"
  lipo -create $macs -output "$target_dir/universal-macos/libplaintext_ffi.a"
  set -- "$@" -library "$target_dir/universal-macos/libplaintext_ffi.a" -headers "$out/headers"
fi
xcodebuild -create-xcframework "$@" -output apple/PlaintextFFI.xcframework >/dev/null
echo "Built apple/PlaintextFFI.xcframework and $out/plaintext_ffi.swift ($profile)"
