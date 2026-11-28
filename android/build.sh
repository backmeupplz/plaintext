#!/bin/sh
# Builds the Rust FFI for Android (cargo-ndk), generates its Kotlin bindings, then the APK.
#   android/build.sh                 release APK (R8), signed when android/keystore.properties exists
#   TASK=assembleDebug android/build.sh
#   ABIS="x86_64" android/build.sh   fewer ABIs (default: arm64-v8a x86_64)
#   PROFILE=dev android/build.sh     unoptimized Rust, for quick local iteration
# Needs: rustup, cargo-ndk (`cargo install cargo-ndk`), an Android SDK with the NDK (ANDROID_HOME, or
# ANDROID_NDK_HOME), and JDK 17+.
set -eu
cd "$(dirname "$0")/.."
abis="${ABIS:-arm64-v8a x86_64}"
profile="${PROFILE:-release}"
gen=android/app/build/generated
PATH="$HOME/.cargo/bin:$PATH"
# Homebrew's Rust has no Android targets: put rustup's toolchain first.
if command -v rustup >/dev/null 2>&1; then
  PATH="$(dirname "$(rustup which cargo)"):$PATH"
  for a in $abis; do
    case $a in
      arm64-v8a) rustup target add aarch64-linux-android >/dev/null ;;
      x86_64) rustup target add x86_64-linux-android >/dev/null ;;
      *) echo "unsupported ABI $a" >&2; exit 1 ;;
    esac
  done
fi
if [ -z "${ANDROID_NDK_HOME:-}" ] && [ -n "${ANDROID_HOME:-}" ] && [ -d "$ANDROID_HOME/ndk" ]; then
  ANDROID_NDK_HOME="$ANDROID_HOME/ndk/$(ls "$ANDROID_HOME/ndk" | sort -V | tail -1)"
  export ANDROID_NDK_HOME
fi

rm -rf "$gen/jniLibs" "$gen/uniffi"
set --
for a in $abis; do set -- "$@" -t "$a"; done
cargo ndk "$@" -P 29 -o "$gen/jniLibs" build --locked -p plaintext-ffi --lib --profile "$profile"


cargo run --locked -q -p uniffi-bindgen-kotlin -- generate --language kotlin --no-format --out-dir "$gen/uniffi" src:plaintext_ffi

cd android
./gradlew --quiet "${TASK:-assembleRelease}"
find app/build/outputs/apk -name '*.apk' | sed 's/^/Built android\//'
