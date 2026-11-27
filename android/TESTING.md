# Testing the Android app

## Build

You need the Android SDK (`ANDROID_HOME`, with NDK 28.2.13676358), JDK 17, rustup and `cargo install cargo-ndk --version 4.1.2`. Then, from the repo root:

```sh
android/build.sh                                   # release APK, arm64-v8a + x86_64
ABIS=x86_64 PROFILE=dev TASK=assembleDebug android/build.sh   # quick debug build for the emulator
```

The script builds `plaintext-ffi` with cargo-ndk, generates the Kotlin bindings with UniFFI and runs Gradle. The APKs end up in `android/app/build/outputs/apk/`. A release build is signed only when `android/keystore.properties` exists. The keystore lives in Vaultwarden under "Plaintext: Android release keystore" and never goes into the repo.

## Install

```sh
adb install -r android/app/build/outputs/apk/release/app-release.apk
```

The debug build installs next to it as `com.borodutch.plaintext.debug`. Debug builds allow screenshots. Release builds set FLAG_SECURE, so the app shows up black in screenshots, recordings and the recents view.

## A local server

```sh
PLAINTEXT_ADDR=127.0.0.1:7982 PLAINTEXT_DB=/tmp/pt.db PLAINTEXT_SETUP_CODE=setup cargo run -p plaintext-server
```

The emulator reaches it at `http://10.0.2.2:7982`. The app allows plain http only for local and private addresses, and it says so on screen. Create the first account with the setup code. Use the CLI (`PLAINTEXT_HOME=/tmp/bob PLAINTEXT_KEYCHAIN=file plaintext signup …`) for the people you share with.

## What to check

- **First run:** pick a server, create an account, save the Emergency Kit as a PDF (or print it), then turn on fingerprint unlock. Sign in on a second device by typing the Secret Key, or by scanning the code from Settings → your account → Add a device.
- **Unlock:** one fingerprint opens every account. "Use password" is the fallback. Enrolling a new fingerprint asks for the password once. The app locks when the screen turns off, after the idle time set in Settings → Security, and right away if Auto-lock is set to Immediately.
- **Items:** search, favorites, the vault picker and swipe actions. On an item: reveal, copy (the copy is marked sensitive and cleared after the set time, and on lock), large type, the one-time code countdown and attachments. Add and edit every kind, with the generator.
- **Sharing:** share a vault, verify someone by comparing fingerprints or scanning their code, send an item to someone's inbox, or create a share link.
- **Inbox, Agents, Watchtower, Import** (1PUX, Bitwarden JSON, CSV), plus several accounts on one or more servers.

AutoFill and passkeys aren't in this version.

## Emulator tips

`adb emu finger touch 1` acts as a fingerprint once one is enrolled (Settings → Security → Fingerprint). Biometric unlock needs a screen lock PIN.
