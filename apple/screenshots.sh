#!/bin/sh
# Screenshots of every iPhone screen for design review: starts a fresh local
# server, makes "bob" with the CLI (he invites alice, shares a vault and sends
# her an item), then runs the Journey UI test on one simulator, which signs
# alice up in the app, imports the 1PUX fixture, shares a vault with bob,
# creates an agent and visits every screen.
#   apple/screenshots.sh <simulator name> <light|dark> <output dir>
# With MAC=1 bob then signs in on the Mac app (Debug build), which sees what
# alice shared and draws its own windows, light and dark, into the same folder.
# Needs apple/build-rust.sh first. Uses port 7959 and a temporary folder.
set -eu
cd "$(dirname "$0")/.."
sim=$1 theme=$2 out=$3
tmp=$(mktemp -d)
cargo build -q -p plaintext-server -p plaintext-cli
pt() { PLAINTEXT_HOME="$tmp/bob" PLAINTEXT_KEYCHAIN=file target/debug/plaintext "$@"; }

PLAINTEXT_ADDR=127.0.0.1:7959 PLAINTEXT_DB="$tmp/db" PLAINTEXT_SETUP_CODE=setup target/debug/plaintext-server >"$tmp/server.log" 2>&1 &
server=$!
trap 'kill $server ${watcher:-} ${matcher:-} 2>/dev/null; rm -rf "$tmp"' EXIT
sleep 1
url=http://127.0.0.1:7959

# bob, through the CLI's password prompts.
sk=$(PLAINTEXT_HOME="$tmp/bob" PLAINTEXT_KEYCHAIN=file expect -c "
  spawn target/debug/plaintext signup --server $url --username bob --invite setup
  expect \"New password:\"; send \"bob's long password\r\"
  expect \"Again:\"; send \"bob's long password\r\"
  expect eof" | grep -o 'A1-[A-Z0-9-]*' | head -1)
pt vault create Family >/dev/null
pt add "Home Wi-Fi" --kind wifi --vault Family --concealed "Wireless password=sunny-meadow-42" --field "Network name=Meadow" >/dev/null
pt add Netflix --vault Family --username family@example.com --generate --url https://netflix.com >/dev/null
pt add "Family email" --vault Family --username family@example.com --generate --totp JBSWY3DPEHPK3PXP --url https://mail.example.com >/dev/null
pt add "Router" --vault Family --username admin --password admin --url http://192.168.1.1 >/dev/null
pt add "Door code" --kind password --password 4711 >/dev/null
invite=$(pt user invite | sed -n 's/.*--invite \([^ ]*\).*/\1/p')

# Once alice exists, bob shares Family with her and sends her an item.
(
  until pt user verify alice >/dev/null 2>&1; do sleep 2; done
  sleep 40 # after the empty-home screenshot
  pt vault share Family alice --role writer >/dev/null
  pt send --to alice "Door code" >/dev/null
) &
watcher=$!

zip -qj "$tmp/export.1pux" client/tests/fixtures/export.data
printf '{"version":3,"description":"1Password Unencrypted Export","createdAt":1700000000}' >"$tmp/export.attributes"
(cd "$tmp" && zip -q export.1pux export.attributes)

xcrun simctl ui "$sim" appearance "$theme"
# Enrolled Touch ID / Face ID that matches whenever the app asks.
xcrun simctl spawn "$sim" notifyutil -s com.apple.BiometricKit.enrollmentChanged 1
xcrun simctl spawn "$sim" notifyutil -p com.apple.BiometricKit.enrollmentChanged
(while :; do
  for m in pearl fingerTouch; do xcrun simctl spawn "$sim" notifyutil -p "com.apple.BiometricKit_Sim.$m.match" >/dev/null 2>&1; done
  sleep 2
done) &
matcher=$!
xcrun simctl uninstall "$sim" com.borodutch.plaintext 2>/dev/null || true
xcrun simctl status_bar "$sim" override --time 9:41 --batteryState charged --batteryLevel 100 --cellularBars 4 --wifiBars 3
rm -rf "$tmp/result.xcresult"
TEST_RUNNER_PT_SERVER=$url TEST_RUNNER_PT_INVITE=$invite TEST_RUNNER_PT_IMPORT_FILE="$tmp/export.1pux" \
  xcodebuild -quiet -project apple/Plaintext.xcodeproj -scheme Journey -destination "platform=iOS Simulator,name=$sim" \
  -derivedDataPath "${DERIVED_DATA:-apple/build}" -resultBundlePath "$tmp/result.xcresult" test || status=$?
mkdir -p "$out"
[ -z "${status:-}" ] || cp -R "$tmp/result.xcresult" "$out/" # to see why
xcrun xcresulttool export attachments --path "$tmp/result.xcresult" --output-path "$tmp/att" >/dev/null || true
python3 - "$tmp/att" "$out" "$theme" <<'PY'
import json, os, shutil, sys
src, out, theme = sys.argv[1:]
for t in json.load(open(os.path.join(src, "manifest.json"))):
    for a in t["attachments"]:
        name = a["suggestedHumanReadableName"].split("_")[0]
        if not name[:2].isdigit():
            continue
        shutil.copy(os.path.join(src, a["exportedFileName"]), os.path.join(out, f"{name}-{theme}.png"))
PY
xcrun simctl status_bar "$sim" clear
if [ "${MAC:-}" = 1 ]; then
  dd="${DERIVED_DATA:-apple/build}"
  xcodebuild -quiet -project apple/Plaintext.xcodeproj -scheme Plaintext -destination 'platform=macOS,arch=arm64' -derivedDataPath "$dd" build
  data="$HOME/Library/Containers/com.borodutch.plaintext/Data"
  rm -rf "$data/tmp/shots" "$data/Library/Application Support/Plaintext" "$data/Library/Preferences/com.borodutch.plaintext.plist"
  PT_SHOTS=1 PT_LOGIN="$(printf '%s\t%s\t%s' "$url" "$sk" "bob's long password")" PT_INVITE2=$(pt user invite | sed -n 's/.*--invite \([^ ]*\).*/\1/p') \
    "$dd/Build/Products/Debug/Plaintext.app/Contents/MacOS/Plaintext" >/dev/null 2>&1 || true
  cp "$data/tmp/shots/"*.png "$out/"
  rm -rf "$data/Library/Application Support/Plaintext" "$data/Library/Preferences/com.borodutch.plaintext.plist"
fi
[ -z "${status:-}" ] || xcrun xcresulttool get test-results summary --path "$tmp/result.xcresult" --compact |
  python3 -c 'import json, sys; [print(f["failureText"]) for f in json.load(sys.stdin).get("testFailures", [])]'
exit "${status:-0}"
