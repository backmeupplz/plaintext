#!/bin/sh
# Checks a release's SHA256SUMS against SHA256SUMS.sig next to it with the release key in docs/install, the same check
# the installer makes:  packaging/verify.sh dist/SHA256SUMS
set -eu
key=$(sed -n "s/^key='\(.*\)'\$/\1/p" "$(dirname "$0")/../docs/install")
[ -n "$key" ] || { echo "no key= line in docs/install" >&2; exit 1; }
signers=$(mktemp)
trap 'rm -f "$signers"' EXIT
echo "release@getplaintext.org $key" > "$signers"
ssh-keygen -Y verify -f "$signers" -I release@getplaintext.org -n plaintext-release -s "$1.sig" < "$1"
