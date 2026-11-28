#!/bin/sh
# Stops a release build if Cargo or rustup config sits in a parent of the build directory or in $HOME, where an earlier
# job on a shared runner could have left it: Cargo reads .cargo/config.toml from every parent of the directory it runs
# in, so one with a rustc-wrapper would run on every compile.
#   packaging/check-build-dir.sh "$SRC"
set -eu
found=0
for start in "$(dirname "$1")" "$HOME"; do
  d=$(cd "$start" && pwd -P)
  while :; do
    for f in .cargo/config .cargo/config.toml rust-toolchain rust-toolchain.toml; do
      if [ -e "$d/$f" ] || [ -L "$d/$f" ]; then
        echo "found $d/$f, which could change this build" >&2
        found=1
      fi
    done
    [ "$d" = / ] && break
    d=$(dirname "$d")
  done
done
exit $found
