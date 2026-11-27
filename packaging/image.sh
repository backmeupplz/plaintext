#!/bin/sh
# Pushes the server image for amd64 and arm64 from the release's static musl tarballs, without a Docker daemon (the
# Forgejo jobs have none): one layer with /plaintext-server, /data owned by the nonroot uid and /tmp, on an empty base.
#   packaging/image.sh ghcr.io/backmeupplz/plaintext-server 0.1.0 dist     (needs crane, logged in to the registry)
set -eu
img=$1 version=$2 dist=$3
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
manifests=""
for arch in amd64:x86_64 arm64:aarch64; do
  platform=linux/${arch%%:*}
  tar -xzf "$dist/plaintext-server-${arch##*:}-unknown-linux-musl.tar.gz" -C "$tmp" plaintext-server
  # python's tarfile sets owners and modes the same way on macOS and Linux, unlike bsdtar and GNU tar's flags
  python3 - "$tmp/plaintext-server" "$tmp/layer.tar" <<'EOF'
import sys, tarfile
src, out = sys.argv[1:]
def entry(name, kind, uid, mode):
    i = tarfile.TarInfo(name)
    i.type, i.uid, i.gid, i.mode = kind, uid, uid, mode
    return i
with tarfile.open(out, "w", format=tarfile.PAX_FORMAT) as t:
    t.addfile(entry("data", tarfile.DIRTYPE, 65532, 0o755))
    t.addfile(entry("tmp", tarfile.DIRTYPE, 0, 0o1777))
    with open(src, "rb") as f:
        i = entry("plaintext-server", tarfile.REGTYPE, 0, 0o755)
        i.size = f.seek(0, 2)
        f.seek(0)
        t.addfile(i, f)
EOF
  base=$(crane append --oci-empty-base -f "$tmp/layer.tar" -t "$img:$version")
  mutated=$(crane mutate "$base" --repo "$img" --set-platform "$platform" \
    --entrypoint /plaintext-server --user 65532:65532 --exposed-ports 8080/tcp \
    -e PLAINTEXT_DB=/data/plaintext.db -e PLAINTEXT_ADDR=0.0.0.0:8080 \
    -l org.opencontainers.image.source=https://github.com/backmeupplz/plaintext \
    -l org.opencontainers.image.version="$version" -l org.opencontainers.image.licenses=MIT)
  # VOLUME /data like the Dockerfile, so a run without -v still keeps the vault out of the container layer; crane
  # mutate has no flag for volumes
  manifests="$manifests -m $(crane config "$mutated" |
    python3 -c 'import json, sys; c = json.load(sys.stdin); c["config"]["Volumes"] = {"/data": {}}; print(json.dumps(c))' |
    crane edit config "$mutated")"
  rm "$tmp/plaintext-server" "$tmp/layer.tar"
done
# the version tag ends up on the multi-arch index, replacing the single-arch image pushed above
# shellcheck disable=SC2086
crane index append $manifests -t "$img:$version"
# GHCR links the package to the repo through this annotation on the index; crane mutate can't annotate an index yet
crane manifest "$img:$version" |
  python3 -c 'import json, sys; m = json.load(sys.stdin); m["annotations"] = {"org.opencontainers.image.source": sys.argv[1]}; print(json.dumps(m))' \
    https://github.com/backmeupplz/plaintext |
  crane edit manifest "$img:$version" -t "$img:$version" >/dev/null
crane tag "$img:$version" latest
