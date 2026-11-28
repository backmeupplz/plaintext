#!/usr/bin/env python3
"""Package the extension for Chrome and Firefox from this one source tree.

    wasm/build.sh extension            # builds extension/pkg first
    python3 extension/package.py [N]   # N: test build number

Writes extension/dist/{chrome,firefox}/ (load either unpacked) and
plaintext-chrome-<v>.zip / plaintext-firefox-<v>.xpi (unsigned).
With N the manifest version is 0.1.0.N, so each test build has its own.
"""
import json
import pathlib
import shutil
import sys
import zipfile

here = pathlib.Path(__file__).resolve().parent
dist = here / "dist"
build = sys.argv[1] if len(sys.argv) > 1 else None
FILES = ["manifest.json", "background.js", "content.js", "popup.html", "popup.js", "popup.css", "setup.html", "setup.js",
         "setup.css", "offscreen.html", "offscreen.js", "lib", "icons", "pkg/plaintext_wasm.js", "pkg/plaintext_wasm_bg.wasm"]

if not (here / "pkg/plaintext_wasm_bg.wasm").exists():
    sys.exit("extension/pkg is missing: run wasm/build.sh extension first")

base = json.loads((here / "manifest.json").read_text())
if build:
    base["version"] = f"{base['version']}.{int(build)}"
    base["version_name"] = f"{base['version'].rsplit('.', 1)[0]}-test.{int(build)}"


def firefox(m):
    m = json.loads(json.dumps(m))
    m.pop("minimum_chrome_version")
    m.pop("version_name", None)
    # Firefox runs background scripts in an event page, which has the DOM
    # (and so the clipboard) that Chrome's service worker borrows an offscreen page for.
    m["background"] = {"scripts": ["background.js"], "type": "module"}
    m["permissions"] = [p for p in m["permissions"] if p != "offscreen"]
    m["browser_specific_settings"] = {"gecko": {"id": "plaintext@getplaintext.org", "strict_min_version": "140.0",
                                                "data_collection_permissions": {"required": ["none"]}}}
    return m


version = base.get("version_name", base["version"])
for name, manifest, skip, ext in [("chrome", base, set(), "zip"), ("firefox", firefox(base), {"offscreen.html", "offscreen.js"}, "xpi")]:
    out = dist / name
    shutil.rmtree(out, ignore_errors=True)
    for f in FILES:
        if f in skip:
            continue
        src, dst = here / f, out / f
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(src, dst) if src.is_dir() else shutil.copy2(src, dst)
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    archive = dist / f"plaintext-{name}-{version}.{ext}"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(out.rglob("*")):
            if p.is_file():
                info = zipfile.ZipInfo(str(p.relative_to(out)), date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o644 << 16
                z.writestr(info, p.read_bytes())
    print(archive)
