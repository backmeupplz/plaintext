#!/usr/bin/env python3
"""Refresh core/src/public_suffix_list.txt, the Public Suffix List that site
matching (core/src/site.rs) uses to find a page's registrable domain (eTLD+1).
Rules are stored in ASCII (punycode), the form browsers give hostnames in.

    python3 tools/psl.py [list.dat]   # default: download from publicsuffix.org
"""
import sys
import urllib.request

URL = "https://publicsuffix.org/list/public_suffix_list.dat"
src = open(sys.argv[1], encoding="utf-8").read() if len(sys.argv) > 1 else urllib.request.urlopen(URL).read().decode()
version = next((l.split(":", 1)[1].strip() for l in src.splitlines() if l.startswith("// VERSION:")), "unknown")
rules = []
for line in src.splitlines():
    rule = line.strip().split()[0] if line.strip() else ""
    if not rule or rule.startswith("//"):
        continue
    prefix = "!" if rule.startswith("!") else ""
    labels = rule.lstrip("!").split(".")
    try:
        labels = [l if l == "*" else l.encode("idna").decode() for l in labels]
    except UnicodeError:
        print(f"skipped {rule}", file=sys.stderr)
        continue
    rules.append(prefix + ".".join(labels).lower())
out = "core/src/public_suffix_list.txt"
with open(out, "w") as f:
    f.write(f"// Public Suffix List {version}, from {URL} (MPL-2.0), converted to ASCII by tools/psl.py.\n")
    f.write("\n".join(rules) + "\n")
print(f"{len(rules)} rules -> {out}")
