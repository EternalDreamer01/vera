#!/usr/bin/env python3
import sys, json

if len(sys.argv) != 4:
    print(f"Usage: {sys.argv[0]} <distro> <packages.tsv> <output.json>", file=sys.stderr)
    sys.exit(1)

distro, tsv_file, out_file = sys.argv[1:]
components = []

with open(tsv_file) as f:
    for line in f:
        name, version, arch = line.strip().split("\t")
        purl = f"pkg:deb/{distro}/{name}@{version}?arch={arch}"
        components.append({
            "type": "application",
            "name": name,
            "version": version,
            "purl": purl
        })

sbom = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "version": 1,
    "components": components
}

with open(out_file, "w") as f:
    json.dump(sbom, f, indent=2)

