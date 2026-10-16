"""Build-time Camoufox tuples using the pinned official Python generator.

Use an isolated environment with camoufox==0.4.11 and browserforge==1.2.1.
This script generates data only; it never launches a browser or inspects a
display, user profile, network egress, local fonts, or hardware identifier.
BrowserForge may fetch its pinned public model files on the first import.
"""

import argparse
import hashlib
import importlib.metadata
import json
from pathlib import Path
import random


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--properties", required=True, type=Path)
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    for package, version in {"camoufox": "0.4.11", "browserforge": "1.2.1"}.items():
        if importlib.metadata.version(package) != version:
            raise RuntimeError(f"Expected {package}=={version}")

    import numpy as np
    import camoufox
    import browserforge
    from browserforge.fingerprints import Screen
    from camoufox.fingerprints import from_browserforge, generate_fingerprint
    from camoufox.utils import update_fonts, validate_type
    from camoufox.webgl import sample_webgl

    random.seed(0x454E5641)
    np.random.seed(0x454E5641)
    properties = {p["property"]: p["type"] for p in json.loads(args.properties.read_text())}
    templates = []
    for target_os, native_os in {"macos": "mac", "windows": "win", "linux": "lin"}.items():
        for index in range(8):
            fp = generate_fingerprint(
                browser="firefox", os=target_os, device="desktop", strict=True,
                screen=Screen(min_width=1024, max_width=2560, min_height=720, max_height=1800),
            )
            fields = from_browserforge(fp, "135")
            update_fonts(fields, native_os)
            # The launch integration leaves WebGL 2 enabled. Keep whole sampled
            # families with that same setting; never invent vendor/renderer pairs.
            for _ in range(100):
                webgl = sample_webgl(native_os)
                if webgl.pop("webGl2Enabled"):
                    break
            else:
                raise RuntimeError("No compatible complete WebGL sample")
            fields.update(webgl)
            # Network-dependent surfaces are resolved for each session by Envara.
            # Keeping the generator's language here would incorrectly make an
            # automatic environment appear to have a user-fixed language.
            for key in list(fields):
                if key.startswith(("locale:", "geolocation:", "webrtc:")) or key in {
                    "timezone", "navigator.language", "navigator.languages", "headers.Accept-Language",
                }:
                    del fields[key]
            for key, value in fields.items():
                if key not in properties or not validate_type(value, properties[key]):
                    raise RuntimeError(f"Unsupported native property: {key}")
            if "Firefox/135." not in fields["navigator.userAgent"]:
                raise RuntimeError("Generated UA does not match pinned Firefox major")
            templates.append({"id": f"{target_os}-{index + 1:02d}", "targetOS": target_os, "fingerprint": fields})

    output = {"schemaVersion": 1, "provider": "camoufox", "firefoxMajor": 135, "templates": templates}
    args.output_dir.mkdir(parents=True, exist_ok=True)
    catalog = args.output_dir / "catalog.json"
    catalog.write_text(json.dumps(output, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
    camou_dir = Path(camoufox.__file__).parent
    forge_dir = Path(next(iter(browserforge.__path__)))
    inputs = {
        "camoufox/fingerprints.py": camou_dir / "fingerprints.py",
        "camoufox/utils.py": camou_dir / "utils.py",
        "camoufox/browserforge.yml": camou_dir / "browserforge.yml",
        "camoufox/fonts.json": camou_dir / "fonts.json",
        "camoufox/webgl/sample.py": camou_dir / "webgl/sample.py",
        "camoufox/webgl/webgl_data.db": camou_dir / "webgl/webgl_data.db",
    }
    for group in ("headers", "fingerprints"):
        for path in sorted((forge_dir / group / "data").glob("*")):
            if path.is_file():
                inputs[f"browserforge/{group}/data/{path.name}"] = path
    provenance = {
        "schemaVersion": 1,
        "generator": {"camoufox": "0.4.11", "browserforge": "1.2.1", "numpy": np.__version__},
        "sources": {
            "camoufox": "https://github.com/daijro/camoufox/tree/v135.0.1-beta.24/pythonlib",
            "camoufoxSourceCommit": "95cc4489d025471368412b035743bb59855b160e",
            "browserforge": "https://pypi.org/project/browserforge/1.2.1/",
            "fingerprintModels": "https://github.com/apify/fingerprint-suite/tree/v2.1.58",
        },
        "nativePropertiesSHA256": digest(args.properties),
        "nativePropertiesSource": {
            "url": "https://github.com/daijro/camoufox/releases/download/v135.0.1-beta.24/camoufox-135.0.1-beta.24-mac.arm64.zip",
            "assetID": 237731697,
            "publishedDigest": None,
            "observedArchiveSHA256": "40d6eff71305dcc856a5d67880d328f99783236d7e306eef664b2e9ff4981a67",
            "verification": "Official HTTPS download and ZIP CRC; upstream asset has no published digest.",
        },
        "inputSHA256": {name: digest(path) for name, path in inputs.items()},
        "catalogSHA256": digest(catalog),
        "tupleCount": len(templates),
        "perTargetOS": 8,
        "screenConstraint": {"minWidth": 1024, "maxWidth": 2560, "minHeight": 720, "maxHeight": 1800},
        "webgl2Enabled": True,
        "networkFieldsExcluded": True,
    }
    (args.output_dir / "provenance.json").write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"tupleCount": len(templates), "catalogBytes": catalog.stat().st_size, "catalogSHA256": digest(catalog)}))


if __name__ == "__main__":
    main()
