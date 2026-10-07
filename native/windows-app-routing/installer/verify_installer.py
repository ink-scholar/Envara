#!/usr/bin/env python3
"""Read-only static installer grammar/bundle checks; never runs PowerShell.

Optional --report writes just the JSON evidence file explicitly requested.
Tree-sitter parsing does not establish PowerShell engine or Windows acceptance.
"""

import argparse
import hashlib
import importlib.metadata
import json
import platform
import re
import struct
from pathlib import Path


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def unique_object(items):
    result = {}
    for key, value in items:
        require(key not in result, f"duplicate JSON property: {key}")
        result[key] = value
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    from tree_sitter import Language, Parser
    import tree_sitter_powershell

    script = Path(__file__).with_name("Install-AppRouting.ps1")
    source = script.read_bytes()
    tree = Parser(Language(tree_sitter_powershell.language())).parse(source)
    errors = []

    def visit(node):
        if node.type == "ERROR" or node.is_missing:
            errors.append({"type": node.type, "line": node.start_point.row + 1,
                           "column": node.start_point.column + 1})
        for child in node.children:
            visit(child)

    visit(tree.root_node)
    require(not errors, f"PowerShell grammar errors: {errors}")
    text = source.decode("ascii")
    names_block = re.search(r"\$PayloadNames = @\((.*?)\n\)", text, re.S)
    require(names_block is not None, "installer payload declaration missing")
    names = re.findall(r"'([^']+)'", names_block.group(1))
    require(len(names) == 12 and len(set(names)) == 12, "installer payload names invalid")
    bundle = args.bundle.resolve(strict=True)
    require({entry.name for entry in bundle.iterdir()} == set(names) | {"install-manifest.json"},
            "source bundle must contain exactly 12 payloads plus manifest")
    require(all(entry.is_file() and not entry.is_symlink() for entry in bundle.iterdir()),
            "bundle contains a directory or symlink")
    manifest_path = bundle / "install-manifest.json"
    manifest_sha = digest(manifest_path)
    require(re.fullmatch(r"[a-f0-9]{64}", args.expected_manifest_sha256) is not None and
            manifest_sha == args.expected_manifest_sha256, "manifest does not match review anchor")
    manifest = json.loads(manifest_path.read_text(), object_pairs_hook=unique_object)
    require(set(manifest) == {"schema", "platform", "architecture", "service", "captureAbi", "engine", "upstream", "files"},
            "installer manifest field contract differs")
    require(type(manifest["schema"]) is int and manifest["schema"] == 1 and
            type(manifest["captureAbi"]) is int and manifest["captureAbi"] == 1 and
            manifest["platform"] == "windows" and manifest["architecture"] == "x64" and
            manifest["service"] == "EnvaraAppRouting" and manifest["engine"] == "windivert",
            "manifest platform/ABI/service contract differs")
    commit = re.search(r"\$UpstreamCommit = '([a-f0-9]+)'", text).group(1)
    require(manifest["upstream"] == {"project": "basil00/WinDivert", "version": "2.2.2", "commit": commit},
            "upstream contract differs")
    require(type(manifest["files"]) is list and len(manifest["files"]) == 12, "payload list invalid")
    hashes = {}
    for artifact in manifest["files"]:
        require(set(artifact) == {"name", "sha256"} and artifact["name"] in names and
                artifact["name"] not in hashes and re.fullmatch(r"[a-f0-9]{64}", artifact["sha256"]) is not None,
                "invalid payload entry")
        require(digest(bundle / artifact["name"]) == artifact["sha256"], "payload bytes changed")
        hashes[artifact["name"]] = artifact["sha256"]
    for variable, name in [("PinnedDriverSHA256", "WinDivert64.sys"), ("PinnedDLLSHA256", "WinDivert.dll"),
                           ("PinnedSourceSHA256", "WinDivert-corresponding-source.tar.gz")]:
        pinned = re.search(rf"\${variable} = '([a-f0-9]{{64}})'", text).group(1)
        require(hashes[name] == pinned, f"pinned {name} digest differs")
    capture = json.loads((bundle / "capture-provenance.json").read_text(), object_pairs_hook=unique_object)
    require(set(capture) == {"schema", "captureAbi", "engine", "architecture", "upstream", "files"} and
            capture["schema"] == 1 and capture["captureAbi"] == 1 and capture["architecture"] == "x64" and
            capture["engine"] == "windivert" and capture["upstream"] == manifest["upstream"], "capture manifest differs")
    require({entry["name"]: entry["sha256"] for entry in capture["files"]} ==
            {name: hashes[name] for name in ["EnvaraCapture.dll", "WinDivert.dll", "WinDivert64.sys"]} and
            len(capture["files"]) == 3, "capture payload hashes differ")
    for name in ["EnvaraAppRouting.exe", "EnvaraCapture.dll", "WinDivert.dll", "WinDivert64.sys"]:
        data = (bundle / name).read_bytes()
        require(data[:2] == b"MZ" and len(data) >= 512, f"bad PE DOS header: {name}")
        offset = struct.unpack_from("<I", data, 0x3c)[0]
        require(offset >= 64 and offset + 168 <= len(data) and data[offset:offset + 4] == b"PE\0\0" and
                struct.unpack_from("<H", data, offset + 4)[0] == 0x8664 and
                struct.unpack_from("<H", data, offset + 24)[0] == 0x20b, f"not x64 PE32+: {name}")
    report = {
        "host": platform.system(), "installerScriptSHA256": digest(script), "bundleManifestSHA256": manifest_sha,
        "treeSitterVersion": importlib.metadata.version("tree-sitter"),
        "treeSitterPowerShellVersion": importlib.metadata.version("tree-sitter-powershell"),
        "powerShellGrammarErrors": errors, "exactPayloadCount": 12, "exactBundleEntryCount": 13,
        "schemaMatchesInstaller": True, "payloadHashesMatch": True, "pinnedUpstreamHashesMatch": True,
        "captureManifestAgrees": True, "staticX64PEHeadersMatch": True,
        "powerShellEngineTested": False, "windowsAuthenticodeTested": False,
        "uacAclScmInstallTested": False, "installerExecuted": False,
        "captureActivated": False, "nativeRoutingAcceptanceVerified": False,
    }
    output = json.dumps(report, indent=2) + "\n"
    if args.report:
        args.report.write_text(output)
    print(output, end="")


if __name__ == "__main__":
    main()
