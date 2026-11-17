#!/usr/bin/env python3
"""Validate the QA SIEM own-product legal register and web copy."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def fail(message: str) -> None:
    print(f"legal: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> int:
    manifest_file = ROOT / "legal" / "manifest.json"
    try:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot read {manifest_file}: {exc}")

    if manifest.get("schemaVersion") != 1:
        fail("schemaVersion must be 1")
    if manifest.get("spdx") != "MIT":
        fail("spdx must be MIT")
    source = manifest.get("source", "")
    if not source.startswith("https://"):
        fail("source must be an https URL")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", manifest.get("lastReviewed", "")):
        fail("lastReviewed must be YYYY-MM-DD")
    if not manifest.get("components"):
        fail("components must not be empty")
    if not manifest.get("documents"):
        fail("documents must not be empty")
    if not isinstance(manifest.get("reviews"), list):
        fail("reviews must be an array")

    header = (ROOT / "src" / "server.h").read_text(encoding="utf-8")
    version = re.search(r'#define QA_SIEM_VERSION "([^"]+)"', header)
    if not version:
        fail("cannot read QA_SIEM_VERSION")
    if manifest.get("reviewedVersion") != version.group(1):
        fail(
            f"reviewedVersion {manifest.get('reviewedVersion')} does not match "
            f"QA_SIEM_VERSION {version.group(1)}"
        )

    for component in manifest["components"]:
        if component.get("id") == "qa-siem" and component.get("license") != "MIT":
            fail("qa-siem component must be MIT")

    for document in manifest["documents"]:
        path = (ROOT / document["path"]).resolve()
        if ROOT not in path.parents and path != ROOT:
            fail(f"document escapes the repository: {document['path']}")
        if not path.is_file():
            fail(f"missing document: {document['path']}")

    for name in ("legal.html", "legal.js"):
        if not (ROOT / "web" / name).is_file():
            fail(f"missing web/{name}")
    web_copy = ROOT / "web" / "legal.json"
    if not web_copy.is_file():
        fail("web/legal.json is missing; run make legal")
    if json.loads(web_copy.read_text(encoding="utf-8")) != manifest:
        fail("web/legal.json does not match legal/manifest.json")

    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    installer = (ROOT / "scripts" / "install.sh").read_text(encoding="utf-8")
    for name in ("LICENSE", "THIRD-PARTY-NOTICES.md", "legal.json"):
        if name not in makefile:
            fail(f"Makefile does not install {name}")
    for name in ("LICENSE", "THIRD-PARTY-NOTICES.md", "legal.json"):
        if name not in installer:
            fail(f"scripts/install.sh does not install {name}")

    print("legal: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
