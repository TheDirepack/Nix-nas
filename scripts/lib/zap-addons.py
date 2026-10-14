"""Materialize reviewed archives; ZAP owns dependency resolution and loading."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from typing import Any
from xml.parsers import expat

LOCK = pathlib.Path(__file__).with_name("zap-addons.lock.json")
RELEASE_ROOT = "https://github.com/zaproxy/zap-extensions/releases/download/"


def load_lock(path: pathlib.Path) -> dict[str, Any]:
    lock = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(lock, dict) or set(lock) != {"schemaVersion", "addons"} or lock["schemaVersion"] != 1:
        raise ValueError("invalid ZAP add-on lock")
    rows = lock["addons"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= 100:
        raise ValueError("invalid ZAP add-on inventory")
    seen = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"id", "version", "status", "archive", "sha256", "url"}:
            raise ValueError("invalid ZAP add-on entry")
        if not all(isinstance(value, str) for value in row.values()):
            raise ValueError("invalid ZAP add-on fields")
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", row["id"]) or not re.fullmatch(
            r"[0-9]+\.[0-9]+\.[0-9]+", row["version"]
        ):
            raise ValueError("invalid ZAP add-on identity/version")
        if row["id"] in seen:
            raise ValueError(f"duplicate ZAP add-on: {row['id']}")
        seen.add(row["id"])
        if row["status"] not in {"release", "beta", "alpha"}:
            raise ValueError("invalid ZAP add-on status")
        prefix = f"{row['id']}-{row['status']}-"
        archive = row["archive"]
        if not re.fullmatch(re.escape(prefix) + r"[0-9]+(?:\.[0-9]+)*\.zap", archive):
            raise ValueError("invalid ZAP archive filename")
        version = archive.removeprefix(prefix).removesuffix(".zap")
        expected_url = f"{RELEASE_ROOT}{row['id']}-v{version}/{archive}"
        if row["url"] != expected_url or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"]):
            raise ValueError("ZAP add-ons require exact upstream release URLs and SHA256")
    return lock


def verify_hash(path: pathlib.Path, expected: str) -> None:
    with path.open("rb") as handle:
        actual = hashlib.file_digest(handle, "sha256").hexdigest()
    if actual != expected:
        raise ValueError(f"ZAP add-on SHA256 mismatch: {path.name}")


def prepare(lock: dict[str, Any], home: pathlib.Path, bundled: pathlib.Path) -> None:
    plugins = home / "plugin"
    plugins.mkdir(parents=True, exist_ok=True)
    for row in lock["addons"]:
        destination = plugins / row["archive"]
        source = bundled / row["archive"]
        if source.is_file():
            verify_hash(source, row["sha256"])
            shutil.copyfile(source, destination)
        else:
            with tempfile.NamedTemporaryFile(dir=plugins, suffix=".download") as handle:
                staged = pathlib.Path(handle.name)
                subprocess.run(
                    [
                        "curl",
                        "--fail",
                        "--location",
                        "--silent",
                        "--show-error",
                        "--max-time",
                        "120",
                        "--output",
                        str(staged),
                        row["url"],
                    ],
                    check=True,
                    timeout=125,
                )
                verify_hash(staged, row["sha256"])
                shutil.copyfile(staged, destination)


def verify_loaded(lock: dict[str, Any], state: pathlib.Path) -> None:
    with state.open("rb") as handle:
        content = handle.read(65537)
    if len(content) > 65536:
        raise ValueError("ZAP native state exceeds its size limit")

    def reject_doctype(*_args: Any) -> None:
        raise ValueError("ZAP native state must not contain a DOCTYPE")

    tree = ET.TreeBuilder()
    parser = expat.ParserCreate()
    # Reject DTDs before Expat can process entity declarations.
    parser.StartDoctypeDeclHandler = reject_doctype
    parser.StartElementHandler = tree.start
    parser.EndElementHandler = tree.end
    parser.CharacterDataHandler = tree.data
    parser.Parse(content, True)
    rows = tree.close().findall("runnableAddOns/addon")
    actual = {row.findtext("id"): row.findtext("fullversion") for row in rows}
    expected = {row["id"]: row["version"] for row in lock["addons"]}
    if actual != expected or len(rows) != len(expected):
        raise ValueError(f"ZAP runnable add-ons differ from lock: expected {expected}, got {actual}")


def verify_evidence(lock_path: pathlib.Path, evidence_path: pathlib.Path, image: str) -> None:
    with evidence_path.open("rb") as handle:
        content = handle.read(262145)
    if len(content) > 262144:
        raise ValueError("ZAP add-on evidence exceeds its size limit")
    evidence = json.loads(content)
    expected = {
        "image": image,
        "lockSha256": hashlib.sha256(lock_path.read_bytes()).hexdigest(),
        "runnableVerified": True,
        "addons": load_lock(lock_path)["addons"],
    }
    if evidence != expected or evidence.get("runnableVerified") is not True:
        raise ValueError("ZAP add-on evidence differs from the verified image/lock inventory")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "verify-loaded", "verify-evidence"))
    parser.add_argument("--home", type=pathlib.Path)
    parser.add_argument("--bundled", type=pathlib.Path, default=pathlib.Path("/zap/plugin"))
    parser.add_argument("--evidence", type=pathlib.Path)
    parser.add_argument("--image")
    args = parser.parse_args()
    if args.mode == "verify-evidence":
        if not args.evidence or not args.image:
            parser.error("verify-evidence requires --evidence and --image")
        verify_evidence(LOCK, args.evidence, args.image)
        return 0
    if not args.home:
        parser.error("prepare and verify-loaded require --home")
    lock = load_lock(LOCK)
    if args.mode == "prepare":
        prepare(lock, args.home, args.bundled)
    else:
        verify_loaded(lock, args.home / "add-ons-state.xml")
        if args.evidence:
            evidence = {
                "image": os.environ.get("NAS_ZAP_IMAGE", ""),
                "lockSha256": hashlib.sha256(LOCK.read_bytes()).hexdigest(),
                "runnableVerified": True,
                "addons": lock["addons"],
            }
            args.evidence.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, expat.ExpatError, subprocess.SubprocessError) as error:
        raise SystemExit(f"error: {error}") from error
