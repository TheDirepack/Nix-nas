"""Generate a machine-readable Nix closure and OCI pin inventory for releases."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
from typing import Any

_REPOSITORY_RE = re.compile(r'^\s*repository\s*=\s*"([^"]+)"\s*;\s*$', re.MULTILINE)
_TAG_RE = re.compile(r'^\s*tag\s*=\s*"([^"]+)"\s*;\s*$', re.MULTILINE)
_DIGEST_RE = re.compile(r'^\s*([A-Za-z0-9_]+)\s*=\s*"([^"]*)"\s*;\s*$', re.MULTILINE)


def _closure_entries(payload: Any) -> list[dict[str, Any]]:
    raw_entries: list[tuple[str, dict[str, Any]]] = []
    if isinstance(payload, dict):
        for path, metadata in payload.items():
            if not isinstance(path, str) or not isinstance(metadata, dict):
                raise ValueError("nix path-info JSON contains an invalid entry")
            raw_entries.append((path, metadata))
    elif isinstance(payload, list):
        for item in payload:
            if not isinstance(item, dict):
                raise ValueError("nix path-info JSON list entries must be objects")
            path = item.get("path")
            if not isinstance(path, str):
                raise ValueError("nix path-info JSON entry is missing path")
            raw_entries.append((path, item))
    else:
        raise ValueError("nix path-info JSON must be an object or list")

    entries: list[dict[str, Any]] = []
    for path, metadata in raw_entries:
        entry: dict[str, Any] = {"path": path}
        for key in ("narHash", "narSize", "closureSize"):
            value = metadata.get(key)
            if isinstance(value, (str, int)) and not isinstance(value, bool):
                entry[key] = value
        references = metadata.get("references")
        if isinstance(references, list) and all(isinstance(value, str) for value in references):
            entry["references"] = sorted(references)
        entries.append(entry)
    return sorted(entries, key=lambda item: item["path"])


def collect_nix_closure(*, nix_bin: str, system_path: str) -> list[dict[str, Any]]:
    result = subprocess.run(
        [nix_bin, "path-info", "--json", "-r", system_path],
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[:4000]
        raise RuntimeError(f"nix path-info failed: {detail}")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("nix path-info returned invalid JSON") from exc
    return _closure_entries(payload)


def _image_pin(path: pathlib.Path, root: pathlib.Path) -> dict[str, Any] | None:
    text = path.read_text(encoding="utf-8")
    repository = _REPOSITORY_RE.search(text)
    tag = _TAG_RE.search(text)
    if repository is None or tag is None:
        return None
    digests: dict[str, str] = {}
    digest_block = text.split("digests", 1)
    if len(digest_block) == 2:
        for key, value in _DIGEST_RE.findall(digest_block[1]):
            if key in {"repository", "tag"}:
                continue
            digests[key] = value
    return {
        "file": path.relative_to(root).as_posix(),
        "repository": repository.group(1),
        "tag": tag.group(1),
        "digests": dict(sorted(digests.items())),
    }


def collect_oci_pins(root: pathlib.Path) -> list[dict[str, Any]]:
    pins: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*-image.nix")):
        pin = _image_pin(path, root)
        if pin is not None:
            pins.append(pin)
    return pins


def build_inventory(
    *,
    root: pathlib.Path,
    system_path: str,
    nix_bin: str,
    revision: str,
) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "sourceRevision": revision,
        "systemPath": system_path,
        "nixClosure": collect_nix_closure(nix_bin=nix_bin, system_path=system_path),
        "ociImages": collect_oci_pins(root),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=str(pathlib.Path(__file__).resolve().parents[1]))
    parser.add_argument("--system", default="/run/current-system")
    parser.add_argument("--nix", default="nix")
    parser.add_argument("--revision", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)

    root = pathlib.Path(args.root).resolve()
    output = pathlib.Path(args.output)
    inventory = build_inventory(
        root=root,
        system_path=args.system,
        nix_bin=args.nix,
        revision=args.revision,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(inventory, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
