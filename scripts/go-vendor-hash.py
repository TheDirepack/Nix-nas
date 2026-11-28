#!/usr/bin/env python3
"""Print the buildGoModule vendorHash for go/ without a working host Nix.

buildGoModule hashes the NAR serialization of the `go mod vendor` tree. This
reproduces that hash so a dependency bump can update the Nix packaging; the
QEMU/CI Nix build remains the authority that verifies it.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _string(digest: hashlib._Hash, value: bytes) -> None:
    digest.update(len(value).to_bytes(8, "little"))
    digest.update(value)
    digest.update(b"\0" * (-len(value) % 8))


def _node(digest: hashlib._Hash, path: pathlib.Path) -> None:
    mode = path.lstat().st_mode
    _string(digest, b"(")
    _string(digest, b"type")
    if stat.S_ISLNK(mode):
        _string(digest, b"symlink")
        _string(digest, b"target")
        _string(digest, os.fsencode(os.readlink(path)))
    elif stat.S_ISDIR(mode):
        _string(digest, b"directory")
        for name in sorted(os.listdir(path), key=os.fsencode):
            _string(digest, b"entry")
            _string(digest, b"(")
            _string(digest, b"name")
            _string(digest, os.fsencode(name))
            _string(digest, b"node")
            _node(digest, path / name)
            _string(digest, b")")
    else:
        _string(digest, b"regular")
        if mode & 0o111:
            _string(digest, b"executable")
            _string(digest, b"")
        _string(digest, b"contents")
        _string(digest, path.read_bytes())
    _string(digest, b")")


def nar_sri(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    _string(digest, b"nix-archive-1")
    _node(digest, path)
    return "sha256-" + base64.b64encode(digest.digest()).decode()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module", type=pathlib.Path, default=ROOT / "go")
    parser.add_argument("--go", default=os.environ.get("GO", "go"))
    args = parser.parse_args(argv)
    with tempfile.TemporaryDirectory() as raw:
        work = pathlib.Path(raw) / "module"
        shutil.copytree(args.module, work, ignore=shutil.ignore_patterns("vendor"))
        environment = {**os.environ, "GOFLAGS": "-mod=mod", "GOTOOLCHAIN": "local"}
        subprocess.run([args.go, "mod", "vendor"], cwd=work, env=environment, check=True)
        print(nar_sri(work / "vendor"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
