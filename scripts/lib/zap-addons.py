"""Build and verify the locked scanner; ZAP owns add-on dependency loading."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from typing import Any
from xml.parsers import expat

LOCK = pathlib.Path(__file__).with_name("zap-addons.lock.json")
RELEASE_ROOT = "https://github.com/zaproxy/zap-extensions/releases/download/"


def load_source_build(recipe: Any, archives: set[str]) -> None:
    if recipe is None:
        return
    if not isinstance(recipe, dict) or set(recipe) != {"core", "sources", "patch", "outputs"}:
        raise ValueError("invalid ZAP source build")
    core = recipe["core"]
    if (
        not isinstance(core, dict)
        or set(core) != {"archive", "sha256"}
        or not all(isinstance(value, str) for value in core.values())
    ):
        raise ValueError("invalid ZAP source core")
    if core["archive"] != "zap-2.17.0.jar" or not re.fullmatch(r"[0-9a-f]{64}", core["sha256"]):
        raise ValueError("invalid ZAP source core identity/hash")
    patch = recipe["patch"]
    if (
        not isinstance(patch, dict)
        or set(patch) != {"file", "sha256"}
        or not all(isinstance(value, str) for value in patch.values())
    ):
        raise ValueError("invalid ZAP source patch")
    if patch["file"] != "zap-cookie-probes.patch" or not re.fullmatch(r"[0-9a-f]{64}", patch["sha256"]):
        raise ValueError("invalid ZAP source patch path/hash")
    outputs = recipe["outputs"]
    expected = {core["archive"], "network-beta-0.30.0.zap", "ascanrulesBeta-beta-67.zap"}
    if not isinstance(outputs, dict) or set(outputs) != expected or not (expected - {core["archive"]}) <= archives:
        raise ValueError("invalid ZAP source outputs")
    if not all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) for value in outputs.values()):
        raise ValueError("invalid ZAP source output hashes")
    sources = recipe["sources"]
    if not isinstance(sources, list) or len(sources) != 5:
        raise ValueError("invalid ZAP source inventory")
    seen = set()
    for row in sources:
        if not isinstance(row, dict) or set(row) != {"path", "url", "sha256"}:
            raise ValueError("invalid ZAP source entry")
        if not all(isinstance(value, str) for value in row.values()):
            raise ValueError("invalid ZAP source fields")
        path = row["path"]
        if not re.fullmatch(r"(?:zap|addOns)/[A-Za-z0-9_/]+\.java", path) or path in seen:
            raise ValueError("invalid ZAP source path")
        seen.add(path)
        match = re.fullmatch(
            r"https://raw\.githubusercontent\.com/zaproxy/(?:zaproxy|zap-extensions)/[0-9a-f]{40}/(.+)", row["url"]
        )
        if not match or match[1] != path or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"]):
            raise ValueError("ZAP sources require exact revisions and SHA256")


def load_lock(path: pathlib.Path) -> dict[str, Any]:
    lock = json.loads(path.read_text(encoding="utf-8"))
    if (
        not isinstance(lock, dict)
        or set(lock) != {"schemaVersion", "addons", "sourceBuild"}
        or lock["schemaVersion"] != 2
    ):
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
    load_source_build(lock["sourceBuild"], {row["archive"] for row in rows})
    return lock


def verify_hash(path: pathlib.Path, expected: str) -> None:
    with path.open("rb") as handle:
        actual = hashlib.file_digest(handle, "sha256").hexdigest()
    if actual != expected:
        raise ValueError(f"ZAP SHA256 mismatch: {path.name}: expected {expected}, got {actual}")


def download(url: str, destination: pathlib.Path, digest: str) -> None:
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
            str(destination),
            url,
        ],
        check=True,
        timeout=125,
    )
    verify_hash(destination, digest)


def prepare(lock: dict[str, Any], home: pathlib.Path, bundled: pathlib.Path, *, upstream: bool = False) -> None:
    plugins = home / "plugin"
    plugins.mkdir(parents=True, exist_ok=True)
    outputs = (lock.get("sourceBuild") or {}).get("outputs", {}) if not upstream else {}
    for row in lock["addons"]:
        destination = plugins / row["archive"]
        source = bundled / row["archive"]
        digest = outputs.get(row["archive"], row["sha256"])
        if source.is_file():
            verify_hash(source, digest)
            shutil.copyfile(source, destination)
        else:
            if row["archive"] in outputs:
                raise ValueError("ZAP source-built add-on is missing; rebuild the scanner image")
            with tempfile.NamedTemporaryFile(dir=plugins, suffix=".download") as handle:
                staged = pathlib.Path(handle.name)
                download(row["url"], staged, digest)
                shutil.copyfile(staged, destination)


def repack_classes(source: pathlib.Path, destination: pathlib.Path, classes: pathlib.Path) -> None:
    replacements = {path.relative_to(classes).as_posix(): path.read_bytes() for path in classes.rglob("*.class")}
    if not replacements:
        raise ValueError("ZAP source build produced no classes")
    with zipfile.ZipFile(source) as original:
        names = original.namelist()
        if len(names) != len(set(names)) or not replacements.keys() <= set(names):
            raise ValueError("ZAP source build produced unexpected classes or duplicate archive entries")
        with zipfile.ZipFile(destination, "w") as result:
            result.comment = original.comment
            for info in original.infolist():
                result.writestr(info, replacements.get(info.filename, original.read(info)))


def publish_source_built_addons(
    lock: dict[str, Any],
    compiled: pathlib.Path,
    source_plugins: pathlib.Path,
    output: pathlib.Path,
    installation: pathlib.Path,
) -> None:
    """Install verified patched add-ons ahead of ZAP's equal-version stock copies."""
    outputs = lock["sourceBuild"]["outputs"]
    output.mkdir(parents=True, exist_ok=True)
    for row in lock["addons"]:
        archive = row["archive"]
        rebuilt = archive in outputs
        source = compiled / archive if rebuilt else source_plugins / archive
        shutil.copyfile(source, output / archive)
        if rebuilt:
            # Equal-version installation add-ons take precedence over ZAP_HOME.
            installed = installation / "plugin" / archive
            installed.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, installed)
            verify_hash(installed, outputs[archive])


def build_sources(lock: dict[str, Any], installation: pathlib.Path, output: pathlib.Path) -> None:
    recipe = lock["sourceBuild"]
    if recipe is None:
        raise ValueError("ZAP source build recipe is missing")
    core = installation / recipe["core"]["archive"]
    verify_hash(core, recipe["core"]["sha256"])
    patch = LOCK.parent / recipe["patch"]["file"]
    verify_hash(patch, recipe["patch"]["sha256"])
    with tempfile.TemporaryDirectory() as temporary:
        directory = pathlib.Path(temporary)
        prepare(lock, directory, installation / "plugin", upstream=True)
        sources = directory / "sources"
        sources.mkdir()
        for row in recipe["sources"]:
            target = sources / row["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            download(row["url"], target, row["sha256"])
        subprocess.run(["patch", "--batch", "--fuzz=0", "-p1", "-i", str(patch)], cwd=sources, check=True, timeout=30)
        plugins = sorted((directory / "plugin").glob("*.zap"))
        dependencies = directory / "dependencies"
        dependencies.mkdir()
        classpath = [str(core), *map(str, sorted((installation / "lib").glob("*.jar"))), *map(str, plugins)]
        for index, archive in enumerate(plugins):
            with zipfile.ZipFile(archive) as package:
                for info in package.infolist():
                    if not info.filename.endswith(".jar"):
                        continue
                    target = dependencies / f"{index}-{pathlib.PurePosixPath(info.filename).name}"
                    target.write_bytes(package.read(info))
                    classpath.append(str(target))
        artifacts = [
            ("zap/", core),
            ("addOns/network/", directory / "plugin/network-beta-0.30.0.zap"),
            ("addOns/ascanrulesBeta/", directory / "plugin/ascanrulesBeta-beta-67.zap"),
        ]
        compiled = directory / "compiled"
        compiled.mkdir()
        for index, (prefix, original) in enumerate(artifacts):
            classes = directory / f"classes-{index}"
            classes.mkdir()
            inputs = [str(sources / row["path"]) for row in recipe["sources"] if row["path"].startswith(prefix)]
            subprocess.run(
                [
                    "javac",
                    "--release",
                    "17",
                    "-g:none",
                    "-proc:none",
                    "-implicit:none",
                    "-encoding",
                    "UTF-8",
                    "-cp",
                    os.pathsep.join(classpath),
                    "-d",
                    str(classes),
                    *inputs,
                ],
                check=True,
                timeout=120,
            )
            classpath.insert(0, str(classes))
            repack_classes(original, compiled / original.name, classes)
        hashes = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(compiled.iterdir())}
        print("ZAP source-build output SHA256: " + json.dumps(hashes, sort_keys=True), flush=True)
        for name, digest in recipe["outputs"].items():
            verify_hash(compiled / name, digest)
        publish_source_built_addons(lock, compiled, directory / "plugin", output, installation)
        shutil.copyfile(compiled / core.name, core)


def build_image(runtime: str, image: str) -> str:
    if runtime not in {"docker", "podman"} or not re.fullmatch(r".+@sha256:[0-9a-fA-F]{64}", image):
        raise ValueError("ZAP source builds require a container runtime and immutable image")
    with tempfile.TemporaryDirectory() as temporary:
        iid = pathlib.Path(temporary) / "image-id"
        subprocess.run(
            [
                runtime,
                "build",
                "--pull=false",
                "--network=host",
                "--build-arg",
                f"BASE_IMAGE={image}",
                "--iidfile",
                str(iid),
                "-f",
                str(LOCK.parent / "zap.Dockerfile"),
                str(LOCK.parent),
            ],
            check=True,
            timeout=900,
            stdout=sys.stderr,
        )
        identity = iid.read_text().strip()
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", identity):
            raise ValueError("container build did not return an immutable image ID")
        return identity


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


def verify_artifacts(lock: dict[str, Any], home: pathlib.Path, installation: pathlib.Path) -> None:
    recipe = lock["sourceBuild"]
    outputs = (recipe or {}).get("outputs", {})
    if recipe is not None:
        verify_hash(installation / recipe["core"]["archive"], outputs[recipe["core"]["archive"]])
    for row in lock["addons"]:
        digest = outputs.get(row["archive"], row["sha256"])
        verify_hash(home / "plugin" / row["archive"], digest)
        if row["archive"] in outputs:
            # A matching home artifact is insufficient if the installation
            # still contains an equally versioned upstream implementation.
            verify_hash(installation / "plugin" / row["archive"], digest)


def verify_evidence(lock_path: pathlib.Path, evidence_path: pathlib.Path, image: str, runtime_image: str) -> None:
    with evidence_path.open("rb") as handle:
        content = handle.read(262145)
    if len(content) > 262144:
        raise ValueError("ZAP add-on evidence exceeds its size limit")
    evidence = json.loads(content)
    lock = load_lock(lock_path)
    expected = {
        "image": image,
        "runtimeImage": runtime_image,
        "lockSha256": hashlib.sha256(lock_path.read_bytes()).hexdigest(),
        "runnableVerified": True,
        "addons": lock["addons"],
        "sourceBuild": lock["sourceBuild"],
    }
    if evidence != expected or evidence.get("runnableVerified") is not True:
        raise ValueError("ZAP add-on evidence differs from the verified image/lock inventory")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("build", "image", "prepare", "verify-loaded", "verify-evidence"))
    parser.add_argument("--home", type=pathlib.Path)
    parser.add_argument("--bundled", type=pathlib.Path, default=pathlib.Path("/opt/nas-zap/plugin"))
    parser.add_argument("--installation", type=pathlib.Path, default=pathlib.Path("/zap"))
    parser.add_argument("--evidence", type=pathlib.Path)
    parser.add_argument("--image")
    parser.add_argument("--runtime-image")
    parser.add_argument("--runtime")
    args = parser.parse_args()
    if args.mode == "image":
        if not args.runtime or not args.image:
            parser.error("image requires --runtime and --image")
        print(build_image(args.runtime, args.image))
        return 0
    if args.mode == "verify-evidence":
        if not args.evidence or not args.image or not args.runtime_image:
            parser.error("verify-evidence requires --evidence, --image and --runtime-image")
        verify_evidence(LOCK, args.evidence, args.image, args.runtime_image)
        return 0
    lock = load_lock(LOCK)
    if args.mode == "build":
        build_sources(lock, args.installation, args.bundled)
        return 0
    if not args.home:
        parser.error("prepare and verify-loaded require --home")
    if args.mode == "prepare":
        prepare(lock, args.home, args.bundled)
        verify_artifacts(lock, args.home, args.installation)
    else:
        verify_loaded(lock, args.home / "add-ons-state.xml")
        verify_artifacts(lock, args.home, args.installation)
        if args.evidence:
            evidence = {
                "image": os.environ.get("NAS_ZAP_IMAGE", ""),
                "runtimeImage": os.environ.get("NAS_ZAP_RUNTIME_IMAGE", ""),
                "lockSha256": hashlib.sha256(LOCK.read_bytes()).hexdigest(),
                "runnableVerified": True,
                "addons": lock["addons"],
                "sourceBuild": lock["sourceBuild"],
            }
            args.evidence.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, expat.ExpatError, subprocess.SubprocessError) as error:
        raise SystemExit(f"error: {error}") from error
