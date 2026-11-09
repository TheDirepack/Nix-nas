"""Installed OCI fixture with read-only persistence checks and explicit teardown."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import shlex
import subprocess
import sys
import time
import urllib.request
import uuid

SERVICE = "vm-oci-persist"
RESOURCE = "vm-oci-persist-data"
CONTAINER = "systemd-nas-v2-vm-oci-persist"
UNIT = "nas-v2-vm-oci-persist.service"
DATA = pathlib.Path("/tank/vm-oci-persist/sentinel")
CADDY = pathlib.Path("/run/nas-control/caddy-managed.conf")
TOKEN = pathlib.Path("/run/nas-authentik/api-token")
MANIFEST = pathlib.Path("/var/lib/nas-control/authentik-v2-objects.json")
PROJECTIONS = (
    pathlib.Path("/run/containers/systemd/nas-v2-vm-oci-persist.container"),
    pathlib.Path("/run/containers/systemd/nas-v2-net-vm-oci-persist.network"),
    pathlib.Path("/run/systemd/generator/nas-v2-vm-oci-persist.service"),
)
BASELINE = pathlib.Path("/var/lib/nas-test/oci-probe-baseline.json")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def command(*argv: str, input_text: str | None = None, timeout: float = 120) -> str:
    result = subprocess.run(argv, input=input_text, capture_output=True, text=True, timeout=timeout, check=False)
    require(result.returncode == 0, f"{argv[0]} failed ({result.returncode}): {result.stderr[-1200:]}")
    return result.stdout.strip()


def document() -> dict:
    return json.loads(command("nas-managed-services-control", "document"))


def data_state() -> dict:
    info = DATA.stat()
    return {
        "sha256": hashlib.sha256(DATA.read_bytes()).hexdigest(),
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": info.st_mode & 0o777,
    }


def fixture_document() -> dict:
    desired = {"schemaVersion": 3, "services": {}}
    desired.setdefault("storageResources", {})[RESOURCE] = {
        "path": str(DATA.parent),
        "dataset": "tank/nas/vm-oci-persist",
        "stateClass": "authoritative",
        "backup": {"enabled": True, "consistency": "zfs-snapshot"},
    }
    desired["services"][SERVICE] = {
        "name": "VM OCI persistence probe",
        "enabled": True,
        "workload": {"kind": "daemon", "activation": "persistent"},
        "runtime": {"type": "oci", "image": "localhost/nas-v2-vm-probe:v2", "pull": "never"},
        "storage": [{"resource": RESOURCE, "mountPath": "/data", "access": "write"}],
        "resources": {"cpuQuotaPercent": 25, "memoryMaxBytes": 134217728, "pidsMax": 64},
        "network": {"mode": "isolated"},
        "listeners": {"http": {"protocol": "tcp", "exposure": {"port": 18089}, "targetPort": 8080, "firewall": False}},
        "readiness": {"timeoutSeconds": 30, "probes": [{"type": "http", "url": "http://127.0.0.1:18089/"}]},
        "authorization": {"capabilities": [{"id": "access", "title": "Access persistence probe"}]},
        "routes": {
            "web": {
                "target": {"type": "http", "host": "127.0.0.1", "port": 18089},
                "exposure": {"type": "path", "paths": ["/vm-oci-persist/"]},
                "proxy": {"stripPrefix": "/vm-oci-persist"},
                "auth": {"mode": "identity", "capability": "access"},
            }
        },
    }
    return desired


def remove_declarations(expected: dict | None = None) -> None:
    value = document()
    desired = value["document"]
    changed = False
    for section, key in (("services", SERVICE), ("storageResources", RESOURCE)):
        entries = desired.get(section, {})
        if key not in entries:
            continue
        if expected is not None:
            require(entries[key] == expected[section][key], f"fixture declaration changed during cleanup: {key}")
        del entries[key]
        changed = True
    if changed:
        command(
            "nas-managed-services-control",
            "replace-json-document",
            "-",
            value["revision"],
            input_text=json.dumps(desired),
        )


def create() -> None:
    require(not BASELINE.exists() and not DATA.parent.exists(), "OCI persistence fixture already exists")
    value = document()
    desired = value["document"]
    require(SERVICE not in desired["services"], "OCI persistence service already exists")
    require(RESOURCE not in desired.get("storageResources", {}), "OCI persistence resource already exists")
    fixture = fixture_document()
    for section in ("services", "storageResources"):
        desired.setdefault(section, {}).update(fixture[section])
    ownership = str(uuid.uuid4())
    created = False
    published = False
    try:
        command(
            "zfs",
            "create",
            "-o",
            f"mountpoint={DATA.parent}",
            "-o",
            f"nas:qualification={ownership}",
            "tank/nas/vm-oci-persist",
        )
        created = True
        command(
            "nas-managed-services-control",
            "replace-json-document",
            "-",
            value["revision"],
            input_text=json.dumps(desired),
        )
        published = True
        command(
            "podman", "exec", CONTAINER, "sh", "-c", "umask 077; printf '%s\n' nas-v2-persistent-data > /data/sentinel"
        )
        command("zfs", "snapshot", "tank/nas/vm-oci-persist@qualification")
        record()
        verify("creation")
    except Exception as error:
        try:
            if not created:
                datasets = command("zfs", "list", "-H", "-o", "name", "-t", "filesystem").splitlines()
                if "tank/nas/vm-oci-persist" in datasets:
                    observed = command(
                        "zfs", "get", "-H", "-o", "value", "nas:qualification", "tank/nas/vm-oci-persist"
                    )
                    require(observed == ownership, "cannot confirm ownership of partially created fixture dataset")
                    created = True
            if created:
                if published:
                    remove_declarations(fixture)
                else:
                    current = document()["document"]
                    require(
                        SERVICE not in current.get("services", {})
                        and RESOURCE not in current.get("storageResources", {}),
                        "failed document update left declarations with unconfirmed ownership",
                    )
                command("zfs", "destroy", "-r", "tank/nas/vm-oci-persist")
                BASELINE.unlink(missing_ok=True)
        except Exception as cleanup_error:
            raise RuntimeError(f"{error}; fixture cleanup failed: {cleanup_error}; manual recovery required") from error
        raise


def record() -> None:
    require(not BASELINE.exists(), "OCI baseline already exists; use a fresh disposable VM")
    value = document()
    baseline = {
        "revision": value["revision"],
        "service": value["document"]["services"][SERVICE],
        "resource": value["document"]["storageResources"][RESOURCE],
        "data": data_state(),
    }
    require(DATA.read_text() == "nas-v2-persistent-data\n", "OCI fixture data was not written by the container")
    BASELINE.parent.mkdir(parents=True, exist_ok=True)
    BASELINE.write_text(json.dumps(baseline, sort_keys=True) + "\n")
    BASELINE.chmod(0o600)


def read_baseline() -> dict:
    baseline = json.loads(BASELINE.read_text())
    require(
        isinstance(baseline, dict)
        and isinstance(baseline.get("revision"), str)
        and all(isinstance(baseline.get(key), dict) for key in ("service", "resource", "data")),
        "invalid OCI fixture baseline",
    )
    return baseline


def wait_ready(stage: str, timeout: float = 60.0) -> None:
    deadline = time.monotonic() + timeout
    while True:
        try:
            command("systemctl", "is-active", "--quiet", UNIT, timeout=5)
            command(
                "curl", "--fail", "--silent", "--show-error", "--max-time", "2", "http://127.0.0.1:18089/", timeout=5
            )
            return
        except (RuntimeError, subprocess.TimeoutExpired) as error:
            if time.monotonic() >= deadline:
                raise RuntimeError(f"OCI did not become ready after {stage}") from error
            time.sleep(1)


def expected_route(baseline: dict) -> list[str]:
    root = pathlib.Path(__file__).resolve().parents[2]
    if str(root / "services") not in sys.path:
        sys.path.insert(0, str(root / "services"))
    from nas_v2_caddy import generate_caddyfile
    from nas_v2_spec import compile_document, load_schema

    desired = {
        "schemaVersion": 3,
        "services": {SERVICE: baseline["service"]},
        "storageResources": {RESOURCE: baseline["resource"]},
    }
    effective = compile_document(desired, load_schema(root / "schemas/managed-services-v3.schema.json"))
    lines = generate_caddyfile(effective).splitlines()
    first = next(index for index, line in enumerate(lines) if line.startswith("  @"))
    return lines[first:-1]


def verify_route(baseline: dict, stage: str) -> None:
    expected = expected_route(baseline)
    matcher, patterns = expected[0].split(" path ", 1)
    actual = CADDY.read_text().splitlines()
    matches = []
    for index, line in enumerate(actual):
        candidate, separator, paths = line.partition(" path ")
        if separator and any(path.rstrip("/*") == "/vm-oci-persist" for path in shlex.split(paths)):
            matches.append((index, candidate, paths))
    require(len(matches) == 1, f"OCI route missing or duplicated after {stage}")
    index, candidate, paths = matches[0]
    # The renderer assigns path indexes across all applications.
    block = "\n".join(expected).replace(matcher.strip(), candidate.strip())
    require(
        paths == patterns and "\n".join(actual[index : index + len(expected)]) == block,
        f"OCI route target, authentication or proxy changed after {stage}",
    )


def verify(stage: str) -> None:
    baseline = read_baseline()
    value = document()
    require(value["revision"] == baseline["revision"], f"desired revision changed after {stage}")
    require(value["document"]["services"][SERVICE] == baseline["service"], f"OCI declaration changed after {stage}")
    require(
        value["document"]["storageResources"][RESOURCE] == baseline["resource"],
        f"OCI storage declaration changed after {stage}",
    )
    require(
        command("findmnt", "-n", "-o", "FSTYPE,SOURCE,TARGET", "--target", str(DATA.parent)).split()
        == ["zfs", "tank/nas/vm-oci-persist", str(DATA.parent)],
        f"OCI data is not on its declared ZFS dataset after {stage}",
    )
    require(data_state() == baseline["data"], f"OCI data or ownership changed after {stage}")
    wait_ready(stage)
    require(
        command("podman", "inspect", "--format", "{{.ImageName}}", CONTAINER) == "localhost/nas-v2-vm-probe:v2",
        f"wrong OCI image is running after {stage}",
    )
    require(
        command("curl", "--fail", "--silent", "--show-error", "--max-time", "10", "http://127.0.0.1:18089/")
        == "nas-v2-oci-v2",
        f"wrong live OCI response after {stage}",
    )
    require(
        command("podman", "exec", CONTAINER, "cat", "/data/sentinel") == "nas-v2-persistent-data",
        f"OCI cannot read its persistent attachment after {stage}",
    )
    require(
        command("podman", "exec", CONTAINER, "cat", "/sys/fs/cgroup/memory.max") == "134217728",
        "OCI memory limit is not enforced",
    )
    require(
        command("podman", "exec", CONTAINER, "cat", "/sys/fs/cgroup/pids.max") == "64",
        "OCI PID limit is not enforced",
    )
    quota, period = map(int, command("podman", "exec", CONTAINER, "cat", "/sys/fs/cgroup/cpu.max").split())
    require(quota > 0 and period > 0 and quota * 4 == period, "OCI CPU limit is not enforced")
    verify_route(baseline, stage)
    print(f"PASS: OCI revision, image, HTTP, ZFS data, ownership and cgroup limits after {stage}", flush=True)


def locked() -> None:
    state = command("systemctl", "show", UNIT, "--property=ActiveState", "--value")
    require(state == "inactive", f"OCI service remained {state} while secrets are locked")
    result = subprocess.run(
        ["curl", "--silent", "--max-time", "5", "http://127.0.0.1:18089/"],
        capture_output=True,
        timeout=10,
        check=False,
    )
    require(result.returncode == 7, "OCI listener did not refuse connections while locked")


def remove() -> None:
    baseline = read_baseline()
    remove_declarations(
        {"services": {SERVICE: baseline["service"]}, "storageResources": {RESOURCE: baseline["resource"]}}
    )
    require(
        command("systemctl", "show", UNIT, "--property=ActiveState", "--value") == "inactive", "removed OCI is active"
    )
    for path in PROJECTIONS:
        require(not path.exists() and not path.is_symlink(), f"removed OCI projection remains: {path}")
    for kind, name in (("container", CONTAINER), ("network", "nas-v2-vm-oci-persist")):
        result = subprocess.run(["podman", kind, "exists", name], capture_output=True, timeout=30, check=False)
        require(result.returncode == 1, f"removed OCI {kind} remains or inspection failed")
    require("/vm-oci-persist/" not in CADDY.read_text(), "removed OCI route remains")
    manifest = MANIFEST
    command("systemctl", "start", "nas-managed-services-authentik-reconcile.service")
    require(
        f"application.{SERVICE}.access" not in json.loads(manifest.read_text())["groups"],
        "removed OCI capability remains",
    )
    token = TOKEN.read_text().strip()
    request = urllib.request.Request(
        f"http://127.0.0.1:9000/identity/api/v3/core/groups/?name=application.{SERVICE}.access&page_size=100",
        headers={"Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        groups = json.load(response)["results"]
    require(
        not any(group["name"] == f"application.{SERVICE}.access" for group in groups), "removed Authentik group remains"
    )
    require(data_state() == baseline["data"], "app removal deleted retained data")
    print("PASS: OCI removal cleaned projections and retained application data", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("create", "verify", "locked", "remove"))
    parser.add_argument("--stage", default="installed lifecycle")
    args = parser.parse_args()
    try:
        if args.mode == "verify":
            verify(args.stage)
        else:
            {"create": create, "locked": locked, "remove": remove}[args.mode]()
    except (RuntimeError, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        print(f"OCI qualification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
