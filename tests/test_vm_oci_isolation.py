from __future__ import annotations

import json
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
GUEST = ROOT / "tests/vm/guest-test.sh"


def isolation_function() -> str:
    source = GUEST.read_text()
    marker = "assert_oci_isolation_profile() {"
    if marker not in source:
        raise AssertionError("installed OCI lifecycle has no isolation profile verifier")
    return marker + source.split(marker, 1)[1].split("\n}\n", 1)[0] + "\n}\n"


def inspect_fixture(
    *, privileged=False, readonly=True, security=("no-new-privileges",), mounts=None, pid=4242, networks=None
):
    return [
        {
            "HostConfig": {
                "Privileged": privileged,
                "ReadonlyRootfs": readonly,
                "SecurityOpt": list(security),
                "PidMode": "",
                "CapAdd": [],
                "NetworkMode": "bridge",
            },
            "NetworkSettings": {
                "Networks": {"nas-v2-vm-oci-probe": {}} if networks is None else networks,
            },
            "Mounts": mounts
            if mounts is not None
            else [
                {"Type": "bind", "Source": "/tank/vm-oci-state", "Destination": "/state", "RW": True},
                {
                    "Type": "bind",
                    "Source": "/run/nas-secrets/vm-oci-probe/token",
                    "Destination": "/run/secrets/token",
                    "RW": False,
                },
                {
                    "Type": "bind",
                    "Source": "/run/containers/storage/etc-hosts",
                    "Destination": "/etc/hosts",
                    "RW": True,
                },
                {"Type": "bind", "Source": "/var/lib/containers/hostname", "Destination": "/etc/hostname", "RW": True},
                {
                    "Type": "bind",
                    "Source": "/run/containers/storage/resolv.conf",
                    "Destination": "/etc/resolv.conf",
                    "RW": True,
                },
                {"Type": "tmpfs", "Source": "tmpfs", "Destination": "/tmp", "RW": True},
            ],
            "State": {"Pid": pid},
        }
    ]


class OciIsolationProfileTests(unittest.TestCase):
    def run_profile(self, *, inspect=None, rootless="false", probes="ok 0 2"):
        function = isolation_function()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "inspect.json").write_text(json.dumps(inspect or inspect_fixture()))
            script = (
                f"""set -euo pipefail
oci_container=fixture
oci_state=/tank/vm-oci-state
oci_credential=/run/nas-secrets/vm-oci-probe/token
fail() {{ echo "$*" >&2; exit 1; }}
oci_inspect() {{ cat '{root}/inspect.json'; }}
oci_rootless() {{ printf '%s\\n' '{rootless}'; }}
oci_probe() {{ printf '%s\\n' '{probes}'; }}
pass() {{ printf 'PASS: %s\\n' "$*"; }}
"""
                + function
                + "\nassert_oci_isolation_profile\n"
            )
            return subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=10, check=False)

    def test_qualified_rootful_profile_is_accepted(self):
        result = self.run_profile()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("rootful", result.stdout)

    def test_profile_rejects_privilege_or_mount_escalation(self):
        extra_bind = inspect_fixture()
        extra_bind[0]["Mounts"].append(
            {"Type": "bind", "Source": "/var/run/docker.sock", "Destination": "/run/podman/podman.sock", "RW": True}
        )
        capability_add = inspect_fixture()
        capability_add[0]["HostConfig"]["CapAdd"] = ["SYS_ADMIN"]
        cases = {
            "privileged": inspect_fixture(privileged=True),
            "writable-root": inspect_fixture(readonly=False),
            "no-new-privileges-missing": inspect_fixture(security=()),
            "extra-host-mount": extra_bind,
            "writable-credential": inspect_fixture(
                mounts=[
                    {"Type": "bind", "Source": "/tank/vm-oci-state", "Destination": "/state", "RW": True},
                    {
                        "Type": "bind",
                        "Source": "/run/nas-secrets/vm-oci-probe/token",
                        "Destination": "/run/secrets/token",
                        "RW": True,
                    },
                ]
            ),
            "host-pid": inspect_fixture(pid=1),
            "capability-add": capability_add,
            "extra-network": inspect_fixture(networks={"nas-v2-vm-oci-probe": {}, "host": {}}),
            "host-network-only": inspect_fixture(networks={"host": {}}),
            "no-network": inspect_fixture(networks={}),
        }
        for label, inspect in cases.items():
            with self.subTest(label=label):
                result = self.run_profile(inspect=inspect)
                self.assertNotEqual(result.returncode, 0, label)
                self.assertIn("OCI", result.stderr)

    def test_profile_rejects_unexpected_rootless_or_container_state(self):
        for label, kwargs in {
            "rootless": {"rootless": "true"},
            "nonroot-uid": {"probes": "ok 1000 2"},
            "seccomp-disabled": {"probes": "ok 0 0"},
            "malformed-probes": {"probes": "ok 0"},
            "failed-step": {"probes": "fail"},
        }.items():
            with self.subTest(label=label):
                result = self.run_profile(**kwargs)
                self.assertNotEqual(result.returncode, 0, label)
                self.assertIn("OCI", result.stderr)

    def test_guest_applies_profile_before_recreate_evidence(self):
        source = GUEST.read_text()
        call = "\nassert_oci_isolation_profile\n"
        self.assertIn(call, source)
        self.assertLess(source.index(call), source.index("OCI container recreation retained"))
        for marker in (
            'podman inspect "$oci_container"',
            "podman info --format",
            'podman exec "$oci_container" /bin/sh -c',
            "/run/podman/podman.sock",
            "NoNewPrivs",
            "CapEff",
            "State.Pid",
        ):
            self.assertIn(marker, source, marker)


if __name__ == "__main__":
    unittest.main()
