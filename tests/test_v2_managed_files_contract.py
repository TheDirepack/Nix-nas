"""Schema and fail-closed validation for V2's future managed-file primitive.

No runtime materializer is installed by this change. Even a fully valid
declaration must fail compilation until generation staging and native service
delivery are implemented, rather than being silently ignored.
"""

from __future__ import annotations

import copy
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_spec as v2  # noqa: E402


class ManagedFileContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = v2.load_schema(ROOT / "schemas/managed-services-v3.schema.json")

    @staticmethod
    def item(destination: str = "/etc/demo/config.yaml", **changes: object) -> dict:
        result = {
            "id": "primary",
            "destination": destination,
            "sensitivity": "non-secret",
            "content": {"literal": "enabled: true\n"},
        }
        result.update(changes)
        return result

    def doc(self, files: list[dict] | None = None) -> dict:
        service = {
            "name": "Demo",
            "workload": {"kind": "daemon"},
            "runtime": {"type": "exec", "command": ["/bin/true"]},
        }
        if files is not None:
            service["files"] = files
        return {"schemaVersion": 3, "services": {"demo": service}}

    def compile(self, doc: dict) -> dict:
        return v2.compile_document(doc, self.schema)

    def assert_file_error(self, doc: dict, code: str) -> None:
        with self.assertRaises(v2.ManagedServicesV2Error) as raised:
            self.compile(doc)
        self.assertEqual(raised.exception.code, code)
        self.assertIn("$.services.demo.files", raised.exception.path)

    def test_legacy_specs_continue_compiling_without_file_declarations(self) -> None:
        effective = self.compile(self.doc())
        self.assertNotIn("files", effective["services"]["demo"])
        self.assertEqual(effective["derived"]["runtime"]["demo"]["ownerUnit"], "nas-v2-demo.service")

    def test_explicit_empty_file_list_remains_a_noop(self) -> None:
        self.assertEqual(self.compile(self.doc([]))["services"]["demo"]["files"], [])

    def test_valid_contract_normalizes_defaults_but_cannot_silently_apply(self) -> None:
        document = self.doc([self.item()])
        original = copy.deepcopy(document)
        v2.validate_schema(document, self.schema)
        normalized = v2.normalize(document)
        v2.validate_schema(normalized, self.schema)
        entry = normalized["services"]["demo"]["files"][0]
        self.assertEqual(entry["delivery"], "generation")
        self.assertEqual(entry["mode"], "0444")
        self.assertEqual(entry["onChange"], "restart")
        self.assertEqual(document, original)
        self.assert_file_error(document, "managed-file-unavailable")

    def test_even_disabled_files_fail_closed(self) -> None:
        document = self.doc([self.item()])
        document["services"]["demo"]["enabled"] = False
        self.assert_file_error(document, "managed-file-unavailable")

    def test_schema_rejects_unsupported_content_and_secret_classes(self) -> None:
        for update in (
            {"sensitivity": "secret"},
            {"content": {"template": "secret {{ credentials.api }}" }},
            {"content": {"literal": "x", "credential": "api"}},
            {"id": "../bad"},
            {"delivery": "runtime"},
            {"mode": "0777"},
            {"onChange": "execute"},
            {"unknown": True},
        ):
            with self.subTest(update=update):
                self.assert_file_error(self.doc([self.item(**update)]), "schema-validation")

    def test_schema_bounds_file_count_and_individual_literal_size(self) -> None:
        files = [self.item(id=f"file-{i}", destination=f"/etc/demo/{i}") for i in range(129)]
        self.assert_file_error(self.doc(files), "schema-validation")
        self.assert_file_error(self.doc([self.item(content={"literal": "a" * 65537})]), "schema-validation")

    def test_utf8_byte_limit_and_nul_are_enforced(self) -> None:
        self.assert_file_error(
            self.doc([self.item(content={"literal": "é" * 33000})]),
            "managed-file-content",
        )
        self.assert_file_error(self.doc([self.item(content={"literal": "before\x00after"})]), "managed-file-content")

    def test_relative_parent_traversal_and_control_paths_fail(self) -> None:
        for destination in (
            "etc/demo.yml",
            "/etc/demo/../unsafe",
            "/etc/demo/\nunsafe",
        ):
            with self.subTest(destination=destination):
                self.assert_file_error(self.doc([self.item(destination)]), "unsafe-path")

    def test_noncanonical_and_reserved_destinations_fail(self) -> None:
        for destination in (
            "/etc//demo/config.yaml",
            "/etc/./demo/config.yaml",
            "//etc/demo/config.yaml",
            "/proc/sys/kernel/core_pattern",
            "/sys/class/example",
            "/dev/zero",
            "/nix/store/obj",
            "/run/nas-control/plan.json",
            "/run/credentials/api",
            "/var/lib/nas-control/services.yaml",
        ):
            with self.subTest(destination=destination):
                self.assert_file_error(self.doc([self.item(destination)]), "managed-file-path")

    def test_duplicate_id_and_overlapping_targets_fail(self) -> None:
        for other in (
            self.item("/etc/demo/other.yaml"),
            self.item("/etc/demo/config.yaml", id="secondary"),
            self.item("/etc/demo", id="secondary"),
            self.item("/etc/demo/config.yaml/subfile", id="secondary"),
        ):
            with self.subTest(other=other):
                self.assert_file_error(
                    self.doc([self.item(), other]),
                    "managed-file-conflict",
                )

    def test_storage_and_credential_mounts_cannot_shadow_files(self) -> None:
        storage = self.doc([self.item()])
        storage["storageResources"] = {"data": {"path": "/srv/demo", "stateClass": "authoritative"}}
        storage["services"]["demo"]["storage"] = [{"resource": "data", "mountPath": "/etc/demo"}]
        self.assert_file_error(storage, "managed-file-conflict")

        credentials = self.doc([self.item()])
        credentials["credentials"] = {"api": {"path": "/run/nas-secrets/api"}}
        credentials["services"]["demo"]["credentials"] = [
            {"credential": "api", "use": "file", "mountPath": "/etc/demo/config.yaml"}
        ]
        self.assert_file_error(credentials, "managed-file-conflict")

    def test_declared_file_never_reaches_effective_output(self) -> None:
        with self.assertRaises(v2.ManagedServicesV2Error) as raised:
            self.compile(self.doc([self.item()]))
        self.assertEqual(raised.exception.code, "managed-file-unavailable")


if __name__ == "__main__":
    unittest.main()
