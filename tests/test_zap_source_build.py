from __future__ import annotations

import hashlib
import importlib.util
import json
import pathlib
import tempfile
import unittest
import zipfile
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]


class ZapSourceBuildTests(unittest.TestCase):
    def setUp(self) -> None:
        spec = importlib.util.spec_from_file_location("zap_source_addons", ROOT / "scripts/lib/zap-addons.py")
        assert spec is not None and spec.loader is not None
        self.addons = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.addons)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = pathlib.Path(self.temporary.name)

    def test_source_rebuild_replaces_only_reviewed_existing_classes(self) -> None:
        rebuild = getattr(self.addons, "repack_classes", None)
        self.assertIsNotNone(rebuild, "ZAP has no reproducible source-build artifact boundary")
        assert rebuild is not None
        source = self.directory / "original.zap"
        with zipfile.ZipFile(source, "w") as archive:
            archive.writestr("p/Rule.class", b"old implementation")
            archive.writestr("ZapAddOn.xml", b"unchanged rules and dependencies")
            archive.writestr("lib/dependency.jar", b"unchanged dependency")
        classes = self.directory / "classes"
        (classes / "p").mkdir(parents=True)
        (classes / "p/Rule.class").write_bytes(b"compiled source")
        output = self.directory / "rebuilt.zap"
        rebuild(source, output, classes)
        first = output.read_bytes()
        rebuild(source, output, classes)
        self.assertEqual(first, output.read_bytes())
        with zipfile.ZipFile(output) as archive:
            self.assertEqual(set(archive.namelist()), {"p/Rule.class", "ZapAddOn.xml", "lib/dependency.jar"})
            self.assertEqual(archive.read("p/Rule.class"), b"compiled source")
            self.assertEqual(archive.read("ZapAddOn.xml"), b"unchanged rules and dependencies")
            self.assertEqual(archive.read("lib/dependency.jar"), b"unchanged dependency")
        (classes / "p/Unexpected.class").write_bytes(b"unexpected class")
        with self.assertRaisesRegex(ValueError, "unexpected"):
            rebuild(source, output, classes)

    def test_runtime_cannot_substitute_upstream_bytes_for_a_source_rebuild(self) -> None:
        original = b"upstream archive"
        compiled = b"reviewed source rebuild"
        row = {"archive": "network-beta-0.30.0.zap", "sha256": hashlib.sha256(original).hexdigest()}
        lock = {
            "addons": [row],
            "sourceBuild": {"outputs": {row["archive"]: hashlib.sha256(compiled).hexdigest()}},
        }
        bundled = self.directory / "bundled"
        bundled.mkdir()
        (bundled / row["archive"]).write_bytes(original)
        with self.assertRaisesRegex(ValueError, "SHA256"):
            self.addons.prepare(lock, self.directory / "bad-home", bundled)
        (bundled / row["archive"]).write_bytes(compiled)
        self.addons.prepare(lock, self.directory / "home", bundled)
        self.assertEqual((self.directory / "home/plugin" / row["archive"]).read_bytes(), compiled)

    def test_missing_source_built_archive_is_fatal_without_a_download_fallback(self) -> None:
        row = {"archive": "network-beta-0.30.0.zap", "sha256": "a" * 64}
        lock = {"addons": [row], "sourceBuild": {"outputs": {row["archive"]: "b" * 64}}}
        with mock.patch.object(self.addons.subprocess, "run") as download:
            with self.assertRaisesRegex(ValueError, "source-built add-on is missing"):
                self.addons.prepare(lock, self.directory / "home", self.directory / "bundled")
        download.assert_not_called()

    def test_runtime_checks_rebuilt_core_and_every_plugin_hash(self) -> None:
        core = self.directory / "zap-2.17.0.jar"
        plugins = self.directory / "home/plugin"
        plugins.mkdir(parents=True)
        plugin = plugins / "network-beta-0.30.0.zap"
        compiled_core, compiled_plugin = b"compiled core", b"compiled plugin"
        outputs = {
            core.name: hashlib.sha256(compiled_core).hexdigest(),
            plugin.name: hashlib.sha256(compiled_plugin).hexdigest(),
        }
        lock = {
            "addons": [{"archive": plugin.name, "sha256": "a" * 64}],
            "sourceBuild": {"core": {"archive": core.name}, "outputs": outputs},
        }
        core.write_bytes(compiled_core)
        plugin.write_bytes(compiled_plugin)
        installed = self.directory / "plugin" / plugin.name
        installed.parent.mkdir()
        installed.write_bytes(compiled_plugin)
        self.addons.verify_artifacts(lock, plugins.parent, self.directory)
        for artifact, correct in ((core, compiled_core), (plugin, compiled_plugin), (installed, compiled_plugin)):
            with self.subTest(artifact=artifact.name):
                artifact.write_bytes(b"unreviewed artifact")
                with self.assertRaisesRegex(ValueError, "SHA256"):
                    self.addons.verify_artifacts(lock, plugins.parent, self.directory)
                artifact.write_bytes(correct)

    def test_patched_addon_overwrites_equal_version_stock_installation_copy(self) -> None:
        install = self.directory / "installation"
        output = self.directory / "bundled"
        compiled = self.directory / "compiled"
        source = self.directory / "upstream"
        (install / "plugin").mkdir(parents=True)
        compiled.mkdir()
        source.mkdir()
        patched = b"patched network code"
        upstream = b"unchanged upstream code"
        patched_name = "network-beta-0.30.0.zap"
        regular_name = "ordinary-addon.zap"
        (install / "plugin" / patched_name).write_bytes(b"stock equal-version code")
        (install / "plugin" / regular_name).write_bytes(upstream)
        (compiled / patched_name).write_bytes(patched)
        (source / regular_name).write_bytes(upstream)
        lock = {
            "sourceBuild": {"outputs": {patched_name: hashlib.sha256(patched).hexdigest()}},
            "addons": [{"archive": patched_name}, {"archive": regular_name}],
        }
        self.addons.publish_source_built_addons(lock, compiled, source, output, install)
        self.assertEqual((install / "plugin" / patched_name).read_bytes(), patched)
        self.assertEqual((output / patched_name).read_bytes(), patched)
        self.assertEqual((output / regular_name).read_bytes(), upstream)
        self.assertEqual((install / "plugin" / regular_name).read_bytes(), upstream)

    def test_canonical_recipe_pins_sources_patch_and_all_three_outputs(self) -> None:
        lock = self.addons.load_lock(ROOT / "scripts/lib/zap-addons.lock.json")
        recipe = lock.get("sourceBuild")
        self.assertIsInstance(recipe, dict, "scanner source repair has no locked provenance")
        assert recipe is not None
        self.assertEqual(
            set(recipe["outputs"]), {"zap-2.17.0.jar", "network-beta-0.30.0.zap", "ascanrulesBeta-beta-67.zap"}
        )
        self.assertEqual(len(recipe["sources"]), 5)
        patch = ROOT / "scripts/lib" / recipe["patch"]["file"]
        self.assertEqual(hashlib.sha256(patch.read_bytes()).hexdigest(), recipe["patch"]["sha256"])
        for row in recipe["sources"]:
            self.assertRegex(
                row["url"], r"^https://raw\.githubusercontent\.com/zaproxy/(zaproxy|zap-extensions)/[0-9a-f]{40}/"
            )
            self.assertRegex(row["sha256"], r"^[0-9a-f]{64}$")

    def test_recipe_rejects_source_path_escape_unpinned_source_and_missing_output(self) -> None:
        canonical = json.loads((ROOT / "scripts/lib/zap-addons.lock.json").read_text())
        self.assertIsNotNone(canonical.get("sourceBuild"), "source repair lock is absent")
        for mutation in ("path", "url", "outputs", "patch"):
            with self.subTest(mutation=mutation):
                lock = json.loads(json.dumps(canonical))
                recipe = lock["sourceBuild"]
                if mutation == "path":
                    recipe["sources"][0]["path"] = "../../escape.java"
                elif mutation == "url":
                    recipe["sources"][0]["url"] = recipe["sources"][0]["url"].replace(
                        "8a1bff313f4d183dba5aa154ecbe89ad751c9153", "main"
                    )
                elif mutation == "patch":
                    recipe["patch"]["file"] = "../escape.patch"
                else:
                    recipe["outputs"].pop("network-beta-0.30.0.zap")
                path = self.directory / "bad-lock.json"
                path.write_text(json.dumps(lock))
                with self.assertRaises(ValueError):
                    self.addons.load_lock(path)

    def test_recipe_rejects_non_text_core_and_patch_hashes(self) -> None:
        canonical = json.loads((ROOT / "scripts/lib/zap-addons.lock.json").read_text())
        for owner in ("core", "patch"):
            with self.subTest(owner=owner):
                lock = json.loads(json.dumps(canonical))
                lock["sourceBuild"][owner]["sha256"] = None
                path = self.directory / "bad-lock.json"
                path.write_text(json.dumps(lock))
                with self.assertRaisesRegex(ValueError, "source"):
                    self.addons.load_lock(path)

    def test_container_build_returns_only_the_immutable_result_id(self) -> None:
        build_image = getattr(self.addons, "build_image", None)
        self.assertIsNotNone(build_image)
        assert build_image is not None
        image = "fixture@sha256:" + "a" * 64

        def build(command, **kwargs):
            self.assertEqual(command[:5], ["docker", "build", "--pull=false", "--network=host", "--build-arg"])
            self.assertIn("BASE_IMAGE=" + image, command)
            self.assertTrue(kwargs["check"])
            self.assertEqual(kwargs["timeout"], 900)
            pathlib.Path(command[command.index("--iidfile") + 1]).write_text("sha256:" + "b" * 64)

        with mock.patch.object(self.addons.subprocess, "run", side_effect=build):
            self.assertEqual(build_image("docker", image), "sha256:" + "b" * 64)
        for runtime, source in (("shell", image), ("docker", "fixture:latest")):
            with self.subTest(runtime=runtime, source=source), self.assertRaises(ValueError):
                build_image(runtime, source)

    def test_container_build_rejects_unverifiable_build_identity(self) -> None:
        def build(command, **_kwargs):
            pathlib.Path(command[command.index("--iidfile") + 1]).write_text("fixture:latest")

        with (
            mock.patch.object(self.addons.subprocess, "run", side_effect=build),
            self.assertRaisesRegex(ValueError, "image ID"),
        ):
            self.addons.build_image("docker", "fixture@sha256:" + "a" * 64)


if __name__ == "__main__":
    unittest.main()
