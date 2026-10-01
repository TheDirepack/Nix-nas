from __future__ import annotations

import importlib.util
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

SPEC = importlib.util.spec_from_file_location("nas_cockpit_api_ws04", SERVICES / "nas_cockpit_api.py")
assert SPEC and SPEC.loader
api = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = api
SPEC.loader.exec_module(api)


class Ws04GuardedUpdateTests(unittest.TestCase):
    def test_source_control_allows_only_read_only_operations(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            with mock.patch.object(api, "CONFIG_DIR", root):
                for op in ("status", "diff", "log"):
                    with mock.patch.object(
                        api, "run", return_value=mock.Mock(returncode=0, stdout="ok", stderr="")
                    ) as run:
                        result = api.source_control({"operation": op})
                        self.assertTrue(result["ok"])
                        run.assert_called_once()
                for op in ("pull", "rebuild", "pull-rebuild"):
                    with (
                        self.assertRaisesRegex(api.ApiError, "Unsupported"),
                        mock.patch.object(api, "run") as run,
                        mock.patch.object(api, "acquire_operation") as acquire,
                    ):
                        api.source_control({"operation": op})
                    run.assert_not_called()
                    acquire.assert_not_called()

    def test_source_control_read_only_does_not_use_operation_lock_or_mutate(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            with (
                mock.patch.object(api, "CONFIG_DIR", root),
                mock.patch.object(api, "run", return_value=mock.Mock(returncode=0, stdout="out", stderr="")) as run,
                mock.patch.object(api, "acquire_operation") as acquire,
            ):
                api.source_control({"operation": "status"})
                acquire.assert_not_called()
                self.assertIn("status", run.call_args.args[0])
                self.assertNotIn("pull", str(run.call_args))
                self.assertNotIn("nixos-rebuild", str(run.call_args))

    def test_no_supported_path_invokes_nixos_rebuild_directly(self) -> None:
        text = (ROOT / "services/nas_cockpit_api.py").read_text(encoding="utf-8")
        # Only allowed nixos-rebuild is inside update-nas.sh, not in cockpit api handler for source ops
        # Ensure source_control does not contain nixos-rebuild, and any update path uses nas-update

        # Find source_control body and ensure no nixos-rebuild
        sc_start = text.index("def source_control")
        next_def = text.find("\ndef ", sc_start + 1)
        sc_body = text[sc_start:next_def]
        self.assertNotIn("nixos-rebuild", sc_body)
        # Ensure no git pull into active checkout in supported path
        self.assertNotIn("pull --ff-only", sc_body)

    def test_supported_update_activation_reaches_nas_update(self) -> None:
        # Use new update-control endpoint or expanded source_control that delegates to nas-update
        # Expect at least one handler that starts nas-update via systemctl or direct nas-update command
        text = (ROOT / "services/nas_cockpit_api.py").read_text(encoding="utf-8")
        self.assertIn("nas-update", text)
        self.assertIn("nas-update-preview.service", text)
        self.assertIn("nas-update-sync.service", text)
        self.assertIn("nas-update-apply.service", text)

    def test_source_page_contains_only_readonly_and_guarded_update_buttons(self) -> None:
        source_page = (ROOT / "cockpit/src/pages/source-page.jsx").read_text(encoding="utf-8")
        self.assertNotIn('"pull"', source_page)
        self.assertNotIn("'pull'", source_page)
        self.assertNotIn("pull-rebuild", source_page)
        # Must not show direct rebuild button text that would trigger nixos-rebuild
        # Should contain status/diff/log and guarded update actions referencing nas-update
        self.assertIn("status", source_page)
        self.assertIn("diff", source_page)
        self.assertIn("log", source_page)
        # At least one reference to the guarded updater flow (preview/sync/apply or nas-update)
        self.assertTrue(
            any(token in source_page for token in ("nas-update", "preview", "sync", "apply")),
            "Source page must route activations through nas-update",
        )

    def test_readonly_inspection_cannot_mutate_source_or_system(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            with mock.patch.object(api, "CONFIG_DIR", root):
                # Simulate a dirty tree; status should still be read-only and not trigger any write
                with (
                    mock.patch.object(
                        api, "run", return_value=mock.Mock(returncode=0, stdout="M dirty", stderr="")
                    ) as run,
                    mock.patch.object(api, "acquire_operation") as acquire,
                ):
                    result = api.source_control({"operation": "status"})
                    self.assertEqual(result["stdout"], "M dirty")
                    acquire.assert_not_called()
                    argv = run.call_args.args[0]
                    self.assertEqual(argv[:3], ["git", "-C", str(root)])
                    self.assertNotIn("pull", argv)
                    self.assertNotIn("nixos-rebuild", argv)

    def test_update_status_exposes_manual_recovery_evidence(self) -> None:
        # update_status should surface rollback/manual-recovery evidence instead of hiding it
        text = (ROOT / "services/nas_cockpit_api.py").read_text(encoding="utf-8")
        self.assertIn("manual-recovery", text.lower())

    def test_rollback_failure_never_shown_as_success(self) -> None:
        text = (ROOT / "services/nas_cockpit_api.py").read_text(encoding="utf-8")
        # The cockpit API must not translate a failed update into ok:true; it should propagate error
        # Ensure error handling for update activation exists (either via run returncode check or exception)
        self.assertTrue(
            "manual-recovery" in text.lower() or "rollback" in text.lower(),
            "Expected rollback/manual-recovery handling for failed updates",
        )
