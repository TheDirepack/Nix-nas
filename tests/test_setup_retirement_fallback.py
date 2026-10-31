from __future__ import annotations

import email.message
import os
import pathlib
import tempfile
import unittest
import urllib.error
from unittest import mock

import nas_setup as setup


class SetupRetirementFallbackTests(unittest.TestCase):
    def remove(self, statuses: list[int | OSError], *, error: str | None = None) -> dict | None:
        responses = []
        for status in statuses:
            if isinstance(status, OSError):
                responses.append(status)
            elif status >= 400:
                exception = urllib.error.HTTPError("http://fixture", status, "fixture", email.message.Message(), None)
                self.addCleanup(exception.close)
                responses.append(exception)
            else:
                response = mock.MagicMock()
                response.__enter__.return_value.status = status
                responses.append(response)
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            token = root / "token"
            token.write_text("fixture-token\n")
            blueprint = root / "setup.yaml"
            blueprint.write_text("fixture")
            with (
                mock.patch.dict(os.environ, {"NAS_AUTHENTIK_BOOTSTRAP_TOKEN_FILE": str(token)}),
                mock.patch.object(setup, "SETUP_BLUEPRINT_PATH", blueprint),
                mock.patch("urllib.request.urlopen", side_effect=responses) as urlopen,
            ):
                if error:
                    with self.assertRaisesRegex(setup.SetupError, error):
                        setup._remove_setup_application()
                    result = None
                else:
                    result = setup._remove_setup_application()
            self.assertFalse(blueprint.exists())
        self.assertEqual(urlopen.call_count, len(statuses))
        expected = [
            "http://127.0.0.1:9000/identity/api/v3/core/applications/nas-setup/",
            "http://127.0.0.1:9000/api/v3/core/applications/nas-setup/",
        ]
        for call, url in zip(urlopen.call_args_list, expected, strict=False):
            request = call.args[0]
            self.assertEqual(request.full_url, url)
            self.assertEqual(request.get_method(), "DELETE")
            self.assertEqual(request.get_header("Authorization"), "Bearer fixture-token")
            self.assertEqual(call.kwargs, {"timeout": 5})
        return result

    def test_first_prefix_not_found_tries_bare_prefix(self) -> None:
        self.assertEqual(self.remove([404, 204]), {"removed": True, "slug": "nas-setup"})

    def test_absence_requires_both_prefixes_to_return_not_found(self) -> None:
        self.assertEqual(self.remove([404, 404]), {"removed": False, "reason": "not-found"})

    def test_forbidden_then_not_found_does_not_authorize_retirement(self) -> None:
        self.remove([403, 404], error="HTTP 403")

    def test_not_found_then_forbidden_does_not_authorize_retirement(self) -> None:
        self.remove([404, 403], error="HTTP 403")

    def test_transport_failure_is_not_masked_by_not_found(self) -> None:
        self.remove([OSError("fixture offline"), 404], error="fixture offline")

    def test_unaccepted_response_is_not_masked_by_not_found(self) -> None:
        self.remove([203, 404], error="HTTP 203")

    def test_success_still_returns_without_another_request(self) -> None:
        self.assertEqual(self.remove([204]), {"removed": True, "slug": "nas-setup"})
