from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services"))

import nas_managed_service as msvc
import nas_service_caddy as caddy


class ValidateExposureTests(unittest.TestCase):
    def test_hostname_and_dns_accept_valid_names(self):
        for exposure_type in ("hostname", "dns"):
            for value in ("photos.local", "photos", "a-b.c.example", "PX-1"):
                with self.subTest(exposure_type=exposure_type, value=value):
                    self.assertIsNone(caddy._validate_exposure({"type": exposure_type, "value": value}))

    def test_hostname_and_dns_reject_invalid_names(self):
        for exposure_type in ("hostname", "dns"):
            for value in ("bad host", "has space.local", "under_score", "", "x" * 70 + ".local", "a" * 64):
                with self.subTest(exposure_type=exposure_type, value=value):
                    with self.assertRaisesRegex(ValueError, "Invalid hostname"):
                        caddy._validate_exposure({"type": exposure_type, "value": value})

    def test_port_accepts_integer_and_string_forms(self):
        for value in (80, "8080", 65535, "1"):
            with self.subTest(value=value):
                self.assertIsNone(caddy._validate_exposure({"type": "port", "value": value}))

    def test_port_rejects_out_of_range_and_non_numeric(self):
        for value in (0, -1, 65536, "99999", "abc", "80.5", "12x"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "Invalid port"):
                    caddy._validate_exposure({"type": "port", "value": value})

    def test_path_requires_leading_slash(self):
        self.assertIsNone(caddy._validate_exposure({"type": "path", "value": "/photos"}))
        self.assertIsNone(caddy._validate_exposure({"type": "path", "value": "/"}))
        with self.assertRaisesRegex(ValueError, "Invalid path"):
            caddy._validate_exposure({"type": "path", "value": "photos"})
        with self.assertRaisesRegex(ValueError, "Invalid path"):
            caddy._validate_exposure({"type": "path", "value": ""})

    def test_none_and_absent_types_are_accepted(self):
        self.assertIsNone(caddy._validate_exposure({"type": "none"}))
        self.assertIsNone(caddy._validate_exposure({"type": None}))
        self.assertIsNone(caddy._validate_exposure({}))

    def test_unknown_exposure_type_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Invalid exposure type"):
            caddy._validate_exposure({"type": "grpc"})
        with self.assertRaisesRegex(ValueError, "Invalid exposure type"):
            caddy._validate_exposure({"type": "tcp"})


class GenerateFragmentTests(unittest.TestCase):
    def test_empty_effective_yields_no_routes(self):
        self.assertEqual(caddy.generate_caddy_fragment({"schemaVersion": 2, "endpoints": {}}), {"routes": []})

    def test_effective_none_falls_back_to_registry(self):
        with mock.patch.object(msvc, "effective_registry", return_value={"endpoints": {}}) as registry:
            self.assertEqual(caddy.generate_caddy_fragment(None), {"routes": []})
        registry.assert_called_once_with()

    def test_http_endpoint_with_hostname_exposure(self):
        effective = {
            "endpoints": {
                "photos:web": {
                    "transport": "http",
                    "targetPort": 2283,
                    "exposure": {"type": "hostname", "value": "photos.local"},
                }
            }
        }
        fragment = caddy.generate_caddy_fragment(effective)
        route = fragment["routes"][0]
        self.assertEqual(route["id"], "nas-managed-photos-web")
        self.assertEqual(route["match"], [{"host": ["photos.local"]}])
        self.assertEqual(route["handle"], [{"handler": "reverse_proxy", "upstreams": [{"dial": "127.0.0.1:2283"}]}])

    def test_https_and_missing_transport_endpoints_are_handled(self):
        effective = {
            "endpoints": {
                "a": {"transport": "https", "targetPort": 443, "exposure": {"type": "dns", "value": "a.example"}},
                "b": {"targetPort": 9092, "exposure": {"type": "hostname", "value": "b.example"}},
            }
        }
        fragment = caddy.generate_caddy_fragment(effective)
        self.assertEqual(len(fragment["routes"]), 2)
        hosts = [route["match"][0]["host"][0] for route in fragment["routes"]]
        self.assertEqual(hosts, ["a.example", "b.example"])

    def test_non_http_transports_are_skipped(self):
        effective = {
            "endpoints": {
                "tcp": {"transport": "tcp", "targetPort": 3306, "exposure": {"type": "hostname", "value": "db.local"}},
                "udp": {"transport": "udp", "targetPort": 53, "exposure": {"type": "hostname", "value": "dns.local"}},
            }
        }
        self.assertEqual(caddy.generate_caddy_fragment(effective), {"routes": []})

    def test_none_exposure_is_skipped(self):
        effective = {"endpoints": {"web": {"transport": "http", "targetPort": 80, "exposure": {"type": "none"}}}}
        self.assertEqual(caddy.generate_caddy_fragment(effective), {"routes": []})

    def test_invalid_exposure_is_skipped(self):
        effective = {"endpoints": {"web": {"transport": "http", "targetPort": 80, "exposure": {"type": "hostname", "value": "bad host"}}}}
        self.assertEqual(caddy.generate_caddy_fragment(effective), {"routes": []})

    def test_builtins_with_public_path_are_skipped(self):
        effective = {
            "endpoints": {
                "cockpit": {
                    "transport": "http",
                    "targetPort": 9090,
                    "publicPath": "/console/",
                    "exposure": {"type": "path", "value": "/console/"},
                }
            }
        }
        self.assertEqual(caddy.generate_caddy_fragment(effective), {"routes": []})

    def test_path_exposure_matches_on_path(self):
        effective = {
            "endpoints": {
                "photo-app": {
                    "transport": "http",
                    "targetPort": 8080,
                    "exposure": {"type": "path", "value": "/photos"},
                }
            }
        }
        fragment = caddy.generate_caddy_fragment(effective)
        self.assertEqual(fragment["routes"][0]["match"], [{"path": ["/photos"]}])

    def test_port_exposure_matches_on_port(self):
        effective = {
            "endpoints": {
                "proxy": {
                    "transport": "http",
                    "targetPort": 3000,
                    "exposure": {"type": "port", "value": "8443"},
                }
            }
        }
        fragment = caddy.generate_caddy_fragment(effective)
        self.assertEqual(fragment["routes"][0]["match"], [{"port": [8443]}])

    def test_forward_auth_handler_is_inserted_first(self):
        effective = {
            "endpoints": {
                "app:web": {
                    "transport": "http",
                    "targetPort": 8000,
                    "exposure": {"type": "hostname", "value": "app.local"},
                    "auth": {"mode": "forward-auth", "allow": "groups", "groups": ["family"]},
                }
            }
        }
        route = caddy.generate_caddy_fragment(effective)["routes"][0]
        self.assertEqual(route["handle"][0], {"handler": "forward_auth", "uri": "/auth", "copy_headers": {"Remote-User": "{http.auth.user.id}"}})
        self.assertEqual(len(route["handle"]), 2)

    def test_no_forward_auth_keeps_single_handle(self):
        effective = {
            "endpoints": {
                "app:web": {
                    "transport": "http",
                    "targetPort": 8000,
                    "exposure": {"type": "hostname", "value": "app.local"},
                    "auth": {"mode": "public"},
                }
            }
        }
        route = caddy.generate_caddy_fragment(effective)["routes"][0]
        self.assertEqual(len(route["handle"]), 1)

    def test_routes_are_sorted_by_id(self):
        effective = {
            "endpoints": {
                "zebra": {"transport": "http", "targetPort": 1, "exposure": {"type": "hostname", "value": "z.local"}},
                "apple": {"transport": "http", "targetPort": 2, "exposure": {"type": "hostname", "value": "a.local"}},
            }
        }
        fragment = caddy.generate_caddy_fragment(effective)
        self.assertEqual([route["id"] for route in fragment["routes"]], ["nas-managed-apple", "nas-managed-zebra"])

    def test_colon_in_key_becomes_dash_in_route_id(self):
        effective = {
            "endpoints": {
                "photo:web:2": {"transport": "http", "targetPort": 80, "exposure": {"type": "hostname", "value": "x.local"}}
            }
        }
        fragment = caddy.generate_caddy_fragment(effective)
        self.assertEqual(fragment["routes"][0]["id"], "nas-managed-photo-web-2")

    def test_duplicate_host_exposure_raises_conflict(self):
        effective = {
            "endpoints": {
                "a": {"transport": "http", "targetPort": 1, "exposure": {"type": "hostname", "value": "same.local"}},
                "b": {"transport": "http", "targetPort": 2, "exposure": {"type": "hostname", "value": "same.local"}},
            }
        }
        with self.assertRaisesRegex(ValueError, "Duplicate exposure"):
            caddy.generate_caddy_fragment(effective)

    def test_duplicate_path_exposure_raises_conflict(self):
        effective = {
            "endpoints": {
                "a": {"transport": "http", "targetPort": 1, "exposure": {"type": "path", "value": "/shared"}},
                "b": {"transport": "http", "targetPort": 2, "exposure": {"type": "path", "value": "/shared"}},
            }
        }
        with self.assertRaisesRegex(ValueError, "Duplicate exposure"):
            caddy.generate_caddy_fragment(effective)

    def test_distinct_exposures_do_not_conflict(self):
        effective = {
            "endpoints": {
                "a": {"transport": "http", "targetPort": 1, "exposure": {"type": "hostname", "value": "a.local"}},
                "b": {"transport": "http", "targetPort": 2, "exposure": {"type": "hostname", "value": "b.local"}},
            }
        }
        fragment = caddy.generate_caddy_fragment(effective)
        self.assertEqual(len(fragment["routes"]), 2)


class WriteFragmentTests(unittest.TestCase):
    def test_custom_path_creates_parent_dirs_and_writes_json(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = pathlib.Path(temporary) / "nested" / "fragment.json"
            with mock.patch.object(msvc, "effective_registry", return_value={"endpoints": {}}):
                fragment = caddy.write_caddy_fragment(target)
            self.assertTrue(target.exists())
            self.assertEqual(json.loads(target.read_text(encoding="utf-8")), {"routes": []})
            self.assertEqual(fragment, {"routes": []})

    def test_custom_path_writes_full_fragment_content(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = pathlib.Path(temporary) / "fragment.json"
            effective = {
                "endpoints": {
                    "app:web": {
                        "transport": "http",
                        "targetPort": 8080,
                        "exposure": {"type": "hostname", "value": "app.local"},
                    }
                }
            }
            with mock.patch.object(msvc, "effective_registry", return_value=effective):
                caddy.write_caddy_fragment(target)
            decoded = json.loads(target.read_text(encoding="utf-8"))
            self.assertEqual(decoded["routes"][0]["match"], [{"host": ["app.local"]}])

    def test_default_path_uses_run_control_location(self):
        with (
            mock.patch.object(msvc, "effective_registry", return_value={"endpoints": {}}),
            mock.patch("nas_service_caddy.pathlib.Path") as path_class,
        ):
            caddy.write_caddy_fragment()
        path_class.assert_called_once_with("/run/nas-control/caddy-managed.json")
        instance = path_class.return_value
        instance.parent.mkdir.assert_called_once_with(parents=True, exist_ok=True)
        instance.write_text.assert_called_once_with('{\n  "routes": []\n}\n', encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
