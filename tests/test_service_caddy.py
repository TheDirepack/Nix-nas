from __future__ import annotations

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
                    with self.assertRaisesRegex(caddy.CaddyError, "Invalid hostname|exposure value is required"):
                        caddy._validate_exposure({"type": exposure_type, "value": value})

    def test_port_accepts_integer_and_string_forms(self):
        for value in (80, "8080", 65535, "1", 443):
            with self.subTest(value=value):
                self.assertIsNone(caddy._validate_exposure({"type": "port", "value": value}))

    def test_port_rejects_out_of_range_and_non_numeric(self):
        for value in (0, -1, 65536, "99999", "abc", "80.5", "12x"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(caddy.CaddyError, "Invalid port"):
                    caddy._validate_exposure({"type": "port", "value": value})

    def test_path_requires_leading_slash(self):
        self.assertIsNone(caddy._validate_exposure({"type": "path", "value": "/photos"}))
        self.assertIsNone(caddy._validate_exposure({"type": "path", "value": "/"}))
        with self.assertRaisesRegex(caddy.CaddyError, "Invalid path"):
            caddy._validate_exposure({"type": "path", "value": "photos"})
        with self.assertRaisesRegex(caddy.CaddyError, "Invalid path|exposure value is required"):
            caddy._validate_exposure({"type": "path", "value": ""})

    def test_none_and_absent_types_are_rejected(self):
        with self.assertRaisesRegex(caddy.CaddyError, "mandatory|Invalid exposure|must not produce"):
            caddy._validate_exposure({"type": "none"})
        with self.assertRaisesRegex(caddy.CaddyError, "mandatory|Invalid exposure|must not produce"):
            caddy._validate_exposure({"type": None})
        with self.assertRaisesRegex(caddy.CaddyError, "mandatory|Invalid exposure|must not produce"):
            caddy._validate_exposure({})

    def test_unknown_exposure_type_is_rejected(self):
        with self.assertRaisesRegex(caddy.CaddyError, "Invalid exposure"):
            caddy._validate_exposure({"type": "grpc"})
        with self.assertRaisesRegex(caddy.CaddyError, "Invalid exposure"):
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
                    "auth": {"mode": "public"},
                }
            }
        }
        fragment = caddy.generate_caddy_fragment(effective)
        route = fragment["routes"][0]
        self.assertEqual(route["id"], "nas-managed-photos-web")
        self.assertEqual(route["host"], "photos.local")
        self.assertEqual(route["targetPort"], 2283)

    def test_https_and_missing_transport_endpoints_are_handled(self):
        effective = {
            "endpoints": {
                "a": {
                    "transport": "https",
                    "targetPort": 443,
                    "exposure": {"type": "dns", "value": "a.example"},
                    "auth": {"mode": "public"},
                },
                "b": {
                    "targetPort": 9092,
                    "exposure": {"type": "hostname", "value": "b.example"},
                    "auth": {"mode": "public"},
                },
            }
        }
        fragment = caddy.generate_caddy_fragment(effective)
        self.assertEqual(len(fragment["routes"]), 2)

    def test_non_http_transports_are_skipped(self):
        effective = {
            "endpoints": {
                "tcp": {
                    "transport": "tcp",
                    "targetPort": 3306,
                    "exposure": {"type": "hostname", "value": "db.local"},
                    "auth": {"mode": "public"},
                },
                "udp": {
                    "transport": "udp",
                    "targetPort": 53,
                    "exposure": {"type": "hostname", "value": "dns.local"},
                    "auth": {"mode": "public"},
                },
            }
        }
        self.assertEqual(caddy.generate_caddy_fragment(effective), {"routes": []})

    def test_none_exposure_is_rejected(self):
        effective = {
            "endpoints": {
                "web": {"transport": "http", "targetPort": 80, "exposure": {"type": "none"}, "auth": {"mode": "public"}}
            }
        }
        with self.assertRaisesRegex(caddy.CaddyError, "none|mandatory"):
            caddy.generate_caddy_fragment(effective)

    def test_invalid_exposure_is_rejected(self):
        effective = {
            "endpoints": {
                "web": {
                    "transport": "http",
                    "targetPort": 80,
                    "exposure": {"type": "hostname", "value": "bad host"},
                    "auth": {"mode": "public"},
                }
            }
        }
        with self.assertRaisesRegex(caddy.CaddyError, "Invalid hostname"):
            caddy.generate_caddy_fragment(effective)

    def test_missing_exposure_is_rejected(self):
        effective = {"endpoints": {"web": {"transport": "http", "targetPort": 80, "auth": {"mode": "public"}}}}
        with self.assertRaisesRegex(caddy.CaddyError, "exposure is mandatory"):
            caddy.generate_caddy_fragment(effective)

    def test_missing_auth_is_rejected(self):
        effective = {
            "endpoints": {
                "web": {"transport": "http", "targetPort": 80, "exposure": {"type": "hostname", "value": "app.local"}}
            }
        }
        with self.assertRaisesRegex(caddy.CaddyError, "auth is mandatory|unknown auth"):
            caddy.generate_caddy_fragment(effective)

    def test_unknown_auth_mode_is_rejected(self):
        effective = {
            "endpoints": {
                "web": {
                    "transport": "http",
                    "targetPort": 80,
                    "exposure": {"type": "hostname", "value": "app.local"},
                    "auth": {"mode": "foward-auth"},
                }
            }
        }
        with self.assertRaisesRegex(caddy.CaddyError, "unknown auth"):
            caddy.generate_caddy_fragment(effective)

    def test_builtins_with_public_path_are_skipped(self):
        effective = {
            "endpoints": {
                "cockpit": {
                    "transport": "http",
                    "targetPort": 9090,
                    "publicPath": "/console/",
                    "exposure": {"type": "path", "value": "/console/"},
                    "auth": {"mode": "public"},
                }
            }
        }
        self.assertEqual(caddy.generate_caddy_fragment(effective), {"routes": []})

    def test_path_exposure_generates_caddyfile_with_wildcard(self):
        effective = {
            "endpoints": {
                "photo-app": {
                    "transport": "http",
                    "targetPort": 8080,
                    "exposure": {"type": "path", "value": "/photos"},
                    "auth": {"mode": "public"},
                }
            }
        }
        fragment = caddy.generate_caddy_fragment(effective)
        self.assertEqual(fragment["routes"][0]["path"], "/photos")
        self.assertEqual(fragment["routes"][0]["targetPort"], 8080)
        self.assertTrue(fragment["routes"][0]["path_prefix"])
        caddyfile = caddy.generate_caddyfile(effective)
        self.assertIn("/photos", caddyfile)
        self.assertIn("reverse_proxy 127.0.0.1:8080", caddyfile)

    def test_port_exposure_generates_caddyfile(self):
        effective = {
            "endpoints": {
                "proxy": {
                    "transport": "http",
                    "targetPort": 3000,
                    "exposure": {"type": "port", "value": "8443"},
                    "auth": {"mode": "public"},
                }
            }
        }
        fragment = caddy.generate_caddy_fragment(effective)
        self.assertEqual(fragment["routes"][0]["port"], 8443)

    def test_forward_auth_generates_gate_in_caddyfile(self):
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
        fragment = caddy.generate_caddy_fragment(effective)
        self.assertEqual(fragment["routes"][0]["auth"]["mode"], "forward-auth")
        self.assertEqual(fragment["routes"][0]["key"], "app:web")
        caddyfile = caddy.generate_caddyfile(effective)
        self.assertIn("forward_auth", caddyfile)
        self.assertIn("app:web", caddyfile)
        self.assertIn(
            "request_header Remote-Groups {http.request.header.X-Authentik-Groups}",
            caddyfile,
        )
        self.assertIn(
            "header_up Remote-Groups {http.request.header.X-Authentik-Groups}",
            caddyfile,
        )
        self.assertNotIn("X-Authentik-Groups>Remote-Groups", caddyfile)

    def test_public_has_no_forward_auth(self):
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
        caddyfile = caddy.generate_caddyfile(effective)
        self.assertNotIn("forward_auth", caddyfile)

    def test_routes_are_sorted_by_id(self):
        effective = {
            "endpoints": {
                "zebra": {
                    "transport": "http",
                    "targetPort": 1,
                    "exposure": {"type": "hostname", "value": "z.local"},
                    "auth": {"mode": "public"},
                },
                "apple": {
                    "transport": "http",
                    "targetPort": 2,
                    "exposure": {"type": "hostname", "value": "a.local"},
                    "auth": {"mode": "public"},
                },
            }
        }
        fragment = caddy.generate_caddy_fragment(effective)
        self.assertEqual([route["id"] for route in fragment["routes"]], ["nas-managed-apple", "nas-managed-zebra"])

    def test_colon_in_key_becomes_dash_in_route_id(self):
        effective = {
            "endpoints": {
                "photo:web:2": {
                    "transport": "http",
                    "targetPort": 80,
                    "exposure": {"type": "hostname", "value": "x.local"},
                    "auth": {"mode": "public"},
                }
            }
        }
        fragment = caddy.generate_caddy_fragment(effective)
        self.assertEqual(fragment["routes"][0]["id"], "nas-managed-photo-web-2")

    def test_duplicate_host_exposure_raises_conflict(self):
        effective = {
            "endpoints": {
                "a": {
                    "transport": "http",
                    "targetPort": 1,
                    "exposure": {"type": "hostname", "value": "same.local"},
                    "auth": {"mode": "public"},
                },
                "b": {
                    "transport": "http",
                    "targetPort": 2,
                    "exposure": {"type": "hostname", "value": "same.local"},
                    "auth": {"mode": "public"},
                },
            }
        }
        with self.assertRaisesRegex(caddy.CaddyError, "Duplicate exposure"):
            caddy.generate_caddy_fragment(effective)

    def test_duplicate_path_exposure_raises_conflict(self):
        effective = {
            "endpoints": {
                "a": {
                    "transport": "http",
                    "targetPort": 1,
                    "exposure": {"type": "path", "value": "/shared"},
                    "auth": {"mode": "public"},
                },
                "b": {
                    "transport": "http",
                    "targetPort": 2,
                    "exposure": {"type": "path", "value": "/shared"},
                    "auth": {"mode": "public"},
                },
            }
        }
        with self.assertRaisesRegex(caddy.CaddyError, "Duplicate exposure"):
            caddy.generate_caddy_fragment(effective)

    def test_distinct_exposures_do_not_conflict(self):
        effective = {
            "endpoints": {
                "a": {
                    "transport": "http",
                    "targetPort": 1,
                    "exposure": {"type": "hostname", "value": "a.local"},
                    "auth": {"mode": "public"},
                },
                "b": {
                    "transport": "http",
                    "targetPort": 2,
                    "exposure": {"type": "hostname", "value": "b.local"},
                    "auth": {"mode": "public"},
                },
            }
        }
        fragment = caddy.generate_caddy_fragment(effective)
        self.assertEqual(len(fragment["routes"]), 2)

    def test_catch_all_without_matcher_is_rejected(self):
        effective = {
            "endpoints": {
                "bad": {
                    "transport": "http",
                    "targetPort": 80,
                    "exposure": {"type": "hostname", "value": ""},
                    "auth": {"mode": "public"},
                },
            }
        }
        with self.assertRaisesRegex(caddy.CaddyError, "Invalid hostname|exposure value"):
            caddy.generate_caddy_fragment(effective)


class WriteFragmentTests(unittest.TestCase):
    def test_custom_path_creates_parent_dirs_and_writes_caddyfile(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = pathlib.Path(temporary) / "nested" / "caddy-managed.conf"
            with mock.patch.object(msvc, "effective_registry", return_value={"endpoints": {}}):
                with mock.patch.dict("os.environ", {"NAS_SKIP_CADDY_VALIDATE": "1", "NAS_SKIP_CADDY_RELOAD": "1"}):
                    fragment = caddy.write_caddy_fragment(target)
            self.assertTrue(target.exists())
            self.assertEqual(fragment, {"routes": []})

    def test_custom_path_writes_caddyfile_content(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = pathlib.Path(temporary) / "caddy-managed.conf"
            effective = {
                "endpoints": {
                    "app:web": {
                        "transport": "http",
                        "targetPort": 8080,
                        "exposure": {"type": "hostname", "value": "app.local"},
                        "auth": {"mode": "public"},
                    }
                }
            }
            with mock.patch.object(msvc, "effective_registry", return_value=effective):
                with mock.patch.dict("os.environ", {"NAS_SKIP_CADDY_VALIDATE": "1", "NAS_SKIP_CADDY_RELOAD": "1"}):
                    fragment = caddy.write_caddy_fragment(target)
            self.assertEqual(fragment["routes"][0]["host"], "app.local")
            self.assertEqual(fragment["routes"][0]["targetPort"], 8080)
            content = target.read_text(encoding="utf-8")
            self.assertIn("app.local", content)
            self.assertIn("8080", content)

    def test_default_path_uses_run_control_location(self):
        import inspect

        src = inspect.getsource(caddy.write_caddy_fragment)
        self.assertIn("/run/nas-control/caddy-managed.conf", src)


if __name__ == "__main__":
    unittest.main()
