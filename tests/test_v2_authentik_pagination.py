from __future__ import annotations

import pathlib
import sys
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlsplit

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_authentik as authentik  # noqa: E402


class V2AuthentikPaginationTests(unittest.TestCase):
    def test_route_app_reconcile_follows_paginated_collection_results(self) -> None:
        effective = {
            "schemaVersion": 3,
            "derived": {
                "routes": [
                    {
                        "service": "media",
                        "route": "web",
                        "authMode": "identity",
                        "exposure": {"type": "hostname", "hostnames": ["media.nas.local"], "path": "/"},
                        "target": {"type": "http", "host": "127.0.0.1", "port": 8096},
                        "portal": {"visible": True, "title": "Media Library"},
                    }
                ]
            },
        }
        writes: list[tuple[str, str, dict | None]] = []

        page_two = {
            "/providers/proxy/": [
                {"pk": 101, "name": "Media Library"},
            ],
            "/core/applications/": [
                {"slug": "v2-media-web", "provider": 101},
            ],
            "/outposts/instances/": [
                {
                    "pk": 303,
                    "managed": "goauthentik.io/outposts/embedded",
                    "providers": [],
                    "config": {},
                },
            ],
            "/flows/instances/": [
                {"pk": 401, "slug": "default-authentication-flow"},
                {"pk": 402, "slug": "default-provider-authorization-implicit-consent"},
                {"pk": 403, "slug": "default-invalidation-flow"},
            ],
        }

        def request(
            *,
            url: str,
            token: str,
            method: str = "GET",
            body: dict | None = None,
            timeout: float = 15.0,
        ):
            del token, timeout
            parsed = urlsplit(url)
            if method == "GET":
                matching_path = next(path for path in page_two if parsed.path.endswith(path))
                page = int(parse_qs(parsed.query).get("page", ["1"])[0])
                if page == 1:
                    return {"pagination": {"next": 2}, "results": []}
                self.assertEqual(page, 2)
                return {"pagination": {"next": 0}, "results": page_two[matching_path]}

            writes.append((method, url, body))
            if "/providers/proxy/101/" in parsed.path:
                return {"pk": 101, "name": "Media Library"}
            return body or {}

        with mock.patch.object(authentik, "_request_json", side_effect=request):
            result = authentik.reconcile_route_apps(
                effective,
                token="token-value",
                authentik_url="http://127.0.0.1:9000/identity",
                public_host="nas.local",
            )

        self.assertEqual(result["created"], [])
        self.assertEqual(result["updated"], ["v2-media-web"])
        self.assertFalse(any(method == "POST" for method, _url, _body in writes))
        self.assertTrue(any("/providers/proxy/101/" in url for method, url, _body in writes if method == "PATCH"))
        self.assertTrue(
            any("/core/applications/v2-media-web/" in url for method, url, _body in writes if method == "PATCH")
        )
        self.assertTrue(any("/outposts/instances/303/" in url for method, url, _body in writes if method == "PATCH"))


if __name__ == "__main__":
    unittest.main()
