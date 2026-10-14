from __future__ import annotations

import ast
import importlib
import importlib.util
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest
from html.parser import HTMLParser

ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/authentik-csp"
PATCH = ROOT / "authentik/patches/authentik-csp.patch"


class NonceParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.inline = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "style" or (tag == "script" and "src" not in attributes):
            self.inline.append(attributes.get("nonce"))


class AuthentikCspPatchTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.tree = pathlib.Path(temporary.name)
        shutil.copytree(FIXTURES, self.tree, dirs_exist_ok=True)
        for source in self.tree.rglob("*.txt"):
            source.rename(source.with_suffix(""))
        if PATCH.exists():
            subprocess.run(
                [
                    "git",
                    "apply",
                    *[
                        f"--include={source.relative_to(self.tree)}"
                        for source in self.tree.rglob("*")
                        if source.is_file()
                    ],
                    str(PATCH),
                ],
                cwd=self.tree,
                check=True,
                capture_output=True,
            )
        self.settings_source = (self.tree / "authentik/root/settings.py").read_text()
        self.settings_tree = ast.parse(self.settings_source)

    def assignment(self, name) -> ast.expr:
        value = next(
            (
                node.value
                for node in self.settings_tree.body
                if isinstance(node, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)
            ),
            None,
        )
        assert value is not None, f"Authentik settings have no {name} assignment"
        return value

    def test_nonce_middleware_preserves_csrf_session_and_uploaded_file_policies(self):
        middleware = ast.literal_eval(self.assignment("MIDDLEWARE"))
        self.assertIn("csp.middleware.CSPMiddleware", middleware)
        self.assertIn("authentik.root.middleware.CsrfViewMiddleware", middleware)
        self.assertIn("authentik.stages.user_login.middleware.BoundSessionMiddleware", middleware)
        policy = self.assignment("CONTENT_SECURITY_POLICY")
        self.assertIsNotNone(policy, "Authentik does not enforce a nonce CSP")
        policy_source = ast.unparse(policy)
        self.assertNotIn("unsafe-inline", policy_source)
        self.assertNotIn("https:", policy_source)
        self.assertIn("NONCE", policy_source)
        self.assertNotIn("EXCLUDE_URL_PREFIXES", policy_source)
        packages = (ROOT / "modules/nas/internal/account-tools.nix").read_text()
        self.assertIn("authentik-csp.patch", packages)
        self.assertIn("django-csp", packages)
        proxy = (ROOT / "modules/nas/config/reverse-proxy.nix").read_text()
        self.assertNotIn("header_down Content-Security-Policy", proxy)

    def test_every_server_authentication_template_nonces_its_inline_script_and_style(self):
        templates = [source for source in self.tree.rglob("*.html") if "/email/" not in str(source)]
        self.assertGreater(len(templates), 8)
        for source in templates:
            for tag in re.findall(r"<(?:script|style)\b[^>]*>", source.read_text()):
                if "src=" not in tag:
                    self.assertIn('nonce="{{ request.csp_nonce }}"', tag, f"untrusted inline tag: {source}: {tag}")
        skeleton = (self.tree / "authentik/core/templates/base/skeleton.html").read_text()
        self.assertIn("window.litNonce", skeleton)
        self.assertLess(skeleton.index("window.litNonce"), skeleton.index("{% block head_before %}"))

    def test_frontend_preserves_dynamic_styles_without_inline_attributes(self):
        sources = list(self.tree.rglob("*.ts"))
        self.assertEqual(len(sources), 5)
        for source in sources:
            text = source.read_text()
            self.assertNotRegex(text, r"(?<![\w.-])style=", str(source))
            self.assertNotIn("styleMap", text, str(source))
            for tag in re.findall(r"<style\b[^>]*>", text):
                self.assertIn("nonce=${window.litNonce}", tag)
        progress = (self.tree / "web/src/elements/ak-progress-bar.ts").read_text()
        self.assertIn(".style=", progress)
        self.assertIn("Math.min(this.value, 100)", progress)
        self.assertIn("aria-valuenow", progress)
        grid = (self.tree / "web/src/user/LibraryPage/ApplicationList.ts").read_text()
        self.assertIn("--app-list-column-count", grid)
        self.assertIn("columnCount", grid)

    @unittest.skipUnless(importlib.util.find_spec("csp"), "requires the Nix test shell's django-csp")
    def test_real_middleware_renders_unique_nonces_and_preserves_stricter_response_csp(self):
        django = importlib.import_module("django")
        settings = importlib.import_module("django.conf").settings
        if not settings.configured:
            settings.configure(
                SECRET_KEY="owned-csp-fixture", USE_I18N=False, INSTALLED_APPS=[], STATIC_URL="/identity/static/"
            )
            django.setup()
        constants = importlib.import_module("csp.constants")
        namespace = {name: getattr(constants, name) for name in ("SELF", "NONE", "NONCE")}
        policy = self.assignment("CONTENT_SECURITY_POLICY")
        self.assertIsNotNone(policy, "Authentik does not enforce a nonce CSP")
        directives = eval(compile(ast.Expression(policy), "authentik-csp-policy", "eval"), namespace)
        middleware_class = importlib.import_module("csp.middleware").CSPMiddleware
        request_factory = importlib.import_module("django.test").RequestFactory()
        override_settings = importlib.import_module("django.test").override_settings
        http_response = importlib.import_module("django.http").HttpResponse
        templates = {
            source.relative_to(source.parents[1]).as_posix(): source.read_text()
            for source in self.tree.rglob("*.html")
            if source.parent.name in ("base", "login", "if")
        }
        template_module = importlib.import_module("django.template")
        tags = template_module.Library()
        tags.simple_tag(lambda path: "/identity/static/" + path.replace("%v", "2025.12.6"), name="versioned_script")
        engine = template_module.Engine(
            loaders=[("django.template.loaders.locmem.Loader", templates)],
            libraries={"i18n": "django.templatetags.i18n", "static": "django.templatetags.static"},
        )
        engine.template_libraries["authentik_core"] = tags
        nonces = set()
        with override_settings(CONTENT_SECURITY_POLICY=directives):
            for template_name in ("if/flow.html", "login/base_full.html", "if/user.html", "if/admin.html"):
                for _ in range(2):
                    request = request_factory.get("/identity/if/flow/default-authentication/")
                    middleware = middleware_class(lambda request: http_response())
                    middleware.process_request(request)
                    rendered = engine.get_template(template_name).render(
                        template_module.Context(
                            {
                                "request": request,
                                "ui_theme": "auto",
                                "flow": {"compatibility_mode": True},
                                "brand": {"branding_title": "owned fixture"},
                            }
                        )
                    )
                    response = middleware.process_response(request, http_response(rendered))
                    parser = NonceParser()
                    parser.feed(rendered)
                    self.assertGreater(len(parser.inline), 2)
                    nonce = str(request.csp_nonce)
                    self.assertEqual(set(parser.inline), {nonce})
                    self.assertNotIn(nonce, nonces)
                    nonces.add(nonce)
                    self.assertIn(f"'nonce-{nonce}'", response["Content-Security-Policy"])
                    self.assertNotIn("unsafe-inline", response["Content-Security-Policy"])
            request = request_factory.get("/identity/media/uploaded.html")
            middleware.process_request(request)
            response = http_response()
            response["Content-Security-Policy"] = "default-src 'none'; sandbox"
            self.assertEqual(
                middleware.process_response(request, response)["Content-Security-Policy"], "default-src 'none'; sandbox"
            )


if __name__ == "__main__":
    unittest.main()
