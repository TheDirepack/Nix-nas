#!/usr/bin/env python3
"""Validate the small, stable repository structure contract."""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]

REQUIRED_FILES = {
    "AGENTS.md",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "README.md",
    "SECURITY.md",
    "VERSION",
    "flake.nix",
    "flake.lock",
    "hardware-configuration.nix",
    "local.nix",
    "modules/nas/internal/default.nix",
    "modules/nas/internal/base.nix",
    "modules/nas/internal/feature-catalog.nix",
    "modules/nas/internal/service-registry.nix",
    "modules/nas/internal/caddy-helpers.nix",
    "modules/nas/internal/account-tools.nix",
    "modules/nas/internal/documentation-tools.nix",
    "modules/profiles/core-storage.nix",
    "modules/profiles/identity-sharing.nix",
    "modules/profiles/observability.nix",
    "modules/profiles/virtualization.nix",
    "modules/profiles/local-ai.nix",
    "modules/profiles/all.nix",
    "docs/book.toml",
    "docs/src/SUMMARY.md",
    "docs/development/README.md",
    "docs/development/code-map.md",
    "docs/development/invariants.md",
    "docs/development/known-risks.md",
    "docs/development/combined-review-remediation.md",
    "docs/development/testing.md",
    "docs/development/dependencies.md",
    "docs/development/history.md",
    "docs/development/external-validation.md",
    "docs/operator/operations.md",
    "docs/operator/recovery.md",
    "policy/mkforce-allowlist.json",
    "pyproject.toml",
    ".coveragerc",
    ".semgrep.yml",
    "scripts/check-coverage.py",
    "scripts/fuzz.py",
    "scripts/fuzz-executables.py",
    "scripts/run-fuzz.py",
    "scripts/run-matrix-fuzz.py",
    "scripts/run-security-tests.py",
    "scripts/test-matrix.py",
    "scripts/run-unit-tests.py",
    "scripts/security-static-scan.py",
    "scripts/validate-test-inventory.py",
    "scripts/check-mkforce.py",
    "scripts/check-version.py",
    "scripts/package-release.sh",
    "schemas/feature-catalog.schema.json",
    "schemas/state-bundle.schema.json",
    "schemas/service-registry.schema.json",
    "services/nas_common.py",
    "services/nas_setup.py",
    "services/nas_state.py",
    "services/nas_setup_config.py",
    "services/nas_identity_sync.py",
    "services/nas_identity_model.py",
    "services/nas_feature_control.py",
    "services/nas_feature_model.py",
    "services/nas_cockpit_api.py",
    "services/nas_operation_journal.py",
    "services/nas_operation_lock.py",
    "services/nas_syncthing_devices.py",
    "scripts/preflight.sh",
    "scripts/live-validation.sh",
    "scripts/nix-config-matrix.sh",
    "scripts/nix-negative-tests.sh",
    "scripts/lib/nas-secret-transaction.sh",
    "tests/bats/nas-secret-transaction.bats",
    "tests/browser/authz.py",
    "cockpit/e2e/playwright.config.mjs",
    "cockpit/e2e/ui-security.spec.mjs",
    "tests/adversarial_payloads.py",
    "tests/custom-script-contracts.json",
    "tests/test_adversarial_security.py",
    "tests/test_cli_surfaces.py",
    "tests/test_fuzz_boundaries.py",
    "tests/test_maintainer_scripts.py",
    "tests/test_script_inventory.py",
    "tests/test_security_surface.py",
    "tests/test_property_invariants.py",
    "tests/js/security.test.mjs",
    "scripts/qemu-test.sh",
    "scripts/validate-repository-data.py",
    "scripts/validate-doc-links.py",
    "scripts/validate-python-syntax.py",
    "scripts/validate-cockpit-jsx.cjs",
    "setup/first-run.example.json",
    "tests/test_setup.py",
    "tests/test_alpha18_hardening.py",
    "tests/test_state.py",
    "tests/test_secret_transaction.py",
    "tests/test_identity_sync.py",
    "cockpit/Makefile",
    "cockpit/README.md",
    "cockpit/build.js",
    "cockpit/package.json",
    "cockpit/src/manifest.json",
    "cockpit/src/index.html",
    "cockpit/src/index.jsx",
    "cockpit/src/app.jsx",
    "cockpit/src/app.scss",
    "cockpit/src/api.js",
    "cockpit/src/view-model.js",
    "cockpit/dist/README.md",
    "tests/test_feature_control.py",
    "tests/test_cockpit_api.py",
    "tests/test_operation_lock.py",
    "tests/test_comment_policy.py",
    "tests/test_contract_identity.py",
    "tests/test_contract_operations.py",
    "tests/test_contract_tooling.py",
    "tests/nixos/integration.nix",
    "tests/nixos/module-consumer.nix",
    "tests/nixos/negative-eval.nix",
    "tests/nixos/invalid/trusted-loopback.nix",
    "tests/nixos/invalid/trusted-duplicate.nix",
    "tests/nixos/invalid/zfs-dataset-root.nix",
    "tests/nixos/invalid/tftp-privileged-port.nix",
    "tests/nixos/invalid/replication-leading-dash.nix",
    "tests/nixos/invalid/firewall-without-networking.nix",
    "tests/nixos/encrypted.nix",
    "tests/vm/guest-test.sh",
    "tests/vm/encrypted-guest-test.sh",
    ".github/workflows/ci.yml",
}

ALLOWED_ROOT_MARKDOWN = {"AGENTS.md", "CHANGELOG.md", "CONTRIBUTING.md", "README.md", "SECURITY.md"}
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[.-][A-Za-z0-9][A-Za-z0-9.-]*)?$")
STATIC_NIX_PATH_RE = re.compile(r"\$\{(\.\./[^}]+)\}")
FORBIDDEN_DIR_NAMES = {".mypy_cache", ".pytest_cache", ".ruff_cache", "__pycache__", "node_modules", "build", "dist"}
ALLOWED_GENERATED_DIRS = {ROOT / "cockpit" / "dist"}
FORBIDDEN_FILE_NAMES = {".coverage", "coverage.json"}


def fail(message: str) -> None:
    print(f"structure error: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> int:
    missing = sorted(path for path in REQUIRED_FILES if not (ROOT / path).is_file())
    if missing:
        fail("missing required files: " + ", ".join(missing))

    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    if not VERSION_RE.fullmatch(version):
        fail(f"unsupported VERSION value: {version!r}")

    root_markdown = {path.name for path in ROOT.glob("*.md")}
    unexpected = sorted(root_markdown - ALLOWED_ROOT_MARKDOWN)
    if unexpected:
        fail("root documentation must be grouped under docs/: " + ", ".join(unexpected))

    forbidden_dirs = sorted(
        str(path.relative_to(ROOT))
        for path in ROOT.rglob("*")
        if path.is_dir() and path.name in FORBIDDEN_DIR_NAMES and path not in ALLOWED_GENERATED_DIRS
    )
    if forbidden_dirs:
        fail("generated/cache directories are present: " + ", ".join(forbidden_dirs))

    generated_files = sorted(
        str(path.relative_to(ROOT))
        for path in ROOT.rglob("*")
        if path.is_file()
        and (path.name in FORBIDDEN_FILE_NAMES or any(part.endswith(".egg-info") for part in path.parts))
    )
    if generated_files:
        fail("generated files are present: " + ", ".join(generated_files))

    shipped_modules = {path.stem for path in (ROOT / "cockpit/src").glob("*.js")}
    tested_modules = {path.name.removesuffix(".test.mjs") for path in (ROOT / "tests/js").glob("*.test.mjs")}
    untested = sorted(shipped_modules - tested_modules)
    if untested:
        fail("Cockpit modules without direct tests: " + ", ".join(untested))

    documentation_tools = (ROOT / "modules/nas/internal/documentation-tools.nix").read_text(encoding="utf-8")
    if "storage-tools.nix" in documentation_tools:
        fail("documentation-tools.nix references removed storage-tools.nix; use zfs-tools.nix")

    broken_nix_paths: list[str] = []
    for nix_file in sorted((ROOT / "modules").rglob("*.nix")):
        source = nix_file.read_text(encoding="utf-8")
        for relative in STATIC_NIX_PATH_RE.findall(source):
            target = (nix_file.parent / relative).resolve()
            if not target.exists():
                broken_nix_paths.append(f"{nix_file.relative_to(ROOT)} -> {relative}")
    if broken_nix_paths:
        fail("missing static Nix source paths: " + ", ".join(broken_nix_paths))

    print(f"structure ok: {version}; {len(REQUIRED_FILES)} required files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
