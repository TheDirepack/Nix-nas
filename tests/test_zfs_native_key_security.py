from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_zfs_key_validation_is_native() -> None:
    source = (ROOT / "modules" / "nas" / "internal" / "zfs-tools.nix").read_text(encoding="utf-8")

    assert "load-key -L" in source
    assert "keyformat=hex" in source
    assert "^[0-9a-fA-F]{64}$" in source
    assert "keystore-sha256" not in source
    assert "zfsKeyFingerprintProperty" not in source
    assert "stored_fingerprint" not in source
    assert "staged_fingerprint" not in source
    assert "sha256sum" not in source


def test_base_exports_no_parallel_zfs_key_fingerprint_authority() -> None:
    source = (ROOT / "modules" / "nas" / "internal" / "base.nix").read_text(encoding="utf-8")

    assert "zfsKeyFingerprintProperty" not in source
    assert "org.nixos:keystore-sha256" not in source
