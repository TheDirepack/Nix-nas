from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_identity_runtime_switches_from_bootstrap_to_root_not_zfs() -> None:
    source = (ROOT / "modules" / "nas" / "config" / "application-services.nix").read_text(encoding="utf-8")

    selector = source.split("config.systemd.services.nas-bootstrap-runtime-select", 1)[1]
    assert "target=/var/lib/nas-operational" in selector
    assert "target=${lib.escapeShellArg cfg.zfsRoot}" not in selector
    assert "mountpoint --quiet -- ${lib.escapeShellArg cfg.zfsRoot}" not in selector
    assert 'for name in authentik postgresql nas-secrets' in selector


def test_no_dedicated_authentik_proxy_outpost_daemon() -> None:
    services = (ROOT / "modules" / "nas" / "config" / "application-services.nix").read_text(encoding="utf-8")
    base = (ROOT / "modules" / "nas" / "internal" / "base.nix").read_text(encoding="utf-8")

    assert "nas-authentik-proxy-outpost" not in services
    assert "authentik-outposts.proxy" not in services
    assert "view_key" not in services
    assert "authentikOutpostPort = authentikPort;" in base
