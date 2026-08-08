#!/usr/bin/env python3
"""Podman single-container runtime adapter for managed-services."""
from __future__ import annotations
import pathlib, re, subprocess
from typing import Any
from nas_managed_service import ManagedServiceError
IMAGE_RE = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*(?::[a-z0-9_.-]+)?(?:@[a-z0-9:]+)?$", re.IGNORECASE)
def plan_podman(service_id: str, service: dict[str, Any]) -> dict[str, Any]:
    runtime = service.get("runtime", {})
    if runtime.get("type") not in ("quadlet", "compose"):
        return {"actions": [], "warnings": [f"Service {service_id} is not a Podman service"]}
    source = runtime.get("source", "")
    if not source.startswith(f"/var/lib/nas-control/apps/{service_id}/"):
        raise ManagedServiceError(f"Podman source for {service_id} must be under /var/lib/nas-control/apps/{service_id}/")
    image = service.get("image") or runtime.get("image") or ""
    if image and not IMAGE_RE.fullmatch(image):
        raise ManagedServiceError(f"Invalid image for {service_id}: {image!r}")
    mounts = service.get("storage", [])
    resources = service.get("resources", {})
    actions = [{"type": "quadlet", "path": str(pathlib.Path(f"/etc/containers/systemd/{service_id}.container")), "service": service_id}]
    return {"service": service_id, "runtime": "podman", "actions": actions, "resources": resources, "mounts": mounts}
def apply_podman(service_id: str, service: dict[str, Any], *, dry_run: bool = False) -> dict[str, Any]:
    plan = plan_podman(service_id, service)
    if dry_run:
        return plan
    for action in plan["actions"]:
        if action["type"] == "quadlet":
            quadlet_content = _render_quadlet(service_id, service)
            path = pathlib.Path(action["path"])
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(quadlet_content, encoding="utf-8")
            subprocess.run(["systemctl", "daemon-reload"], check=False)
            subprocess.run(["systemctl", "restart", f"{service_id}.service"], check=False)
    return plan
def remove_podman(service_id: str, *, dry_run: bool = False) -> None:
    if dry_run:
        return
    quadlet_path = pathlib.Path(f"/etc/containers/systemd/{service_id}.container")
    if quadlet_path.exists():
        quadlet_path.unlink()
        subprocess.run(["systemctl", "daemon-reload"], check=False)
        subprocess.run(["systemctl", "stop", f"{service_id}.service"], check=False)
def _render_quadlet(service_id: str, service: dict[str, Any]) -> str:
    image = service.get("image") or service.get("runtime", {}).get("image", "docker.io/library/busybox:latest")
    lines = [f"[Container]", f"Image={image}", f"ContainerName={service_id}"]
    for mount in service.get("storage", []):
        host = mount.get("hostPath", "")
        guest = mount.get("guestPath", "")
        mode = mount.get("mode", "ro")
        ro_flag = ":ro" if mode == "ro" else ""
        lines.append(f"Volume={host}:{guest}{ro_flag}")
    resources = service.get("resources", {})
    if "memoryBytes" in resources:
        lines.append(f"Memory={resources['memoryBytes']}")
    if "cpus" in resources:
        lines.append(f"CPUQuota={int(float(resources['cpus']) * 100)}%")
    for ep in (service.get("endpoints") or {}).values():
        if ep.get("transport") in ("http", "https"):
            lines.append(f"PublishPort=127.0.0.1:{ep.get('targetPort')}")
    lines.extend(["[Service]", "Restart=on-failure", "[Install]", "WantedBy=multi-user.target"])
    return "\n".join(lines) + "\n"
