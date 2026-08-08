"""Compatibility shim for the managed Authentik adapter."""
from nas_managed_runtime.authentik import AuthentikError, apply_authentik, plan_authentik, remove_authentik

__all__ = ["AuthentikError", "apply_authentik", "plan_authentik", "remove_authentik"]
