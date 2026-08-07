from __future__ import annotations

import json
import os
import pathlib
import tempfile
import time
from dataclasses import dataclass
from typing import Any, Mapping


class JournalError(RuntimeError):
    pass


def atomic_write_json(path: pathlib.Path, value: Mapping[str, Any], mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    replaced = False
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(name, mode)
        os.replace(name, path)
        replaced = True
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if not replaced:
            try:
                os.unlink(name)
            except FileNotFoundError:
                pass


def load_json(path: pathlib.Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError) as exc:
        raise JournalError(f"Invalid operation journal: {path}") from exc
    if not isinstance(value, dict):
        raise JournalError(f"Operation journal is not a JSON object: {path}")
    return value


@dataclass
class OperationJournal:
    path: pathlib.Path
    value: dict[str, Any]

    @classmethod
    def open(
        cls,
        path: pathlib.Path,
        *,
        workflow: str,
        fingerprint: str,
        metadata: Mapping[str, Any] | None = None,
    ) -> "OperationJournal":
        existing = load_json(path)
        now = int(time.time())
        if existing is not None and existing.get("status") not in {"complete", "cancelled"}:
            if existing.get("schemaVersion") != 1 or existing.get("workflow") != workflow:
                raise JournalError(f"Another operation requires reconciliation: {path}")
            if existing.get("fingerprint") != fingerprint:
                raise JournalError(f"A different {workflow} operation is incomplete; reconcile or clear {path}")
            if existing.get("status") == "manual-recovery-required":
                raise JournalError(
                    f"{workflow} requires explicit recovery acknowledgement before it can resume: {path}"
                )
            existing["status"] = "resuming"
            existing["updatedAt"] = now
            journal = cls(path, existing)
            journal.save()
            return journal
        value: dict[str, Any] = {
            "schemaVersion": 1,
            "workflow": workflow,
            "fingerprint": fingerprint,
            "status": "pending",
            "startedAt": now,
            "updatedAt": now,
            "metadata": dict(metadata or {}),
            "steps": {},
        }
        journal = cls(path, value)
        journal.save()
        return journal

    @classmethod
    def acknowledge_manual_recovery(
        cls,
        path: pathlib.Path,
        *,
        workflow: str,
        note: str,
    ) -> "OperationJournal":
        existing = load_json(path)
        if existing is None:
            raise JournalError(f"No operation journal exists: {path}")
        if existing.get("workflow") != workflow or existing.get("schemaVersion") != 1:
            raise JournalError(f"Journal does not belong to {workflow}: {path}")
        if existing.get("status") != "manual-recovery-required":
            raise JournalError(f"Journal is not awaiting manual recovery: {path}")
        existing["status"] = "reconciled"
        existing["recoveryAcknowledgedAt"] = int(time.time())
        existing["recoveryNote"] = note
        journal = cls(path, existing)
        journal.save()
        return journal

    def save(self) -> None:
        self.value["updatedAt"] = int(time.time())
        atomic_write_json(self.path, self.value)

    def step_complete(self, step: str) -> bool:
        record = self.value.get("steps", {}).get(step)
        return isinstance(record, dict) and record.get("status") == "complete"

    def result(self, step: str) -> Any:
        record = self.value.get("steps", {}).get(step)
        return record.get("result") if isinstance(record, dict) else None

    def start_step(self, step: str) -> None:
        steps = self.value.setdefault("steps", {})
        record = steps.setdefault(step, {})
        record.update({"status": "running", "startedAt": int(time.time())})
        record.pop("error", None)
        self.value["status"] = "running"
        self.value["currentStep"] = step
        self.save()

    def complete_step(self, step: str, result: Any = None) -> None:
        steps = self.value.setdefault("steps", {})
        record = steps.setdefault(step, {})
        record.update({"status": "complete", "completedAt": int(time.time())})
        if result is not None:
            record["result"] = result
        record.pop("error", None)
        self.value["currentStep"] = None
        self.save()

    def fail_step(self, step: str, error: str, *, manual_recovery: bool = False) -> None:
        steps = self.value.setdefault("steps", {})
        record = steps.setdefault(step, {})
        record.update({"status": "failed", "failedAt": int(time.time()), "error": error})
        self.value["status"] = "manual-recovery-required" if manual_recovery else "failed"
        self.value["currentStep"] = step
        self.save()

    def fail(self, error: str, *, manual_recovery: bool = False) -> None:
        self.value["status"] = "manual-recovery-required" if manual_recovery else "failed"
        self.value["error"] = error
        self.value["failedAt"] = int(time.time())
        self.save()

    def complete(self, result: Any = None) -> None:
        self.value["status"] = "complete"
        self.value["completedAt"] = int(time.time())
        self.value["currentStep"] = None
        if result is not None:
            self.value["result"] = result
        self.save()
