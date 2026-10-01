from __future__ import annotations

import ast
import unittest

from repo_test_utils import text


class NtfyDeliveryProbeTests(unittest.TestCase):
    def delivery_matches(self, messages: list[dict]) -> bool:
        source = text("tests/vm/guest-test.sh").split("<<'VERIFY_NTFY'\n", 1)[1].split("\nVERIFY_NTFY", 1)[0]
        tree = ast.parse(source)
        check = next(
            node.test
            for node in ast.walk(tree)
            if isinstance(node, ast.If)
            and isinstance(node.test, ast.Call)
            and isinstance(node.test.func, ast.Name)
            and node.test.func.id == "any"
        )
        return eval(compile(ast.Expression(check), "ntfy-probe", "eval"), {"messages": messages})

    def test_matches_upstream_label_tags_not_annotation_body(self) -> None:
        self.assertTrue(
            self.delivery_matches(
                [
                    {"event": "message", "message": "ntfy outage test", "tags": ["alertname = QemuNtfyDependency"]},
                ]
            )
        )

    def test_rejects_unrelated_notifications(self) -> None:
        self.assertFalse(
            self.delivery_matches(
                [
                    {"event": "message", "message": "ntfy outage test", "tags": ["alertname = AnotherAlert"]},
                    {"event": "message", "message": "QemuNtfyDependency mentioned in unrelated text"},
                ]
            )
        )
