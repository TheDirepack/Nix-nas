#!/usr/bin/env python3
"""Fail on high-risk injection sinks in NAS-owned Python, JavaScript, and shell sources."""

from __future__ import annotations

import ast
import pathlib
import re
import sys
from dataclasses import dataclass

ROOT = pathlib.Path(__file__).resolve().parents[1]
PYTHON_ROOTS = (ROOT / "services", ROOT / "scripts")
WEB_ROOTS = (ROOT / "cockpit" / "src", ROOT / "web")
SHELL_ROOTS = (ROOT / "scripts", ROOT / "tests" / "vm")
NIX_ROOTS = (ROOT / "modules",)


@dataclass(frozen=True)
class Finding:
    path: pathlib.Path
    line: int
    rule: str
    detail: str


SHELL_EVAL_RE = re.compile(r"(?:^|&&|\|\||[;|&()])\s*(?:(?:if|elif|while|until|then|do)\s+)?eval(?:\s|$)")


def shell_eval_in_command_position(line: str) -> bool:
    """Return true only when the shell eval builtin appears as a command."""

    return SHELL_EVAL_RE.search(line) is not None


def relative(path: pathlib.Path) -> str:
    return path.relative_to(ROOT).as_posix()


def dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def dynamic_sql(node: ast.AST) -> bool:
    if isinstance(node, (ast.JoinedStr, ast.BinOp)):
        return True
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format"


def scan_python(path: pathlib.Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, SyntaxError) as exc:
        return [Finding(path, getattr(exc, "lineno", 1) or 1, "python-parse", str(exc))]

    tainted_sql_names: set[str] = set()
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            targets: list[ast.expr] = []
            value: ast.AST | None = None
            if isinstance(node, ast.Assign):
                targets = list(node.targets)
                value = node.value
            elif isinstance(node, ast.AnnAssign):
                targets = [node.target]
                value = node.value
            if value is None:
                continue
            value_is_dynamic = dynamic_sql(value) or (isinstance(value, ast.Name) and value.id in tainted_sql_names)
            if not value_is_dynamic:
                continue
            for target in targets:
                if isinstance(target, ast.Name) and target.id not in tainted_sql_names:
                    tainted_sql_names.add(target.id)
                    changed = True

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = dotted(node.func)
        if name in {"eval", "exec", "os.system", "os.popen"}:
            findings.append(Finding(path, node.lineno, "code-command-injection", f"forbidden call {name}"))
        if name in {"pickle.load", "pickle.loads", "marshal.load", "marshal.loads"}:
            findings.append(Finding(path, node.lineno, "unsafe-deserialization", f"forbidden deserializer {name}"))
        if name == "yaml.load":
            safe_loader = any(
                keyword.arg == "Loader"
                and dotted(keyword.value) in {"yaml.SafeLoader", "SafeLoader", "yaml.CSafeLoader", "CSafeLoader"}
                for keyword in node.keywords
            )
            if not safe_loader:
                findings.append(Finding(path, node.lineno, "unsafe-deserialization", "yaml.load without SafeLoader"))
        if name == "tempfile.mktemp":
            findings.append(Finding(path, node.lineno, "insecure-temporary-file", "tempfile.mktemp is race-prone"))
        if isinstance(node.func, ast.Attribute) and node.func.attr == "extractall":
            findings.append(
                Finding(
                    path,
                    node.lineno,
                    "archive-extraction",
                    "bulk archive extraction requires an explicit reviewed traversal guard",
                )
            )
        if name.startswith("subprocess."):
            for keyword in node.keywords:
                if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                    findings.append(Finding(path, node.lineno, "shell-injection", "subprocess shell=True"))
        if isinstance(node.func, ast.Attribute) and node.func.attr in {"execute", "executemany", "executescript"}:
            if node.args and (
                dynamic_sql(node.args[0])
                or (isinstance(node.args[0], ast.Name) and node.args[0].id in tainted_sql_names)
            ):
                findings.append(Finding(path, node.lineno, "sql-injection", "dynamic SQL passed to database execution"))
    return findings


def scan_web(path: pathlib.Path) -> list[Finding]:
    findings: list[Finding] = []
    text = path.read_text(encoding="utf-8")
    rules = {
        "dom-xss-innerhtml": re.compile(r"\b(?:innerHTML|outerHTML)\s*="),
        "dom-xss-react": re.compile(r"dangerouslySetInnerHTML"),
        "dom-xss-write": re.compile(r"\bdocument\.(?:write|writeln)\s*\("),
        "dom-xss-adjacent": re.compile(r"\binsertAdjacentHTML\s*\("),
        "javascript-eval": re.compile(r"\b(?:eval|Function)\s*\("),
        "javascript-url": re.compile(r"javascript:\s*", re.IGNORECASE),
        "dom-xss-srcdoc": re.compile(r"\bsrcdoc\s*="),
        "dom-xss-event-attribute": re.compile(r"\.setAttribute\(\s*[\"']on[a-z]+[\"']", re.IGNORECASE),
        "javascript-string-timer": re.compile(r"\bset(?:Timeout|Interval)\(\s*[\"']"),
    }
    for lineno, line in enumerate(text.splitlines(), 1):
        for rule, pattern in rules.items():
            if pattern.search(line):
                findings.append(Finding(path, lineno, rule, line.strip()[:160]))
    return findings


def scan_shell(path: pathlib.Path) -> list[Finding]:
    findings: list[Finding] = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        if shell_eval_in_command_position(line):
            findings.append(Finding(path, lineno, "shell-eval", line.strip()[:160]))
        if re.search(r"\bmktemp\s+-u(?:\s|$)", line):
            findings.append(Finding(path, lineno, "insecure-temporary-file", line.strip()[:160]))
        if re.search(r"\bprintf\s+[\"']?\$[A-Za-z_{]", line):
            findings.append(Finding(path, lineno, "shell-format-string", line.strip()[:160]))
    return findings


def scan_nix(path: pathlib.Path) -> list[Finding]:
    """Scan shell fragments embedded in Nix without pretending to parse the Nix language."""
    findings: list[Finding] = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        if shell_eval_in_command_position(line):
            findings.append(Finding(path, lineno, "generated-shell-eval", line.strip()[:160]))
        if re.search(r"\b(?:bash|sh)\s+-c\s+[\"']?\$", line):
            findings.append(Finding(path, lineno, "generated-shell-command-injection", line.strip()[:160]))
        # SQLite dot commands are parsed by sqlite3 itself, not parameterized SQL. Never
        # interpolate a shell-controlled destination into .backup/.restore command text.
        if re.search(r"\bsqlite3\b.*\.(?:backup|restore).*\$[A-Za-z_{]", line):
            findings.append(Finding(path, lineno, "sqlite-meta-command-injection", line.strip()[:160]))
        if re.search(r"\bmktemp\s+-u(?:\s|$)", line):
            findings.append(Finding(path, lineno, "insecure-temporary-file", line.strip()[:160]))
        if re.search(r"\bprintf\s+[\"']?\$[A-Za-z_{]", line):
            findings.append(Finding(path, lineno, "generated-shell-format-string", line.strip()[:160]))
    return findings


def files(root: pathlib.Path, suffixes: set[str]) -> list[pathlib.Path]:
    return sorted(
        path
        for path in root.rglob("*")
        if path.is_file() and path.suffix in suffixes and "node_modules" not in path.parts
    )


def main() -> int:
    findings: list[Finding] = []
    for root in PYTHON_ROOTS:
        for path in files(root, {".py"}):
            findings.extend(scan_python(path))
    for root in WEB_ROOTS:
        for path in files(root, {".js", ".jsx", ".html"}):
            findings.extend(scan_web(path))
    for root in SHELL_ROOTS:
        for path in files(root, {".sh"}):
            findings.extend(scan_shell(path))
    for root in NIX_ROOTS:
        for path in files(root, {".nix"}):
            findings.extend(scan_nix(path))
    if findings:
        print("Static security boundary scan failed:", file=sys.stderr)
        for finding in findings:
            print(f"- {relative(finding.path)}:{finding.line}: {finding.rule}: {finding.detail}", file=sys.stderr)
        return 1
    print("static security boundary scan ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
