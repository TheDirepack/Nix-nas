#!/usr/bin/env python3
"""Fail on high-risk injection sinks in NAS-owned Python, JavaScript, and shell sources."""

from __future__ import annotations

import ast
import os
import pathlib
import re
import sys
from dataclasses import dataclass
from typing import Any

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


# Quoted string literals (single or double quoted) are data, not commands, so
# their contents are replaced before command matching. Text such as
# `printf '%s' 'Use (command eval "$x")'` therefore cannot create a command
# position. Command substitutions are the exception: `$(...)` and `` `...` ``
# interiors execute even inside double quotes, so they are scanned as code.
def _strip_quoted_strings(line: str) -> str:
    """Replace quoted literals with word placeholders of the same length.

    Length and offsets stay stable, and a quoted command word (for example
    `"$NIX" eval --raw`) never turns into whitespace that would make the next
    word look like the start of a new command. Command substitution interiors
    are kept: their quoted arguments are still data, but the substitution body
    is executed, so `result="$(eval "$user_command")"` must be scanned.
    """

    output: list[str] = []
    # Kind of each open context plus the mode to resume when it closes.
    frames: list[dict[str, Any]] = []
    index = 0

    def resume() -> str:
        frame = frames.pop()
        return str(frame["resume"])

    mode = "code"
    while index < len(line):
        char = line[index]

        if mode == "squote":
            output.append("_")
            index += 1
            if char == "'":
                mode = resume()
            continue

        if mode == "dquote":
            if char == "\\" and index + 1 < len(line):
                output.append("__")
                index += 2
                continue
            if char == '"':
                output.append("_")
                index += 1
                mode = resume()
                continue
            if line.startswith("$(", index):
                frames.append({"kind": "subst", "resume": "dquote", "parens": 0})
                output.append("$(")
                index += 2
                mode = "code"
                continue
            if char == "`":
                frames.append({"kind": "backtick", "resume": "dquote"})
                output.append("`")
                index += 1
                mode = "code"
                continue
            output.append("_")
            index += 1
            continue

        # Code position, including the interior of a command substitution.
        if char == "\\" and index + 1 < len(line):
            output.append(line[index : index + 2])
            index += 2
            continue
        if char == "'":
            frames.append({"kind": "squote", "resume": "code"})
            output.append("_")
            index += 1
            mode = "squote"
            continue
        if char == '"':
            frames.append({"kind": "dquote", "resume": "code"})
            output.append("_")
            index += 1
            mode = "dquote"
            continue
        if frames and frames[-1]["kind"] == "subst":
            if line.startswith("$(", index):
                frames[-1]["parens"] = int(frames[-1]["parens"]) + 1
                output.append("$(")
                index += 2
                continue
            if char == "(":
                frames[-1]["parens"] = int(frames[-1]["parens"]) + 1
            elif char == ")":
                if int(frames[-1]["parens"]) == 0:
                    frame = frames.pop()
                    output.append(")")
                    index += 1
                    mode = str(frame["resume"])
                    continue
                frames[-1]["parens"] = int(frames[-1]["parens"]) - 1
            output.append(char)
            index += 1
            continue
        if frames and frames[-1]["kind"] == "backtick" and char == "`":
            frame = frames.pop()
            output.append("`")
            index += 1
            mode = str(frame["resume"])
            continue
        output.append(char)
        index += 1
    return "".join(output)


def _eval_executed(wrapper: str | None) -> bool:
    """Decide whether a matched `eval` is actually executed as a shell builtin.

    `wrapper` is the text between the command boundary and `eval`, including
    wrapper keywords and their options. Bare `eval` executes. `command -v` /
    `command -V` only describe a command, so they do not execute `eval`.
    `--` ends option parsing, so the next token is the invoked command; if that
    token is another wrapper keyword, parsing continues, otherwise `eval` is
    only an argument (`command -- -- eval`).
    """

    if wrapper is None:
        return True
    tokens = wrapper.split()
    index = 1  # drop the command/builtin keyword
    while index < len(tokens):
        token = tokens[index]
        if token.startswith("-") and not token.startswith("--") and {"v", "V"} & set(token[1:]):
            # -v/-V (also clustered, e.g. -pv) only describe the command.
            return False
        index += 1
        if token == "--":
            if index >= len(tokens):
                return True
            token = tokens[index]
            if token in {"command", "builtin"}:
                index += 1
                continue
            return False
        # Wrapper keywords and options such as -p do not change execution.
    return True


# Match eval in executable command position. Boundaries are line start or shell
# list/control terminators; control keywords (if, then, while, do, ...),
# negation, assignment words, and command/builtin wrapper chains (with -p, --,
# or successive wrappers) may precede eval. Options are consumed by the wrapper
# group so command -p eval and command -- eval match while command -v eval does
# not. The lookahead keeps my_eval and eval_helper from matching.
_EVAL_RE = re.compile(
    r"(?:^|&&|\|\||[;|&(){]|`)\s*"
    r"(?:(?:if|elif|while|until|then|do|else|time)\s+|!\s+)*"
    r"(?:[A-Za-z_][A-Za-z0-9_]*=[^\s;|&()]*\s+)*"
    r"(?P<wrapper>(?:command|builtin)(?:\s+(?:command|builtin|-[A-Za-z]+|--))*)?"
    r"\s*"
    r"eval(?!\w)"
)


def shell_eval_in_command_position(line: str) -> bool:
    """Return true only when the shell eval builtin is executed as a command.

    Matching runs against the line with quoted literals replaced by word
    placeholders. eval is accepted at command position (line start, or after a
    shell list/control separator such as ; | & && || ( ) { `), optionally
    preceded by control keywords, negation (!), variable assignments, and
    command wrappers (command, builtin, and nested chains).
    Options such as command -p and an option-terminating -- are allowed between
    the wrapper and eval. `command -v`/`command -V` only describe a command and
    `command -- -- eval` passes eval as an argument, so neither executes eval.
    """

    stripped = _strip_quoted_strings(line)
    for match in re.finditer(_EVAL_RE, stripped):
        if _eval_executed(match.group("wrapper")):
            return True
    return False


# Locate set/bash/sh invocations at command position; the arguments are parsed
# as option words so clustered (-eux), separated (-e -x), and -o xtrace forms
# all agree.
_XTRACE_COMMAND_RE = re.compile(
    r"(?:^|&&|\|\||[;|&(){]|`)\s*"
    r"(?:(?:if|elif|while|until|then|do|else|!)\s+)*"
    r"(?P<command>set|bash|sh)\s+(?P<arguments>[^;&|)]*)"
)


def _options_enable_xtrace(command: str, arguments: str) -> bool:
    tokens = arguments.split()
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            # End of this command's options; later words are operands.
            return False
        if token in {"-o", "+o"}:
            index += 1
            if index >= len(tokens):
                return False
            if token == "-o" and tokens[index] == "xtrace":
                return True
            index += 1
            continue
        if command != "set" and token == "-c":
            # Everything after -c is the command string and its arguments.
            return False
        if token in {"-O", "--rcfile", "--init-file"}:
            index += 2
            continue
        if token.startswith("--"):
            index += 1
            continue
        sign, letters = token[:1], token[1:]
        if sign in {"-", "+"} and letters.isalpha():
            if sign == "-" and "x" in letters:
                return True
            index += 1
            continue
        # Non-option word: for set this ends option processing; for bash/sh it
        # is the script name or command string.
        return False
    return False


def shell_xtrace_enabled(line: str) -> bool:
    """Return true when shell tracing is enabled and could expose secret expansions."""

    return any(
        _options_enable_xtrace(match.group("command"), match.group("arguments"))
        for match in _XTRACE_COMMAND_RE.finditer(line)
    )


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


def safe_ruamel_yaml_instances(tree: ast.AST) -> set[str]:
    """Return variables proven to be safe/round-trip ruamel.yaml YAML instances."""

    factories: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "ruamel.yaml":
            for alias in node.names:
                if alias.name == "YAML":
                    factories.add(alias.asname or alias.name)

    instances: set[str] = set()
    for node in ast.walk(tree):
        targets: list[ast.expr] = []
        value: ast.AST | None = None
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
            value = node.value
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
            value = node.value
        if not isinstance(value, ast.Call) or not isinstance(value.func, ast.Name):
            continue
        if value.func.id not in factories:
            continue

        loader_type = "rt"
        for keyword in value.keywords:
            if (
                keyword.arg == "typ"
                and isinstance(keyword.value, ast.Constant)
                and isinstance(keyword.value.value, str)
            ):
                loader_type = keyword.value.value
        if loader_type not in {"rt", "safe"}:
            continue
        for target in targets:
            if isinstance(target, ast.Name):
                instances.add(target.id)
    return instances


def scan_python(path: pathlib.Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, SyntaxError) as exc:
        return [Finding(path, getattr(exc, "lineno", 1) or 1, "python-parse", str(exc))]

    safe_ruamel_instances = safe_ruamel_yaml_instances(tree)
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
            receiver = node.func.value if isinstance(node.func, ast.Attribute) else None
            if isinstance(receiver, ast.Name) and receiver.id in safe_ruamel_instances:
                continue
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


def _read_lines(path: pathlib.Path) -> list[str] | None:
    """Return the lines of a file, or None if it cannot be read."""

    try:
        return path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None


def scan_shell(path: pathlib.Path) -> list[Finding]:
    findings: list[Finding] = []
    lines = _read_lines(path)
    if lines is None:
        findings.append(Finding(path, 1, "unreadable-source", f"cannot read {path}"))
        return findings
    for lineno, line in enumerate(lines, 1):
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        if shell_eval_in_command_position(line):
            findings.append(Finding(path, lineno, "shell-eval", line.strip()[:160]))
        if shell_xtrace_enabled(line):
            findings.append(Finding(path, lineno, "shell-xtrace-secret-leak", line.strip()[:160]))
        if re.search(r"\bmktemp\s+-u(?:\s|$)", line):
            findings.append(Finding(path, lineno, "insecure-temporary-file", line.strip()[:160]))
        if re.search(r"\bprintf\s+[\"']?\$[A-Za-z_{]", line):
            findings.append(Finding(path, lineno, "shell-format-string", line.strip()[:160]))
    return findings


def scan_nix(path: pathlib.Path) -> list[Finding]:
    """Scan shell fragments embedded in Nix without pretending to parse the Nix language."""
    findings: list[Finding] = []
    lines = _read_lines(path)
    if lines is None:
        findings.append(Finding(path, 1, "unreadable-source", f"cannot read {path}"))
        return findings
    for lineno, line in enumerate(lines, 1):
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        if shell_eval_in_command_position(line):
            findings.append(Finding(path, lineno, "generated-shell-eval", line.strip()[:160]))
        if shell_xtrace_enabled(line):
            findings.append(Finding(path, lineno, "generated-shell-xtrace-secret-leak", line.strip()[:160]))
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


def files(root: pathlib.Path, suffixes: set[str]) -> tuple[list[pathlib.Path], list[str]]:
    """Return (files, errors) under root.

    Files are regular files with a matching suffix (node_modules excluded).
    Traversal errors for unreadable or disappearing directories are collected
    and returned instead of being silently suppressed, as root.rglob() does.
    """

    found: list[pathlib.Path] = []
    errors: list[str] = []

    def walk(dir_path: pathlib.Path) -> None:
        try:
            entries = sorted(os.scandir(dir_path), key=lambda entry: entry.name)
        except OSError as exc:
            errors.append(f"{dir_path}: {exc}")
            return
        for entry in entries:
            full = pathlib.Path(entry.path)
            try:
                if entry.name == "node_modules" and entry.is_dir(follow_symlinks=False):
                    continue
                if entry.is_dir(follow_symlinks=False):
                    walk(full)
                elif entry.is_file(follow_symlinks=False) and full.suffix in suffixes:
                    found.append(full)
            except OSError as exc:
                errors.append(f"{full}: {exc}")

    walk(root)
    return sorted(found), errors


def main() -> int:
    findings: list[Finding] = []
    for root in (*PYTHON_ROOTS, *WEB_ROOTS, *SHELL_ROOTS, *NIX_ROOTS):
        if not root.is_dir():
            print(f"scan root missing: {root}", file=sys.stderr)
            return 1
    scans = (
        (PYTHON_ROOTS, {".py"}, scan_python),
        (WEB_ROOTS, {".js", ".jsx", ".html"}, scan_web),
        (SHELL_ROOTS, {".sh"}, scan_shell),
        (NIX_ROOTS, {".nix"}, scan_nix),
    )
    for roots, suffixes, scanner in scans:
        for root in roots:
            paths, errors = files(root, suffixes)
            if errors:
                print(f"scan root unreadable: {root}", file=sys.stderr)
                for error in errors:
                    print(f"  {error}", file=sys.stderr)
                return 1
            for path in paths:
                findings.extend(scanner(path))
    if findings:
        print("Static security boundary scan failed:", file=sys.stderr)
        for finding in findings:
            print(f"- {relative(finding.path)}:{finding.line}: {finding.rule}: {finding.detail}", file=sys.stderr)
        return 1
    print("static security boundary scan ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
