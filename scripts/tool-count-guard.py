#!/usr/bin/env python3
"""Verify the documented product tool count matches registered MCP tools."""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path
from typing import NamedTuple


REPO = Path(__file__).resolve().parent.parent
DEFAULT_EXPECTED_RUST = 43
DEFAULT_EXPECTED_PYTHON = 14


class DocRule(NamedTuple):
    path: str
    requires_total: bool = False
    requires_rust: bool = False
    requires_python: bool = False
    requires_inventory: bool = False
    # Optional docs are checked only when present (e.g. a gitignored local
    # draft); an absent optional doc is skipped instead of failing the guard.
    optional: bool = False


DOC_RULES = (
    DocRule("CLAUDE.md", requires_total=True, requires_rust=True, requires_python=True),
    DocRule("README.md", requires_total=True, requires_rust=True, requires_python=True),
    DocRule(
        "INSTALL.md", requires_total=True, requires_rust=True, requires_python=True
    ),
    DocRule(
        "docs/architecture.md",
        requires_total=True,
        requires_rust=True,
        requires_python=True,
    ),
    DocRule(
        "docs/reference/mcp-and-tools.md",
        requires_total=True,
        requires_rust=True,
        requires_python=True,
    ),
    DocRule(
        "CONTRIBUTING.md",
        requires_total=True,
        requires_rust=True,
        requires_python=True,
    ),
    DocRule(
        "QUICKSTART.md",
        requires_total=True,
        requires_rust=True,
        requires_python=True,
    ),
    DocRule(
        "Judging Criteria/JUDGING-rubric-and-prompts.md",
        requires_total=True,
        requires_rust=True,
        requires_python=True,
    ),
    DocRule(
        "agent-config/JUDGING.md",
        requires_total=True,
        requires_rust=True,
        requires_python=True,
    ),
    DocRule(
        "docs/extending-the-tool-surface.md",
        requires_total=True,
        requires_rust=True,
        requires_python=True,
    ),
    DocRule(
        "docs/help-wanted.md",
        requires_total=True,
        requires_rust=True,
        requires_python=True,
    ),
    DocRule("services/mcp/README.md", requires_rust=True),
    DocRule(
        "docs/codex-compatibility.md",
        requires_total=True,
        requires_rust=True,
        requires_python=True,
    ),
    DocRule("scripts/doctor.sh", requires_rust=True, requires_python=True),
    DocRule("scripts/install.sh", requires_rust=True, requires_python=True),
    DocRule(
        "docs/diagrams/verdict-code-architecture.mmd",
        requires_rust=True,
        requires_python=True,
    ),
    DocRule(
        "agent-config/PLAYBOOK.md",
        requires_total=True,
        requires_rust=True,
        requires_python=True,
        requires_inventory=True,
    ),
    DocRule(
        "scripts/make-demo-video/src/components/ArchPoster.tsx",
        requires_total=True,
        requires_rust=True,
        requires_python=True,
    ),
    # Strategy doc (gitignored local draft) — pin only the VERDICT product-total
    # claim. It is freeform prose citing many rivals' tool counts, so requiring
    # the Rust/Python sub-counts would false-positive on competitor descriptions;
    # requires_total catches the "56 product tools" drift that this guard missed.
    # optional=True: the file is gitignored, so CI runs without it — check it
    # when the local draft is present, skip when absent.
    DocRule("docs/competitive-analysis.md", requires_total=True, optional=True),
)


def _extract_braced_block(text: str, marker: str) -> str:
    marker_index = text.find(marker)
    if marker_index == -1:
        raise ValueError(f"missing marker {marker!r}")
    brace_index = text.find("{", marker_index)
    if brace_index == -1:
        raise ValueError(f"missing opening brace after {marker!r}")

    depth = 0
    for index in range(brace_index, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[brace_index : index + 1]
    raise ValueError(f"missing closing brace after {marker!r}")


def rust_tool_names(root: Path = REPO) -> tuple[str, ...]:
    server_rs = root / "services/mcp/src/server.rs"
    body = _extract_braced_block(
        server_rs.read_text(encoding="utf-8"),
        "fn build_registry()",
    )
    return tuple(re.findall(r'\bname:\s*"([^"]+)"', body))


def count_rust_tools(root: Path = REPO) -> int:
    return len(rust_tool_names(root))


def _python_tool_modules(root: Path) -> tuple[str, ...]:
    registry = root / "services/agent_mcp/findevil_agent_mcp/tools/__init__.py"
    module = ast.parse(registry.read_text(encoding="utf-8"), filename=str(registry))
    for node in module.body:
        value = None
        if isinstance(node, ast.AnnAssign) and _is_modules_target(node.target):
            value = node.value
        elif isinstance(node, ast.Assign) and any(
            _is_modules_target(t) for t in node.targets
        ):
            value = node.value
        if isinstance(value, ast.Tuple):
            return tuple(
                elt.value
                for elt in value.elts
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
            )
    raise ValueError("missing _MODULES tuple in Python MCP tool registry")


def _python_spec_name(path: Path) -> str:
    module = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: list[str] = []
    for node in module.body:
        value = None
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "SPEC"
            for target in node.targets
        ):
            value = node.value
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == "SPEC"
        ):
            value = node.value
        if not isinstance(value, ast.Call):
            continue
        for keyword in value.keywords:
            if (
                keyword.arg == "name"
                and isinstance(keyword.value, ast.Constant)
                and isinstance(keyword.value.value, str)
            ):
                names.append(keyword.value.value)
    if len(names) != 1:
        raise ValueError(
            f"{path}: expected one static SPEC = ToolSpec(name=...) declaration; "
            f"found {len(names)}"
        )
    return names[0]


def python_tool_names(root: Path = REPO) -> tuple[str, ...]:
    tools_dir = root / "services/agent_mcp/findevil_agent_mcp/tools"
    return tuple(
        _python_spec_name(tools_dir / f"{module_name}.py")
        for module_name in _python_tool_modules(root)
    )


def count_python_tools(root: Path = REPO) -> int:
    return len(python_tool_names(root))


def _is_modules_target(node: ast.AST) -> bool:
    return isinstance(node, ast.Name) and node.id == "_MODULES"


def _required_count_errors(
    text: str, rule: DocRule, total: int, rust: int, python: int
) -> list[str]:
    errors = []
    checks = (
        (rule.requires_total, total, "product total"),
        (rule.requires_rust, rust, "Rust count"),
        (rule.requires_python, python, "Python count"),
    )
    for required, expected, label in checks:
        if required and str(expected) not in text:
            errors.append(f"{rule.path}: missing {label} {expected}")
        if required:
            errors.extend(_conflicting_count_errors(text, rule.path, expected, label))
    return errors


COUNT_CLAIM_PATTERNS = {
    "product total": (
        re.compile(r"\b(\d+)\s+(?:audit-chained\s+)?product\s+tools\b"),
        re.compile(r"\b(\d+)\s+typed\s+read-only\s+tools\b"),
        re.compile(r"\b(\d+)\s+narrow\s+schema-validated\s+product\s+tools\b"),
    ),
    "Rust count": (
        re.compile(r"\b(\d+)\s+Rust(?:\s+DFIR)?(?:\s+MCP)?\s+tools\b"),
        re.compile(
            r"findevil-mcp[^\n|]*\b(\d+)\s+(?:typed\s+)?DFIR\s+(?:primitives|tools)\b"
        ),
    ),
    "Python count": (
        re.compile(r"\b(\d+)\s+Python[^\n|]*\btools\b"),
        re.compile(r"Python\s+MCP\s+server[^\n|]*\b(\d+)\s+[^\n|]*tools\b"),
        re.compile(
            r"findevil-agent-mcp[^\n|]*\b(\d+)\s+crypto/ACH/memory[^\n|]*tools\b"
        ),
    ),
}


def _conflicting_count_errors(
    text: str, path: str, expected: int, label: str
) -> list[str]:
    patterns = COUNT_CLAIM_PATTERNS[label]
    errors = []
    for pattern in patterns:
        for match in pattern.finditer(text):
            actual = int(match.group(1))
            if actual != expected:
                errors.append(f"{path}: {label} claim {actual} != {expected}")
    return errors


def _inventory_subsection(section: str, server: str) -> str | None:
    heading = re.search(rf"^###\s+{re.escape(server)}\b.*$", section, re.MULTILINE)
    if heading is None:
        return None
    next_heading = re.search(r"^###\s+", section[heading.end() :], re.MULTILINE)
    end = heading.end() + next_heading.start() if next_heading else len(section)
    return section[heading.end() : end]


def _inventory_names(section: str) -> list[str]:
    return re.findall(r"^\|\s*`([a-z][a-z0-9_]*)`\s*\|", section, flags=re.MULTILINE)


def _inventory_server_errors(
    path: str,
    server: str,
    documented: list[str],
    registered: tuple[str, ...],
) -> list[str]:
    documented_set = set(documented)
    registered_set = set(registered)
    errors = []
    missing = sorted(registered_set - documented_set)
    unexpected = sorted(documented_set - registered_set)
    if missing:
        errors.append(
            f"{path}: {server} inventory missing registered tools: {', '.join(missing)}"
        )
    if unexpected:
        errors.append(
            f"{path}: {server} inventory lists tools not registered by that server: "
            f"{', '.join(unexpected)}"
        )
    return errors


def _inventory_errors(
    text: str,
    rule: DocRule,
    rust_tools: tuple[str, ...],
    python_tools: tuple[str, ...],
) -> list[str]:
    marker = "## Tool inventory"
    start = text.find(marker)
    if start == -1:
        return [f"{rule.path}: missing {marker!r} section"]
    end = text.find("\n---", start)
    if end == -1:
        return [f"{rule.path}: tool inventory section has no closing divider"]

    section = text[start:end]
    rust_section = _inventory_subsection(section, "Rust")
    python_section = _inventory_subsection(section, "Python")
    if rust_section is None or python_section is None:
        missing = [
            server
            for server, subsection in (
                ("Rust", rust_section),
                ("Python", python_section),
            )
            if subsection is None
        ]
        return [
            f"{rule.path}: tool inventory missing server subsection(s): {', '.join(missing)}"
        ]

    documented = _inventory_names(section)
    documented_set = set(documented)
    registered_tools = set(rust_tools) | set(python_tools)
    errors = []
    missing = sorted(registered_tools - documented_set)
    unexpected = sorted(documented_set - registered_tools)
    duplicates = sorted({name for name in documented if documented.count(name) > 1})
    if missing:
        errors.append(
            f"{rule.path}: inventory missing registered tools: {', '.join(missing)}"
        )
    if unexpected:
        errors.append(
            f"{rule.path}: inventory lists unregistered tools: {', '.join(unexpected)}"
        )
    if duplicates:
        errors.append(
            f"{rule.path}: inventory duplicates tools: {', '.join(duplicates)}"
        )
    errors.extend(
        _inventory_server_errors(
            rule.path, "Rust", _inventory_names(rust_section), rust_tools
        )
    )
    errors.extend(
        _inventory_server_errors(
            rule.path, "Python", _inventory_names(python_section), python_tools
        )
    )
    return errors


def validate_docs(
    root: Path,
    rust: int,
    python: int,
    rust_tools: tuple[str, ...],
    python_tools: tuple[str, ...],
) -> list[str]:
    total = rust + python
    errors = []
    for rule in DOC_RULES:
        path = root / rule.path
        if not path.is_file():
            if not rule.optional:
                errors.append(f"{rule.path}: missing monitored documentation file")
            continue
        text = path.read_text(encoding="utf-8")
        errors.extend(_required_count_errors(text, rule, total, rust, python))
        if rule.requires_inventory:
            errors.extend(_inventory_errors(text, rule, rust_tools, python_tools))
    return errors


def validate_counts(
    root: Path = REPO,
    *,
    expected_rust: int = DEFAULT_EXPECTED_RUST,
    expected_python: int = DEFAULT_EXPECTED_PYTHON,
) -> list[str]:
    errors = []
    rust_names = rust_tool_names(root)
    python_names = python_tool_names(root)
    rust = len(rust_names)
    python = len(python_names)
    if rust != expected_rust:
        errors.append(f"Rust registry has {rust} tools; expected {expected_rust}")
    if python != expected_python:
        errors.append(f"Python registry has {python} tools; expected {expected_python}")
    for server, names in (("Rust", rust_names), ("Python", python_names)):
        duplicates = sorted({name for name in names if names.count(name) > 1})
        if duplicates:
            errors.append(
                f"{server} registry duplicates tool names: {', '.join(duplicates)}"
            )
    overlap = sorted(set(rust_names) & set(python_names))
    if overlap:
        errors.append(
            "Rust and Python registries expose overlapping tool names: "
            + ", ".join(overlap)
        )
    errors.extend(validate_docs(root, rust, python, rust_names, python_names))
    return errors


def main() -> int:
    errors = validate_counts(REPO)
    if errors:
        print("FAIL - tool-count guard found inconsistent tool surface docs:")
        for error in errors:
            print(f"  - {error}")
        return 1

    rust = count_rust_tools(REPO)
    python = count_python_tools(REPO)
    print(
        "OK - tool surface count matches code and docs: "
        f"{rust + python} product tools ({rust} Rust + {python} Python)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
