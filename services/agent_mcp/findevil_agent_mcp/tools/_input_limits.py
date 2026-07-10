"""Iterative JSON-shape budgets for model-controlled semantic MCP inputs."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from findevil_agent.resource_limits import MAX_TOOL_CALL_INDEX_ENTRIES

MAX_JSON_DEPTH = 12
MAX_JSON_NODES = 50_000
MAX_JSON_STRING_CHARS = 4_096
MAX_JSON_TOTAL_STRING_CHARS = 2 * 1024 * 1024
MAX_JSON_CONTAINER_ITEMS = 10_000
MAX_JSON_KEY_CHARS = 256


def enforce_json_budget(value: Any, *, label: str) -> Any:
    """Reject hostile JSON shapes without recursive Python traversal.

    The MCP transport has already decoded JSON by this point. This pass limits
    the work performed by later Pydantic/domain validation and prevents deep
    nesting, huge strings, and aggregate container amplification.
    """
    stack: list[tuple[Any, int]] = [(value, 0)]
    seen_containers: set[int] = set()
    nodes = 0
    total_string_chars = 0

    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise ValueError(f"{label} JSON node limit exceeded ({MAX_JSON_NODES})")
        if depth > MAX_JSON_DEPTH:
            raise ValueError(f"{label} JSON nesting depth limit exceeded ({MAX_JSON_DEPTH})")

        if isinstance(current, str):
            if len(current) > MAX_JSON_STRING_CHARS:
                raise ValueError(
                    f"{label} JSON string length limit exceeded ({MAX_JSON_STRING_CHARS})"
                )
            total_string_chars += len(current)
        elif isinstance(current, Mapping):
            identity = id(current)
            if identity in seen_containers:
                raise ValueError(f"{label} contains a cyclic mapping")
            seen_containers.add(identity)
            if len(current) > MAX_JSON_CONTAINER_ITEMS:
                raise ValueError(
                    f"{label} JSON mapping item limit exceeded ({MAX_JSON_CONTAINER_ITEMS})"
                )
            for key, child in current.items():
                if not isinstance(key, str):
                    raise ValueError(f"{label} JSON mapping keys must be strings")
                if len(key) > MAX_JSON_KEY_CHARS:
                    raise ValueError(
                        f"{label} JSON key length limit exceeded ({MAX_JSON_KEY_CHARS})"
                    )
                total_string_chars += len(key)
                stack.append((child, depth + 1))
        elif isinstance(current, Sequence) and not isinstance(
            current, bytes | bytearray | memoryview
        ):
            identity = id(current)
            if identity in seen_containers:
                raise ValueError(f"{label} contains a cyclic sequence")
            seen_containers.add(identity)
            if len(current) > MAX_JSON_CONTAINER_ITEMS:
                raise ValueError(
                    f"{label} JSON sequence item limit exceeded ({MAX_JSON_CONTAINER_ITEMS})"
                )
            stack.extend((child, depth + 1) for child in current)

        if total_string_chars > MAX_JSON_TOTAL_STRING_CHARS:
            raise ValueError(
                f"{label} aggregate JSON string limit exceeded " f"({MAX_JSON_TOTAL_STRING_CHARS})"
            )
    return value


__all__ = ["MAX_TOOL_CALL_INDEX_ENTRIES", "enforce_json_budget"]
