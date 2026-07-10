"""Fail-fast collection limits for semantic finding pipelines."""

from __future__ import annotations

from collections.abc import Iterable, Sized
from typing import TypeVar

MAX_FINDINGS_PER_POOL = 50
MAX_MERGED_FINDINGS = MAX_FINDINGS_PER_POOL * 2
MAX_VERIFY_BATCH = MAX_MERGED_FINDINGS
MAX_TOOL_CALL_INDEX_ENTRIES = 256

T = TypeVar("T")


class SemanticInputLimitError(ValueError):
    """A semantic stage received more records than its reviewed budget."""


def require_collection_limit(name: str, values: Sized, limit: int) -> None:
    """Reject an already-materialized collection above ``limit``."""
    observed = len(values)
    if observed > limit:
        raise SemanticInputLimitError(f"{name} exceeds limit {limit} (observed {observed})")


def materialize_bounded(name: str, values: Iterable[T], limit: int) -> list[T]:
    """Materialize at most ``limit + 1`` items, then reject oversized iterables."""
    bounded: list[T] = []
    for value in values:
        bounded.append(value)
        if len(bounded) > limit:
            raise SemanticInputLimitError(
                f"{name} exceeds limit {limit} (observed at least {len(bounded)})"
            )
    return bounded


__all__ = [
    "MAX_FINDINGS_PER_POOL",
    "MAX_MERGED_FINDINGS",
    "MAX_TOOL_CALL_INDEX_ENTRIES",
    "MAX_VERIFY_BATCH",
    "SemanticInputLimitError",
    "materialize_bounded",
    "require_collection_limit",
]
