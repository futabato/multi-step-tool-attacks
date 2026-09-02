"""Cell archive for coverage-guided search (Go-Explore / MAP-Elites, SOLUTION.md).

Keyed by the score-driving cell hash. Stores, per cell, the user-message chain
that reached it and the predicates/severity it triggered. New cell, or higher
severity for an existing cell, wins.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

_SEVERITY_W = {1: 1, 2: 2, 3: 4, 4: 8, 5: 16}


def severity_sum(predicates: Iterable[Mapping[str, Any]]) -> int:
    return sum(_SEVERITY_W.get(int(p.get("severity", 1)), 1) for p in predicates)


@dataclass
class Entry:
    cell_hash: str
    user_messages: tuple[str, ...]
    predicates: list[dict[str, Any]]
    severity_sum: int


@dataclass
class CellArchive:
    entries: dict[str, Entry] = field(default_factory=dict)

    def __len__(self) -> int:
        return len(self.entries)

    def consider(
        self,
        cell_hash: str,
        user_messages: Iterable[str],
        predicates: Iterable[Mapping[str, Any]],
    ) -> bool:
        """Insert if cell is new or beats the incumbent on severity. True if changed."""
        preds = [dict(p) for p in predicates]
        sev = severity_sum(preds)
        cur = self.entries.get(cell_hash)
        if cur is not None and sev <= cur.severity_sum:
            return False
        self.entries[cell_hash] = Entry(cell_hash, tuple(user_messages), preds, sev)
        return True

    def candidates(self) -> list[tuple[str, ...]]:
        """The replayable user-message chains, one per cell."""
        return [e.user_messages for e in self.entries.values()]

    def total_severity(self) -> int:
        return sum(e.severity_sum for e in self.entries.values())
