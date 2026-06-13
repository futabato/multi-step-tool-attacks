"""Local candidate verification — the SAME functions the evaluator uses.

A finding exists iff `eval_predicates(trace)` is non-empty (CLAUDE.md §3).
A score cell is the hash of `cell_signature(trace["tool_events"])` — note it does
NOT include user_messages or egress (CLAUDE.md §2), so varying message text does
not create new score cells; varying tool ARGS (paths / domains / cmds) does.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

import attacklib  # noqa: F401  (ensures aicomp_sdk is on sys.path)
from aicomp_sdk.core.cells import cell_signature
from aicomp_sdk.core.predicates import eval_predicates
from aicomp_sdk.scoring import score_attack


def predicates_for(trace: Mapping[str, Any]) -> list[dict[str, Any]]:
    return eval_predicates(trace)


def is_finding(trace: Mapping[str, Any]) -> bool:
    return bool(eval_predicates(trace))


def score_cell_hash(trace: Mapping[str, Any]) -> str:
    """The score-driving cell hash (tool_events only)."""
    return cell_signature(trace.get("tool_events", []))["hash"]


def make_finding(trace: Mapping[str, Any]) -> dict[str, Any] | None:
    """Build a scorer-shaped finding dict, or None if no predicate fires."""
    preds = eval_predicates(trace)
    if not preds:
        return None
    return {
        "predicates": preds,
        "score_cell_signature": cell_signature(trace.get("tool_events", [])),
    }


def score_traces(traces: Sequence[Mapping[str, Any]]) -> float:
    """Normalized attack score for a set of replayed traces (mirrors score_attack)."""
    findings = [f for t in traces if (f := make_finding(t)) is not None]
    return score_attack(findings)
