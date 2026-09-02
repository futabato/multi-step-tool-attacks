"""Deterministic local search harness (skeleton, SOLUTION.md).

Drives `env.interact(...)` with seed/mutated user messages, observes the trace,
verifies findings locally (attacklib.verify), and fills a CellArchive. Go-Explore
branching uses env.snapshot()/restore(). Control flow is LLM-free; the only
stochastic part is the target agent, which must be seeded / temperature-0 for
replay determinism (SOLUTION.md).

Building a real `env` that drives GPT-OSS/Gemma needs the [agents] extra (torch)
and a GPU. For logic development without a model, construct synthetic traces (see
tests/) or a deterministic/fake agent. See recon/README.md.
"""
from __future__ import annotations

from collections.abc import Iterable

from attacklib.archive import CellArchive
from attacklib.verify import make_finding, score_cell_hash


def explore_seeds(env, seeds: Iterable[str], *, max_tool_hops: int = 8) -> CellArchive:
    """One pass: replay each seed message, archive any finding by its score cell."""
    archive = CellArchive()
    for msg in seeds:
        env.reset()
        env.interact(msg, max_tool_hops=max_tool_hops)
        trace = env.export_trace_dict()
        finding = make_finding(trace)
        if finding is None:
            continue
        archive.consider(
            score_cell_hash(trace),
            trace.get("user_messages", []),
            finding["predicates"],
        )
    return archive


# TODO(stage1): mutation loop with UCB1 seed selection + snapshot/restore branching
#   (AgentVigil: seed -> MCTS -> mutate -> coverage). Use attacklib.mutate operators.
