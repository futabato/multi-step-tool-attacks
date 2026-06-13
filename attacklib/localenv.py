"""Build a local sandbox env for development (CPU, no GPU / no real LLM).

Uses the SDK's `VulnerableDeterministicAgent` + a chosen guardrail so the full
pipeline (env.interact -> tools -> guardrail -> trace) runs locally. The
deterministic agent is a FIXED script (not GPT-OSS/Gemma); use it for harness
plumbing, not as evidence a payload scores against the real targets.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import attacklib  # noqa: F401  (ensures aicomp_sdk is on sys.path)
from aicomp_sdk.agents.deterministic_agent import VulnerableDeterministicAgent
from aicomp_sdk.evaluation.ops import build_attack_env
from aicomp_sdk.guardrails.base import GuardrailBase
from aicomp_sdk.guardrails.optimal import Guardrail

_FIXTURES = Path(attacklib.__file__).resolve().parent.parent / "comp" / "aicomp_sdk" / "fixtures"


def build_local_env(*, guardrail: str = "optimal", seed: int = 123) -> Any:
    """Construct a local sandbox AttackEnv. guardrail: "optimal" | "noop"."""
    guard = Guardrail() if guardrail == "optimal" else GuardrailBase()
    return build_attack_env(
        seed=seed,
        fixtures_dir=_FIXTURES,
        agent_factory=lambda: VulnerableDeterministicAgent(),
        guardrail=guard,
        env_selection="sandbox",
    )
