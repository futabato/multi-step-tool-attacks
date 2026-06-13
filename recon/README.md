# recon/ — offline white-box recon (LLM allowed)

Per CLAUDE.md §5/§7: recon is **offline, white-box, may use an attacker LLM**, and
does NOT consume the competition's 9,000s budget. Its outputs are **confirmed,
deterministic payload strings / arg variants** that get baked into `attack.py`.

The in-env search loop (`attacklib.harness`) stays LLM-free and deterministic.

## What lives here
- Experiments that drive a local replica of GPT-OSS (Apache-2.0) / Gemma to find
  which injected payloads reliably steer the agent into predicate-triggering,
  guardrail-passing tool calls.
- Parsing-boundary probes (harmony `analysis` channel; Gemma `tool_code` block).
- Fixture inspection (`comp/aicomp_sdk/fixtures/`): injection surfaces and
  multi-hop seeds (`secret.txt`, `api_keys.txt`, `mh_*.txt`, `web_corpus.json`,
  `mail_seed.json`).

## Notes
- Driving the real agents needs the `[agents]` extra (torch) and a GPU:
  `uv sync --extra agents`. On CPU/WSL, prefer synthetic traces (see `tests/`)
  or a deterministic agent for logic work.
- Anything non-deterministic must be frozen before it reaches `attack.py`
  (CLAUDE.md §6): replay must reproduce the finding exactly.
