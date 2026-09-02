# Multi-Step Tool Attacks — a Kaggle solution

Our entry for the Kaggle competition **[AI Agent Security: Multi-Step Tool
Attacks](https://www.kaggle.com/competitions/ai-agent-security-multi-step-tool-attacks)**
($50,000). The deliverable is `attack.py`: a coverage-guided **indirect
prompt-injection search policy** that drives a fixed agent (GPT-OSS / Gemma)
through user messages so it makes predicate-triggering tool calls that survive a
guardrail, maximizing distinct score **cells**. There is no model to train: the
entry is a search that emits attack candidates.

## Result

| | public | private (the prize) |
|---|--:|--:|
| **exfiltration submission** (marker throughput) | **91.585** | **0.000** |
| **confused-deputy submission** (unauthorized `email.send`) | 25.155 | **25.185** ← our score |

The private rerun runs the same candidates against a **held-out** guardrail. The
public score did not carry over: our high-throughput exfiltration submission scored
**0** on private, along with **2,885 other teams**. The submission that carried us —
an attack that reads no data and leaks no secret — transferred almost exactly
(**25.155 → 25.185**). Selecting it by hand, rather than letting auto-select keep
our two highest *public* scores, was the decisive move.

**[SOLUTION.md](SOLUTION.md)** is the write-up (paper format): reproducing the
public score offline, routing a prompt per model, and predicting offline which
attack would transfer to the held-out guardrail. 日本語版は
**[SOLUTION_ja.md](SOLUTION_ja.md)**。

## Layout

```
attack.py       # THE DELIVERABLE — self-contained AttackAlgorithm(AttackAlgorithmBase),
                #   written to /kaggle/working/. Does NOT import attacklib.
attacklib/      # Local dev library (not submitted): harness, archive, seeds, mutate, verify.
recon/          # Offline white-box recon: local_score.py (predict the score offline),
                #   private_guardrail_sim.py (a stand-in for the held-out guardrail).
docs/           # Research notes and surveys (QD/Go-Explore, reward hacking, IPI formats,
                #   the scoring surface, red-team lessons). See docs/README.md.
notebooks/      # Submission packaging (build_submission.py, kernel metadata).
tests/          # Deterministic tests for the attack policy and our reading of the oracle.
external/       # Submodule: a community proxy for the private eval (aduriseti).
SOLUTION.md     # The write-up (SOLUTION_ja.md is the Japanese version).
```

## Reproduce

The competition SDK (`aicomp_sdk`, `kaggle_evaluation`) is **not vendored** — it is
git-ignored under `comp/`. Fetch it with `scripts/fetch_sdk.sh`, then:

```bash
uv sync
uv run python -m pytest tests/ -q          # deterministic policy + oracle tests
uv run python recon/local_score.py --help  # predict a submission's score offline
```

`attack.py` is standalone: the Kaggle evaluator loads it, calls
`AttackAlgorithm().run(env, config)`, and replays the returned `user_messages`.

## License

[MIT](LICENSE).
