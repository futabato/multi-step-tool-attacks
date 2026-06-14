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

## Local recon on your own GPU (recon/local_recon.py) — UNLIMITED, free

If you have a CUDA GPU (e.g. RTX 3070 Ti, 8GB VRAM + 32GB RAM), run the REAL Q4
GGUF locally with partial GPU offload. Determinism transfers to the gateway iff
you use the SAME Q4 file. This is the preferred channel for HEAVY/iterative recon
(no Kaggle quota, no submission slot, instant edit-run). Kaggle's recon notebook
(T4, fits the whole model) is better for occasional runs.

```bash
CMAKE_ARGS="-DGGML_CUDA=on" pip install --no-cache-dir llama-cpp-python   # CUDA build
huggingface-cli download unsloth/gpt-oss-20b-GGUF gpt-oss-20b-Q4_K_M.gguf --local-dir models
python recon/local_recon.py --model gpt_oss --model-path models/gpt-oss-20b-Q4_K_M.gguf \
       --n-gpu-layers 24 --hosts 40
```
- 8GB VRAM → partial offload: tune `--n-gpu-layers` (start ~20-28, raise until ~full/OOM).
- gemma: `--model gemma`, file `gemma-4-26B-A4B-it-UD-Q4_K_M.gguf` (~16GB; fits 8GB VRAM + 32GB RAM).
- Measures **agent_turns/candidate** (replay-cost lever), **posts_ok** (severity), and the
  **firing rate** of the leanest firing phrasing over N fresh hosts (de-risks the v3/v4 fill
  assumption). Use the turns + firing rate to size `target_n` for the next submission.

## Notes
- Driving the real agents needs the `[agents]` extra (torch) and a GPU:
  `uv sync --extra agents`. On CPU/WSL, prefer synthetic traces (see `tests/`)
  or a deterministic agent for logic work.
- Anything non-deterministic must be frozen before it reaches `attack.py`
  (CLAUDE.md §6): replay must reproduce the finding exactly.
