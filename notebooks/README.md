# notebooks/ — Kaggle submission

Code competition: you submit a **Notebook** that writes `attack.py` to
`/kaggle/working/` and serves the inference server. During the scored rerun
(`KAGGLE_IS_COMPETITION_RERUN`), Kaggle's gateway loads `attack.py` and replays
each `AttackCandidate` against the four leaderboards.

## Files
- `build_submission.py` — generates `submit.ipynb` from the repo's `attack.py`
  (single source of truth; base64-embedded to avoid quote collisions). Mirrors
  the official starter's 3 cells: setup sys.path → write attack.py → `serve()`.
- `submit.ipynb` — generated notebook (regenerate after editing `attack.py`).
- `kernel-metadata.json` — push config. **GPU (T4) required**, internet off,
  competition attached (matches the official starter's metadata).

## Regenerate after changing attack.py
```bash
uv run python notebooks/build_submission.py
```

## Submit (consumes GPU quota + a daily submission slot)
```bash
# 1. push + run the notebook on Kaggle (this runs the real GPT-OSS/Gemma agents)
uv run kaggle kernels push -p notebooks
# 2. watch until it finishes committing
uv run kaggle kernels status futabato/jed-attack-submission
# 3. submit the committed version to the competition via the notebook's
#    "Submit to Competition" button on kaggle.com (code-competition flow).
```

## Caveats
- Each run drives 20B-class models on T4 for the full budget across 4 boards →
  significant **GPU-hour** cost. Check remaining quota first.
- Per-day submission limit is unconfirmed (CLAUDE.md §8) — don't burn slots.
- `attack.py`'s yield is unvalidated against the real agents locally (no GPU);
  the first submission establishes the pipeline + a leaderboard baseline.
