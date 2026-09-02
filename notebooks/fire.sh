#!/usr/bin/env bash
# fire.sh — push a submission variant WITHOUT mutating the live kernel-metadata.json.
# Usage:  bash notebooks/fire.sh <MODE> <SHAPE>
#   MODE  = adaptive_k2 | deputy_adaptive_wall | ... (sets DEFAULT_FILL_MODE in attack.py)
#   SHAPE = t4 (NvidiaTeslaT4, default single-T4) | gpu (generic "Gpu", ducnamphan 32GB route)
# Builds submit.ipynb from attack.py, assembles a TEMP push dir with the chosen metadata,
# and pushes the kernel version. You then click "Submit" on that version in the Kaggle UI.
# The V78 gemma-GPU-fit SPEC patch lives in build_submission.py (rerun path) — orthogonal, always on.
set -euo pipefail
cd "$(dirname "$0")/.."
MODE="${1:?need MODE}"; SHAPE="${2:-t4}"

# 1. set the fill mode (restore on exit so the repo state is not left mutated)
ORIG="$(grep -oP 'DEFAULT_FILL_MODE = "\K[^"]+' attack.py)"
restore(){ sed -i "s/^DEFAULT_FILL_MODE = \"[^\"]*\"/DEFAULT_FILL_MODE = \"$ORIG\"/" attack.py; echo "[fire] restored DEFAULT_FILL_MODE=$ORIG"; }
trap restore EXIT
sed -i "s/^DEFAULT_FILL_MODE = \"[^\"]*\"/DEFAULT_FILL_MODE = \"$MODE\"/" attack.py
echo "[fire] DEFAULT_FILL_MODE set to $MODE (was $ORIG)"

# 2. rebuild the notebook from attack.py
uv run python notebooks/build_submission.py

# 3. assemble a temp push dir (never touches live kernel-metadata.json)
TMP="$(mktemp -d)"
cp notebooks/submit.ipynb "$TMP/"
case "$SHAPE" in
  gpu) cp notebooks/kernel-metadata.gpu.json "$TMP/kernel-metadata.json";;
  t4)  cp notebooks/kernel-metadata.json     "$TMP/kernel-metadata.json";;
  *)   echo "[fire] unknown SHAPE=$SHAPE (use t4|gpu)"; exit 1;;
esac
echo "[fire] push dir: $TMP  (shape=$SHAPE, machine_shape=$(grep -oP '"machine_shape": "\K[^"]+' "$TMP/kernel-metadata.json"))"

# 4. push the kernel version
uvx --from kaggle kaggle kernels push -p "$TMP"
echo "[fire] pushed. Now open the kernel on kaggle.com, wait for the commit run to finish,"
echo "[fire] then click 'Submit to Competition' on this version (MODE=$MODE SHAPE=$SHAPE)."
