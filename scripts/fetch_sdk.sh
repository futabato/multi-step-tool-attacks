#!/usr/bin/env bash
# Re-download the competition SDK (aicomp_sdk + kaggle_evaluation) into comp/.
# comp/ is gitignored; this is how you restore it on a fresh checkout.
set -euo pipefail
cd "$(dirname "$0")/.."

COMP="ai-agent-security-multi-step-tool-attacks"
mkdir -p comp
uv run kaggle competitions download -c "$COMP" -p comp
unzip -q -o "comp/${COMP}.zip" -d comp
rm -f "comp/${COMP}.zip"
echo "SDK refreshed in comp/ (aicomp_sdk $(grep -m1 '^Version' comp/aicomp_sdk-*.dist-info/METADATA 2>/dev/null || echo '?'))"
