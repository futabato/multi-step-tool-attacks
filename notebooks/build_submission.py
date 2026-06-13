"""Generate notebooks/submit.ipynb from the repo's attack.py (single source of truth).

The notebook mirrors the official starter's 3-step structure:
  1. put the competition dataset (kaggle_evaluation/ + aicomp_sdk/) on sys.path
  2. write /kaggle/working/attack.py  (embedded base64 to avoid quote collisions)
  3. start the inference server: JEDAttackInferenceServer().serve()

Run:  uv run python notebooks/build_submission.py
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
_ATTACK = _REPO / "attack.py"
_OUT = _REPO / "notebooks" / "submit.ipynb"


def _code_cell(src: str) -> dict:
    return {"cell_type": "code", "metadata": {}, "execution_count": None,
            "outputs": [], "source": src.splitlines(keepends=True)}


def _md_cell(src: str) -> dict:
    return {"cell_type": "markdown", "metadata": {}, "source": src.splitlines(keepends=True)}


def build() -> None:
    b64 = base64.b64encode(_ATTACK.read_bytes()).decode("ascii")
    setup = (
        "import sys, glob\n"
        "from pathlib import Path\n"
        "sys.argv = [sys.argv[0]]  # avoid argparse conflicts in notebooks\n"
        "for c in glob.glob('/kaggle/input/**/kaggle_evaluation', recursive=True):\n"
        "    root = str(Path(c).parent)\n"
        "    if root not in sys.path:\n"
        "        sys.path.insert(0, root)\n"
        "    print('Dataset root:', root)\n"
        "    break\n"
        "print('Setup complete ✅')\n"
    )
    write_attack = (
        "import base64\n"
        "from pathlib import Path\n"
        f"_ATTACK_B64 = '{b64}'\n"
        "Path('/kaggle/working/attack.py').write_bytes(base64.b64decode(_ATTACK_B64))\n"
        "print('Wrote /kaggle/working/attack.py ✅')\n"
    )
    serve = (
        "import kaggle_evaluation.jed_attack_134815.jed_attack_inference_server as server\n"
        "server.JEDAttackInferenceServer().serve()\n"
    )
    nb = {
        "cells": [
            _md_cell("# JED Attack — Submission\n\nEXFILTRATION-first verify-and-keep "
                     "search (see CLAUDE.md). attack.py is the single source of truth; "
                     "this notebook materializes it and serves the inference server."),
            _code_cell(setup),
            _code_cell(write_attack),
            _code_cell(serve),
        ],
        "metadata": {
            "kernelspec": {"language": "python", "name": "python3", "display_name": "Python 3"},
            "language_info": {"name": "python"},
        },
        "nbformat": 4, "nbformat_minor": 5,
    }
    _OUT.write_text(json.dumps(nb, ensure_ascii=False, indent=1))
    print(f"Wrote {_OUT} ({_OUT.stat().st_size} bytes; attack.py={_ATTACK.stat().st_size}B)")


if __name__ == "__main__":
    build()
