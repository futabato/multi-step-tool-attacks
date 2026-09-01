"""Assemble recon.ipynb = INSTALL + SETUP + recon/multistep_oracle_cell.py and push.

Reuses build_recon's INSTALL (llama-cpp CUDA) and SETUP (SDK sys.path) cells, then
appends the standalone multi-step oracle cell. Measures whether the real GPT-OSS /
Gemma agent emits a read->act chain (web/email -> http.post/fs.write/shell) under a
PERMISSIVE guardrail and whether UNTRUSTED_TO_ACTION fires. GPU T4, internet ON.

Run:  uv run python notebooks/build_recon_multistep.py   (writes notebooks/recon.ipynb)
Then: uvx --from kaggle kaggle kernels push -p notebooks/recon_kernel
"""
from __future__ import annotations
import json
from pathlib import Path

import build_recon  # reuse INSTALL + SETUP

_HERE = Path(__file__).resolve().parent
_CELL = (_HERE.parent / "recon" / "multistep_oracle_cell.py").read_text()
_OUT = _HERE / "recon_kernel" / "recon.ipynb"


def _code(src):
    return {"cell_type": "code", "metadata": {}, "execution_count": None,
            "outputs": [], "source": src.strip("\n").splitlines(keepends=True)}


def _md(src):
    return {"cell_type": "markdown", "metadata": {}, "source": src.splitlines(keepends=True)}


def build():
    nb = {
        "cells": [
            _md("# Multi-step oracle — the competition's INTENDED attack (read -> act)\n\n"
                "Does the real GPT-OSS / Gemma agent emit a web/email read followed by a "
                "dangerous act (http.post / fs.write / shell.run) across hops, and does "
                "UNTRUSTED_TO_ACTION fire? Run under a PERMISSIVE guardrail (best case for a "
                "lenient private guard). Public-dead (taint), so this only proves the mechanism. "
                "GPU T4, internet ON. Not a submission."),
            _code(build_recon.INSTALL),
            _code(build_recon.SETUP),
            _code(_CELL),
        ],
        "metadata": {"kernelspec": {"language": "python", "name": "python3", "display_name": "Python 3"},
                     "language_info": {"name": "python"}},
        "nbformat": 4, "nbformat_minor": 5,
    }
    _OUT.write_text(json.dumps(nb, ensure_ascii=False, indent=1))
    print(f"Wrote {_OUT}")


if __name__ == "__main__":
    build()
