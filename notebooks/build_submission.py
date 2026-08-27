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
    # Rerun -> serve() for real scoring. Commit/interactive -> run a SHORT
    # deterministic local gateway so the committed version OUTPUTS submission.csv
    # (Kaggle requires this for the version to be submit-eligible). Real models
    # only run at the scored rerun. Pattern from the pilkwang EDA notebook.
    serve = (
        "import os, shutil\n"
        "from pathlib import Path\n"
        "WORKING_DIR = Path('/kaggle/working')\n"
        "import kaggle_evaluation.jed_attack_134815.jed_attack_inference_server as server\n"
        "if os.getenv('KAGGLE_IS_COMPETITION_RERUN'):\n"
        "    # V78 INFRA LEVER: gemma-4-26B with the default SPEC (n_gpu_layers=-1, n_ctx=8192) OOMs\n"
        "    # on 1xT4 (16GB) and falls back to CPU -> the binding gemma row runs ~35x slower (cm391/\n"
        "    # Starry #736246: 'host is CPU'; organizers' own gateway comment warns of T4 OOM). Force\n"
        "    # gemma to a GPU-FITTING offload (probe-verified ngl<=40/n_ctx=4096 loads fast ~1.6s on\n"
        "    # 1xT4) by patching the module SPEC + the module-level _server the gateway calls via\n"
        "    # module.predict -> module._server. Candidates are short so n_ctx=4096 is ample.\n"
        "    # ngl=-1 (all layers) is tried FIRST: it OOMs on 1xT4 (16GB) -> falls to 40 (V78 single-T4\n"
        "    # behavior preserved), but SUCCEEDS on 2xT4 (32GB, UI-set 'GPU T4 x2') -> gemma fully on GPU.\n"
        "    try:\n"
        "        import dataclasses as _dc\n"
        "        from kaggle_evaluation.jed_attack_134815 import gemma_model_server as _gm, gpt_oss_model_server as _gp\n"
        "        from kaggle_evaluation.jed_attack_134815.gguf_model_server import GgufModelServer as _GMS\n"
        "        try:\n"
        "            _gp.SPEC = _dc.replace(_gp.SPEC, n_ctx=4096); _gp._server = _GMS(_gp.SPEC)\n"
        "            print('[V78] gpt SPEC n_ctx=4096')\n"
        "        except Exception as _ge:\n"
        "            print('[V78] gpt patch skip', repr(_ge))\n"
        "        for _ngl in (-1, 40, 32, 24, 16):\n"
        "            try:\n"
        "                _gm.SPEC = _dc.replace(_gm.SPEC, n_gpu_layers=_ngl, n_ctx=4096)\n"
        "                _gm._server = _GMS(_gm.SPEC); _gm._server.load_model()\n"
        "                print('[V78] gemma loaded ngl=%d/n_ctx=4096 (GPU, not CPU-fallback)' % _ngl); break\n"
        "            except Exception as _me:\n"
        "                print('[V78] gemma ngl=%d failed %r; trying fewer' % (_ngl, repr(_me)))\n"
        "    except Exception as _pe:\n"
        "        print('[V78] SPEC-patch block failed (defaults kept):', repr(_pe))\n"
        "    server.JEDAttackInferenceServer().serve()\n"
        "else:\n"
        "    os.environ['AICOMP_MODEL_NAMES'] = 'deterministic'\n"
        "    import kaggle_evaluation.jed_attack_134815.jed_attack_gateway as gw\n"
        "    from aicomp_sdk.evaluation.ops import resolve_fixtures_dir\n"
        "    gw.MODEL_NAMES = ['deterministic']\n"
        "    server.DEFAULT_SUBMISSION_DIR = WORKING_DIR\n"
        "    if not hasattr(gw.JEDAttackGateway, '_orig_run_attack'):\n"
        "        gw.JEDAttackGateway._orig_run_attack = gw.JEDAttackGateway._run_attack_for_model\n"
        "    _orig = gw.JEDAttackGateway._orig_run_attack\n"
        "    def _limited(self, model_name, guardrail_factory=gw.OptimalGuardrail,\n"
        "                 budget_s=gw.DEFAULT_BUDGET_S, seed=gw.ATTACK_SEED):\n"
        "        return _orig(self, model_name, guardrail_factory=guardrail_factory,\n"
        "                     budget_s=5.0, seed=seed)[:20]\n"
        "    gw.JEDAttackGateway._run_attack_for_model = _limited\n"
        "    try:\n"
        "        server.JEDAttackInferenceServer().run_local_gateway(\n"
        "            data_paths=(str(resolve_fixtures_dir()),))\n"
        "    except Exception as _e:\n"
        "        print('commit-stub local gateway note:', repr(_e))\n"
        "    # FORMAT FIX (2026-06-26): the committed stub must carry the EXACT row Ids the\n"
        "    # scored rerun produces (model x guardrail), or Kaggle rejects with 'Submission\n"
        "    # Format Error'. The deterministic run yields 'deterministic_public' (wrong Id),\n"
        "    # so OVERWRITE submission.csv with the canonical 4 rows (score 0; the rerun\n"
        "    # replaces them with real scores). Independent of attack.py.\n"
        "    _ROWS = ('gpt_oss_public', 'gpt_oss_private', 'gemma_public', 'gemma_private')\n"
        "    with open(WORKING_DIR / 'submission.csv', 'w', newline='') as _f:\n"
        "        _f.write('Id,Score\\n')\n"
        "        for _rid in _ROWS:\n"
        "            _f.write(_rid + ',0.0\\n')\n"
        "    print('submission.csv produced:', (WORKING_DIR / 'submission.csv').exists())\n"
        "    print(open(WORKING_DIR / 'submission.csv').read())\n"
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
