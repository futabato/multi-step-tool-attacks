"""recon/sdk_monitor.py — watch the evaluator's OSS mirror for changes, offline-of-Kaggle.

The competition evaluator lands as code in the OSS mirror BEFORE the organizers post
a discussion announcement (verified 2026-06-22: the "Monday update" was already on
`mbhatt1/competitionscratch` master days early). This script diffs the strategy-relevant
SDK files in that mirror against a pinned baseline we control, so we learn EXACTLY what
changed (not prose) the moment it lands — and never get surprised by a silent rescore.

Needs only the `gh` CLI (GitHub API). No Kaggle creds, no model, no SDK import.

USAGE:
  python recon/sdk_monitor.py --init      # snapshot the mirror NOW as the baseline (first run)
  python recon/sdk_monitor.py             # CHECK: diff mirror vs baseline; exit 1 if changed
  python recon/sdk_monitor.py --update     # accept current mirror as the new baseline (after review)
  python recon/sdk_monitor.py --vs-local   # also diff the mirror against our comp/aicomp_sdk copy

The baseline (recon/sdk_monitor/baseline/ + state.json) is committed to git, so each
`--update` records the evaluator's evolution in our history. Run from cron / a /loop to
get alerted: a nonzero exit means "the evaluator changed — go read the diff."
"""
from __future__ import annotations

import argparse
import base64
import difflib
import hashlib
import json
import subprocess
import sys
from pathlib import Path

REPO = "mbhatt1/competitionscratch"
BRANCH = "master"

# Strategy-relevant files (paths within the mirror repo). Edit freely — anything whose
# change would move our score or invalidate a confirmed fact belongs here.
WATCH = [
    "aicomp_sdk/core/predicates.py",     # secret matching / EXFILTRATION / SECRET_MARKER sentinel
    "aicomp_sdk/scoring.py",             # raw = Σseverity + 2×cells; normalized = raw/200
    "aicomp_sdk/core/cells.py",          # score_cell_signature (http.post url bucketing / fs paths)
    "aicomp_sdk/guardrails/optimal.py",  # public guardrail: keyword block + last-5 taint
    "aicomp_sdk/core/env/sandbox.py",    # taint window, guardrail context, interact() loop
    "aicomp_sdk/evaluation/ops.py",      # replay + eval wiring (hops, both-guardrail replay)
]

_REPO_ROOT = Path(__file__).resolve().parent.parent
_BASE_DIR = _REPO_ROOT / "recon" / "sdk_monitor" / "baseline"
_STATE = _REPO_ROOT / "recon" / "sdk_monitor" / "state.json"
_LOCAL_SDK = _REPO_ROOT / "comp"   # our pinned copy lives at comp/aicomp_sdk/...


def _gh_json(endpoint: str):
    out = subprocess.run(["gh", "api", endpoint], capture_output=True, text=True)
    if out.returncode != 0:
        raise SystemExit(f"gh api {endpoint} failed:\n{out.stderr.strip()}")
    return json.loads(out.stdout)


def _flat(path: str) -> str:
    return path.replace("/", "__")


def _fetch_file(path: str) -> str | None:
    """Return the file's text from the mirror, or None if it 404s (deleted/moved)."""
    out = subprocess.run(
        ["gh", "api", f"repos/{REPO}/contents/{path}?ref={BRANCH}", "--jq", ".content"],
        capture_output=True, text=True,
    )
    if out.returncode != 0:
        if "Not Found" in out.stderr or "404" in out.stderr:
            return None
        raise SystemExit(f"gh api contents/{path} failed:\n{out.stderr.strip()}")
    return base64.b64decode(out.stdout).decode("utf-8", "replace")


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def _head_commit() -> dict:
    c = _gh_json(f"repos/{REPO}/commits?sha={BRANCH}&per_page=1")[0]
    return {"sha": c["sha"][:12], "date": c["commit"]["committer"]["date"],
            "msg": c["commit"]["message"].splitlines()[0]}


def _snapshot() -> dict:
    """Fetch all watched files + head commit. Returns {path: text|None} and meta."""
    files = {p: _fetch_file(p) for p in WATCH}
    return {"head": _head_commit(), "files": files}


def _write_baseline(snap: dict) -> None:
    _BASE_DIR.mkdir(parents=True, exist_ok=True)
    state = {"head": snap["head"], "files": {}}
    for p, text in snap["files"].items():
        fp = _BASE_DIR / _flat(p)
        if text is None:
            if fp.exists():
                fp.unlink()
            state["files"][p] = None
        else:
            fp.write_text(text, encoding="utf-8")
            state["files"][p] = _sha(text)
    _STATE.write_text(json.dumps(state, indent=2), encoding="utf-8")


def _read_baseline_text(path: str) -> str | None:
    fp = _BASE_DIR / _flat(path)
    return fp.read_text(encoding="utf-8") if fp.exists() else None


def _diff(old: str | None, new: str | None, label: str) -> str:
    old_l = (old or "").splitlines(keepends=True)
    new_l = (new or "").splitlines(keepends=True)
    return "".join(difflib.unified_diff(old_l, new_l, f"baseline/{label}", f"mirror/{label}", n=2))


def _check(update: bool, vs_local: bool) -> int:
    if not _STATE.exists():
        raise SystemExit("No baseline yet. Run:  python recon/sdk_monitor.py --init")
    state = json.loads(_STATE.read_text())
    print(f"[baseline] head {state['head']['sha']} {state['head']['date']}  {state['head']['msg']}")
    snap = _snapshot()
    h = snap["head"]
    print(f"[mirror  ] head {h['sha']} {h['date']}  {h['msg']}")
    if h["sha"] != state["head"]["sha"]:
        print(f"[!] mirror HEAD advanced {state['head']['sha']} -> {h['sha']} (some commit landed)")

    changed = []
    for p in WATCH:
        new = snap["files"][p]
        old = _read_baseline_text(p)
        old_sha = state["files"].get(p)
        new_sha = _sha(new) if new is not None else None
        if new_sha != old_sha:
            changed.append(p)
            tag = "DELETED" if new is None else ("ADDED" if old_sha is None else "CHANGED")
            print(f"\n===== {tag}: {p} =====")
            print(_diff(old, new, p) or "(metadata differs, no textual diff)")
        else:
            print(f"  unchanged: {p}")

    if vs_local:
        print("\n----- mirror vs our pinned comp/aicomp_sdk (drift from what we analyzed) -----")
        for p in WATCH:
            local = _LOCAL_SDK / p
            ltext = local.read_text(encoding="utf-8") if local.exists() else None
            new = snap["files"][p]
            if (_sha(ltext) if ltext is not None else None) != (_sha(new) if new is not None else None):
                print(f"\n===== mirror DIFFERS from local: {p} =====")
                print(_diff(ltext, new, p) or "(one side missing)")
            else:
                print(f"  matches local: {p}")

    if changed and update:
        _write_baseline(snap)
        print(f"\n[updated] baseline advanced to {h['sha']} ({len(changed)} file(s)). Commit recon/sdk_monitor/ to record it.")
        return 0
    if changed:
        print(f"\n[ALERT] {len(changed)} watched file(s) changed: {changed}")
        print("Review the diff, update CLAUDE.md/docs/memory, then run --update to accept.")
        return 1
    print("\n[ok] no watched file changed since baseline.")
    return 0


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--init", action="store_true", help="snapshot the mirror now as the baseline")
    ap.add_argument("--update", action="store_true", help="accept current mirror as the new baseline (after review)")
    ap.add_argument("--vs-local", action="store_true", help="also diff the mirror against our comp/aicomp_sdk copy")
    args = ap.parse_args()

    if args.init:
        snap = _snapshot()
        _write_baseline(snap)
        print(f"[init] baseline pinned at {snap['head']['sha']} {snap['head']['date']}  {snap['head']['msg']}")
        present = [p for p, t in snap["files"].items() if t is not None]
        missing = [p for p, t in snap["files"].items() if t is None]
        print(f"[init] {len(present)} files snapshotted; {len(missing)} not found: {missing}")
        print("[init] commit recon/sdk_monitor/ to track. Thereafter run with no args to check.")
        return
    sys.exit(_check(update=args.update, vs_local=args.vs_local))


if __name__ == "__main__":
    main()
