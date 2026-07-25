#!/usr/bin/env python3
"""competitor_feed.py — poll the Kaggle competition's discussion + leaderboard + public
notebooks, DIFF against the last snapshot, and append only what's NEW to a digest.

The competition is a moving target: the 88->~110 levers keep surfacing in the forum
(pilkwang throughput note, cleanorlabs, The T-MAN's continuation multi-post claim, Victor
Mercklé confirming the knapsack/packing view). This gives us a low-noise change feed instead
of re-reading everything by hand.

Usage:
    uv run python recon/competitor_feed.py            # poll, print + append the delta
    uv run python recon/competitor_feed.py --full     # print the full current state too

State (persists across runs, so a system cron / manual run works too):
    recon/feed/snapshot.json   last-seen state (topics, LB top-N, notebooks)
    recon/feed/digest.md       append-only log of NEW/CHANGED items, timestamped

WebFetch can't read Kaggle (JS); this shells out to the kaggle CLI (creds already present).
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import re
import subprocess
import sys
from pathlib import Path

COMP = "ai-agent-security-multi-step-tool-attacks"
FEED_DIR = Path(__file__).resolve().parent / "feed"
SNAP = FEED_DIR / "snapshot.json"
DIGEST = FEED_DIR / "digest.md"
KAGGLE = ["uvx", "--from", "kaggle", "kaggle"]
TIMEOUT = 90


def _run(args: list[str]) -> str:
    try:
        out = subprocess.run(KAGGLE + args, capture_output=True, text=True, timeout=TIMEOUT)
        return (out.stdout or "") + (("\n" + out.stderr) if out.returncode else "")
    except Exception as e:  # network/timeout — treat as empty, don't crash the feed
        return f"<error: {e}>"


def _parse_table(text: str) -> list[dict]:
    """Parse a kaggle CLI table (header row, dashed separator, then rows) into dicts keyed by
    header. Columns are whitespace-runs; we split on 2+ spaces to keep multi-word cells."""
    lines = [ln for ln in text.splitlines() if ln.strip()]
    hdr_i = next((i for i, ln in enumerate(lines) if set(ln.strip()) <= set("- ")), -1)
    if hdr_i < 1:
        return []
    headers = re.split(r"\s{2,}", lines[hdr_i - 1].strip())
    rows = []
    for ln in lines[hdr_i + 1:]:
        if ln.startswith("Next Page Token") or set(ln.strip()) <= set("- "):
            continue
        cells = re.split(r"\s{2,}", ln.strip())
        if len(cells) >= 2:
            rows.append({headers[j]: cells[j] for j in range(min(len(headers), len(cells)))})
    return rows


def collect() -> dict:
    topics = _parse_table(_run(["competitions", "topics", "list", COMP]))
    topics += _parse_table(_run(["competitions", "topics", "list", COMP, "--page-token", "2"]))
    lb = _parse_table(_run(["competitions", "leaderboard", COMP, "--show"]))[:30]
    nbs = _parse_table(_run(["kernels", "list", "--competition", COMP,
                             "--sort-by", "dateRun", "--page-size", "40"]))
    return {"topics": topics, "leaderboard": lb, "notebooks": nbs}


def _key(rows: list[dict], k: str) -> dict:
    return {r.get(k, ""): r for r in rows if r.get(k)}


def diff(old: dict, new: dict) -> list[str]:
    lines: list[str] = []
    # topics: new topic ids OR increased commentCount (someone replied)
    o, n = _key(old.get("topics", []), "id"), _key(new.get("topics", []), "id")
    for tid, row in n.items():
        title = row.get("title", "")
        if tid not in o:
            lines.append(f"NEW TOPIC #{tid} [{row.get('votes','?')}v] {title}")
        else:
            oc, nc = o[tid].get("commentCount", "0"), row.get("commentCount", "0")
            if oc != nc:
                lines.append(f"UPDATED #{tid} comments {oc}->{nc}: {title}")
    # notebooks: newly-seen public kernels
    o_nb, n_nb = _key(old.get("notebooks", []), "ref"), _key(new.get("notebooks", []), "ref")
    for ref, row in n_nb.items():
        if ref not in o_nb:
            lines.append(f"NEW NOTEBOOK {ref}  ({row.get('title','')})")
    # leaderboard: new team in top-30 or score change
    o_lb, n_lb = _key(old.get("leaderboard", []), "teamName"), _key(new.get("leaderboard", []), "teamName")
    for team, row in n_lb.items():
        sc = row.get("score", "?")
        if team not in o_lb:
            lines.append(f"LB new/entered top30: {team} = {sc}")
        elif o_lb[team].get("score") != sc:
            lines.append(f"LB {team}: {o_lb[team].get('score')} -> {sc}")
    return lines


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--full", action="store_true", help="also print the full current state")
    ap.add_argument("--stamp", default=None, help="ISO timestamp label (else system clock)")
    args = ap.parse_args()

    FEED_DIR.mkdir(parents=True, exist_ok=True)
    old = json.loads(SNAP.read_text()) if SNAP.exists() else {}
    new = collect()
    if not any(new.values()):
        print("feed: all pulls empty (network/CLI issue) — snapshot NOT updated.")
        return

    delta = diff(old, new) if old else ["(first run — baseline captured, no delta)"]
    stamp = args.stamp or _dt.datetime.now().strftime("%Y-%m-%d %H:%M")

    if delta and delta != ["(first run — baseline captured, no delta)"]:
        block = f"\n## {stamp}\n" + "\n".join(f"- {d}" for d in delta) + "\n"
        with DIGEST.open("a") as f:
            f.write(block)

    SNAP.write_text(json.dumps(new, indent=2, ensure_ascii=False))
    print(f"feed @ {stamp}: {len(new['topics'])} topics, {len(new['leaderboard'])} LB rows, "
          f"{len(new['notebooks'])} notebooks. delta={len(delta)}")
    for d in delta:
        print("  " + d)
    if args.full:
        print("\n=== LEADERBOARD top30 ===")
        for r in new["leaderboard"]:
            print(f"  {r.get('score','?'):>8}  {r.get('teamName','')}")


if __name__ == "__main__":
    main()
