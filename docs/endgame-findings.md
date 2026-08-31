# Endgame findings (2026-08-29 → 09-01)

> Durable internal record of the late-stage work. Complements `empirical-findings.md` (primary
> measurement log) and the private Working Note artifacts. Memory stays lean; details live here.
> Deadline: **Final Submission 2026-09-01 23:59 UTC**. Scoring queue is ~15-18h (confirmed: ryan panda
> #712642 "took 18 hours"), so submissions made after ~08-31 midday may not score before the deadline.

## FINAL DECISION — barbell, lock manually before 2026-09-01
- **Submit-1 = V63, ref `55510504`** — adaptive_k2 EXFIL, public **91.585** (unbeaten ceiling). Wins private world ① (pure_provenance, marker survives) + ③ (judge/DLP).
- **Submit-2 = V84, ref `55820079`** — deputy_adaptive_wall, public **25.155**. Wins world ② (payload-inspecting/strict private, where marker-exfil self-cancels). CONFUSED_DEPUTY is the unique robust survivor.
- ⚠ MUST select manually (My Submissions): default picks the 2 highest-PUBLIC = two EXFILs = loses the deputy hedge. Deputy's public 25 is far below the auto-threshold.

## Replay-cost oracle era (recon/replay_cost_oracle_cell.py, gemma_shape_oracle_cell.py, gemma_multihop_oracle_cell.py, numbered_ksweep_oracle_cell.py)
Built a CPU replay-cost oracle (n_gpu_layers=0 == host). Findings that HELD:
- Effective per-model replay budget ≈ **15-18k s**, NOT 9k (resolves #737769). We are **WALL-BOUND**; 91.585 is the shape-optimal ceiling at that budget.
- **gemma is the binding row.** Its fastest single shape is `_inj_done` (the "Done." harmony forge): ~12.7-14.7s, raw/wall ~1.22-1.42. Empty/other forge bodies = 19-23s. The "Done." literal specifically shortens gemma's post-"ok" final generation.
- **mccocoful native-syntax (call:http.post{...}) tested and DEAD**: mcco_native 14.3s > inj_done; native+Done forge = 0% fire.

Findings the oracle got WRONG (raw/wall does NOT fully predict host score — the recurring lesson):
- **V91 exfil_wall_route** (forced gemma→inj_done on oracle's raw/wall) = **84.67 < 91.585**. On the host, gemma burst2 (1.5 posts = 26 raw/candidate) beats inj_done (18 raw/candidate); raw-per-candidate matters, raw/wall alone doesn't. adaptive_k2's raw/TURN selection (gemma→burst2) was correct all along.
- **Numbered K-sweep**: oracle showed gemma num_k5 = 3.00 posts (raw/wall 1.123 > burst2 1.048), num_k3 = 2, num_k8 = 3. gpt best stays burst2 (numbered has no forge → CoT tax, 69-102s). BUT on the host ALL numbered regressed: **V92 k3=79.155, V93 k5=83.105, V94 k8=78.035**. The extra posts' wall cost swamped the gain. V95 adaptive_k2 re-draw = 89.245 (variance; our EXFIL draws span 88-91.6).

## gemma 1-tool-call cap — traced to source (HARD wall, no bypass)
- `aicomp_sdk/agents/gemma4_agent.py:400` `_GEMMA4_TOOL_CALL_PATTERN` (`<|tool_call>call:NAME{ARGS}<tool_call|>`, args non-greedy) uses `finditer` → collects ALL blocks in one generation.
- `agents/hf_chat_template/response_parsing.py:~106` `normalize_parsed_response`: **`if len(raw_tool_calls) > 1: raise InvalidModelOutputError`** → 2+ blocks in one generation = the whole response is rejected (not ignored).
- len() bypass is closed: a nested list passes the >1 check but `_normalize_tool_call` requires a Mapping (list element → raise); a string is rejected at the entry `isinstance(str)` check; the native parser only ever appends flat dicts (len = true count); one normalized call → sandbox runs exactly one event → one post.
- So: 1 tool_call/generation is defended in depth. Multi-post only via cross-hop, which hits finalize-on-"ok" + Renee's quote/brace malformation (Syed Asad Ali/Renee #737781). Community consensus: single-post / max_tool=1 is the only reliable path.

## Public levers — exhaustively dead (measured or source-proven)
single-post breadth 91.585 (BEST) · burst K=3 90.5 · K≥4 dead(parser) · packing 78.4 · one-word 81.5 · do-not-summarize forge 75.5 · pending-continuation 78.6 · shell-plan(Codex#2) 54.0 · bare-imperative 80.7 · severity-density 44.8 · continuation/per-model-N timeout · dual-T4 88.4 · wall-route 84.67 · numbered k3/k5/k8 79/83/78 · mccocoful native dead · UNTRUSTED/DESTRUCTIVE public structurally blocked.

## Private-axis intel (the prize)
- Gateway names the private guardrail `aicomp_private_guardrails.persistent_provenance` (provenance-based; held-out, not shipped locally). Source-primary evidence → world ① (marker survives) most likely.
- Independent corroboration of our exact thesis (marker fragile vs payload-inspecting guardrail / deputy robust): hexisteme #737535, **S.M Hadi Rizvi #738226** ("marker-exfiltration is structurally fragile against any guardrail that inspects payload content ... CONFUSED_DEPUTY is comparatively robust").
- Community expects a MASSIVE shakeup (#738261): Renee "100%. A lot of the top scoring on public will score 0 on private"; Ya Xu "greatest shakeup ever, the public leaderboard misled the competition". → strengthens the deputy hedge's expected value; barbell covers both worlds via best-of-2 max.
- kawasaki #712642: "uses SECRET_MARKER, I'm not sure if it works with the private guardrail" — shared world-② uncertainty.

## Operational / open
- Working Note award submission form is unclear — IRAMBONA GAEL #712642 (08-31) asked where to submit, unanswered. If we submit our Writeup, confirm the mechanism (writeups page?).
- Organizers largely unresponsive since ~June (Renee/Raymond Brunell threads). No official clarification on the 4-row→LB aggregation or best-of-2 mechanics.
- An exhaustive all-topics/all-comments discussion sweep is running (2026-08-31) to close any remaining coverage gap.
