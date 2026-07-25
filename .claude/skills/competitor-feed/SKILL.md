---
name: competitor-feed
description: この Kaggle 競技(AI Agent Security: Multi-Step Tool Attacks)の discussion / leaderboard / 公開Notebook を収集し前回との差分だけを提示する。新しい競合の動き・スコア更新・新Notebook・88→110+ throughput レバーの手がかりを追う時に呼ぶ。「discussion 漁って」「competitor 情報」「LB 更新見て」「公開Notebook」等で発動。
---

# Competitor Feed — Kaggle 競合 intel の定期収集

WebFetch は Kaggle を読めない(JS)。すべて `kaggle` CLI (`uvx --from kaggle kaggle ...`, creds あり) 経由。競技 slug = `ai-agent-security-multi-step-tool-attacks`。

## 手順

1. **差分を取る**（低ノイズ変化フィード）:
   ```bash
   uv run python recon/competitor_feed.py
   ```
   - `recon/feed/snapshot.json`（前回状態）と diff し、NEW/UPDATED topic・新 notebook・LB 変動だけを表示＋`recon/feed/digest.md` に追記。
   - 初回はベースライン取得のみ。`--full` で LB top30 も表示。

2. **気になる差分を掘る**:
   - topic: `uvx --from kaggle kaggle competitions topics show <id>`（長コメントは "..." で切れる→本質は把握できる範囲で）。
   - 高得点/新 notebook: `uvx --from kaggle kaggle kernels pull <ref> -p <dir>` → `.ipynb` を Read tool で読む（base64 埋め込みなら decode）。**特にスコアを名前に含む物**（例 `*-m112-*`, `*-n1000-*`）は最優先で精査。
   - LB: `uvx --from kaggle kaggle competitions leaderboard <slug> --show | head -20`。

3. **actionable intel だけ報告**（LBを動かすか？で判断）。無関係な雑談スレは省く。

## 現時点で確定している intel（recall の土台。差分をこの地図に位置づける）

**スコア機構（source+forum 727895/728432 で確定）**: 1 LB点=200 raw。EXFILTRATION sev5=16=0.08点、新 cell=+2=0.01点。single-post 1候補=raw18=0.09点。publicScore=mean(gpt_oss_public, gemma_public)。2000候補上限→180点天井。**リプレイで再現しない候補は0点**（採点は replay 経路）。cell は tie-breaker で戦略でない。

**88 フロンティア=single-post 一色**（tetsutani 88.5 / cleanorlabs 88.7 / pilkwang）。全員ほぼ同一の measured-fill コード。式: `S_row ≈ (18/200)·(候補数/候補あたり時間)` → 唯一のレバーは**候補あたり時間=トークン/TTFT**。

**潰したレバー（測定済み・[[gemma-row-lever]]）**: gemma latency/forge/K-post、prefix-cache 跨ぎ再利用、gpt forge最適化(inj_close が床)。全て dead。

**生きている 88→110+ レバー（要追跡）**:
- **packing 効率**（探索/replay 予算に候補を詰める）＝Victor Mercklé 100.49 が knapsack スレで "Always been." 認証。→ H4 blind-fill（replay 予算まで blind emit、host の gen>replay コスト差を突く）を実装中。
- **gpt-oss continuation multi-post**（The T-MAN, 727895）: 「analysis overhead 無しで即ツール実行を強制する最適化 continuation prompt」で K-post が reliable+fast＝fresh候補超え。我々の V49(bulleted K-post)=18.76 は**形式が悪かっただけ**で軸は死んでいない。
- **wrap-up世代(hop-1)を一語終端に潰す**＋**low-salience/routine framing で reasoning を発火させない**（pilkwang 723698「効いたこと」）。
- **reasoning-effort 設定に到達**（cleanorlabs の未解決 Q）。

**ノイズ**: 同一提出で±10点変動（best-of推奨だが Public 磨きは最終 Private に無関係）。「Submission Format Error」= timeout（候補過多）。予算 = 生成9000s + replay9000s（各モデル独立）。

## 定期化について
`recon/competitor_feed.py` は状態を `recon/feed/` に持つので **system cron / 手動 / CI** で永続実行可能。Claude セッション内の CronCreate はセッション終了で消え7日失効なので、永続には向かない。
