---
name: kaggle-submit
description: このコンペ（ai-agent-security-multi-step-tool-attacks）へ attack.py を提出する手順スキル。notebook 再生成→ローカル検証→push→Web commit→Submit→監視。CLI だけでは提出できない落とし穴を含む。提出/submit/Kaggle に出す、のときに使う。
---

# Kaggle Submit — AI Agent Security: Multi-Step Tool Attacks

提出物は `attack.py`（class `AttackAlgorithm`）。Notebook が `/kaggle/working/attack.py` に書き出し、
採点 rerun で gateway がロード・リプレイ採点する。**single source of truth は repo の `attack.py`**。

competition slug: `ai-agent-security-multi-step-tool-attacks`
kernel: `futabato/jed-attack-submission`（`notebooks/kernel-metadata.json`）

## ⚠️ 最重要の落とし穴（これを最初に思い出す）
- 提出には **commit 済み version が `submission.csv` を出力していること**が必須。
- `submission.csv` を書くのは **gateway**。gateway は notebook の `serve()` が **block している時だけ**接続して走る
  ＝ `KAGGLE_IS_COMPETITION_RERUN` がセットされた実行。
- **`kaggle kernels push` の commit はこのフラグをセットしない** → `serve()` が即 return → submission.csv 未生成
  → **CLI 経由（`kaggle competitions submit -k ...`）も Web Submit も 400/ブロック**
  （"Submission files must be named submission.csv ... does not output this file"）。
- **解決＝Web の「Save & Run All (Commit)」で commit する**。`kaggle kernels push` で作った版は
  コンペ提出版として認識されない（Submit ダイアログでブロック）。notebook のコード（setup→write attack.py→`serve()`）は
  公式 starter と同型で**正しい。変更不要**。
- **commit 自体は速い（~1分）**：`serve()` は commit（非 rerun）では即 return し、gateway は走らない。
  LB 上の公式 notebook の commit ログも 19 行で gateway 実行の痕跡なし＝これが正常。
- **数時間・GPU の重い処理は「Submit 後の採点 rerun」**で、Kaggle 側が実行する（自分の commit 待ち時間ではない）。
  `submission.csv` もその rerun で生成され、`kaggle kernels output` には現れない。

## 手順

### 1. attack.py を更新したら notebook を再生成
```bash
uv run python notebooks/build_submission.py   # repo attack.py を base64 で submit.ipynb に焼き込み
```

### 2. ローカル検証（GPU 不要・提出前に必ず）
```bash
uv run pytest -q                                              # FakeEnv で breadth/verify を決定論検証
PYTHONPATH=comp uv run python -m aicomp_sdk.cli.main validate redteam attack.py   # Kaggle 構造チェック相当
PYTHONPATH=comp uv run python -m aicomp_sdk.cli.main evaluate redteam attack.py \
  --budget-s 30 --agent deterministic --env gym               # 公式スコアラを gym で実走（ランタイムエラー検出）
```
deterministic agent は固定スクリプトでスコア 0 が正常（実歩留まりは実モデル＝Kaggle でのみ判明）。

### 3. notebook を push（任意・版を作るだけ。これだけでは提出不可）
```bash
uv run kaggle kernels push -p notebooks
uv run kaggle kernels status futabato/jed-attack-submission
```

### 4. ★提出（Web 必須・commit は速い）
1. https://www.kaggle.com/code/futabato/jed-attack-submission を開く → **Edit**
2. **Save Version → Save & Run All (Commit)** を実行（**~1分**。gateway は走らないので軽い）
3. 出来た version を **Submit to Competition** → ここで初めて Kaggle 側が採点 rerun（数時間・GPU）を回す
   - CLI push 版（gateway 未認識）は Submit でブロックされる。必ず Web commit した版を使う。

### 5. 監視・スコア確認
```bash
uv run kaggle kernels status futabato/jed-attack-submission
uv run kaggle competitions submissions ai-agent-security-multi-step-tool-attacks
```
失敗時はログ取得して原因特定：
```bash
uv run kaggle kernels output futabato/jed-attack-submission -p .starters/out
```

## チェックリスト
- [ ] `attack.py` 変更を `build_submission.py` で notebook に反映したか
- [ ] pytest / validate / evaluate(gym) が緑か
- [ ] GPU クォータと日次提出上限（§8 未確認）を確認したか
- [ ] **Web の Save & Run All で commit したか**（CLI push だけで満足していないか）
- [ ] 提出後 `competitions submissions` でスコアを確認したか
