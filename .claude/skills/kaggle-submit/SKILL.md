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
- 提出には **commit 済み version が `submission.csv` を出力していること**が必須。出さない版は Submit ダイアログで
  選べない／"Submission files must be named submission.csv ... does not output this file" でブロック。
- **`serve()` だけの notebook は commit で submission.csv を出さない**（`serve()` は `KAGGLE_IS_COMPETITION_RERUN`
  時のみ block して gateway 接続。commit では即 return）。**これが提出ブロックの真因**（CLI push でも Web Save&Run All でも同じ）。
- **解決＝notebook 末尾を分岐にする**（`build_submission.py` に実装済み・pilkwang パターン）：
  - `KAGGLE_IS_COMPETITION_RERUN` あり → `serve()`（実モデルで本採点）
  - なし（commit）→ **deterministic agent で `run_local_gateway()` を走らせ submission.csv を生成**
    （`os.environ['AICOMP_MODEL_NAMES']='deterministic'`＋`gw.MODEL_NAMES=['deterministic']`＋`_run_attack_for_model`
    を budget 5s・候補20 に monkeypatch、数秒・GPU不要）。出力は score 0 のスタブだが**形式要件を満たし submittable に**。
  - else 分岐は rerun では実行されない＝**本採点（実モデル）に影響なし**。
- ローカル事前検証：`uv run --with pandas --with polars --with grpcio --with pyarrow python` で commit 分岐
  （deterministic local gateway）を回し、`submission.csv` 生成を確認できる。
- 提出手順：`kaggle kernels push`（版更新）→ Web **Save & Run All**（出力に `submission.csv produced: True`）→ その version を **Submit**。
- **同時に採点できる提出は1つ**。前の提出が PENDING の間は次の Submit がロック（settle を待つ）。
- 数時間・GPU の重い処理は「Submit 後の採点 rerun」で Kaggle 側が実行（自分の commit 待ち時間ではない）。

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
