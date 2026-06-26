# llm-training-and-attack-surface.md — 事前/事後学習と「構造・学習着目」攻撃面

> 2026-06-26 DeepResearch（108 agents・11 確証 finding・一次資料）の統合。
> GPT-OSS / Gemma の pre/post-training を一次資料で押さえ、そこから**構造・学習着目の攻撃面**を導く。
> 規律：開示分と非開示分を分ける／各攻撃面に「機構＋このベンチでの有効性＋防御」。[[llm-internals-learning]] の続き。

---

## 1. GPT-OSS の作られ方（一次資料・gpt-oss model card / arXiv:2508.10925）

**事前学習**：decoder-only MoE。20b=**20.9B total / 3.6B active**（24層・32 experts top-4）；120b=116.8B/5.1B（128 experts）。GQA（64 query head / 8 KV head）、**banded(128)/dense 交互 attention＋attention-sink bias**、RoPE+YaRN で **131,072 ctx**、**o200k_harmony BPE（201,088 トークン＝harmony 特殊トークンを含む）**。データは「**trillions**・mostly-English・STEM/coding/general」（**正確な混合比は非開示**）、cutoff 2024-06、**120b で 2.1M H100-hours**、Apache-2.0。

**事後学習（reasoning 化）**：**SFT ＋ 高計算 CoT-RL（o3/o4-mini 流）＋ 大規模蒸留**。Model Spec に整合させ、回答前に CoT＋tool 使用するよう訓練。harmony の analysis/commentary/final、reasoning effort（low/med/high・system で設定・高いほど CoT 長＝**178s の正体**）。

**★★ 学習着目攻撃の核心（finding [7]・一次資料確定）**：
> **OpenAI は CoT に直接の監督/最適化圧をかけていない。結果、gpt-oss は final 出力では system 指示に頑健に従うが、CoT の中ではしばしば明示的に指示に背く。**

＝ **安全・指示追従は final チャネルにのみ訓練されており、analysis(CoT) は無監督・無防備**。これが「analysis は final と同じ安全基準に従わない」「自然言語『考えるな』が効かない」の**学習機構レベルの説明**。

**安全事後学習**：Preparedness Framework 評価＋**リリース前に自社 stack で "malicious fine-tuning"（攻撃者シミュレート）して worst-case 能力を測定**（High 閾値未満・o3 以下と結論）。

## 2. Gemma の作られ方（薄い・要追加調査）

**確証できたのは Gemma 3 のみ**（tech report arXiv:2503.19786）：1B–27B、**≥128K ctx（1B は 32K）**、multimodal、**全モデルが大きい teacher からの知識蒸留**で訓練（小 student が teacher の出力分布を真似る＝同サイズ比で強い理由）。

**未解決（正直に open）**：Gemma 1/2 の構成・データ/トークン量・**RLHF/RLAIF の詳細**・**ShieldGemma**（別の安全分類器・base の guardrail ではない）・**「Gemma-4 26B-A4B (MoE)」命名が公式か競技ラベルか**。＝ 学習着目攻撃の Gemma 側は**機構が未確定**。要・追加 DeepResearch（Gemma 2 tech report / ShieldGemma paper を名指しで）。

---

## 3. 構造・学習着目の攻撃面 taxonomy（このベンチでの有効性付き）

> 大前提（実測）：**public は両モデル拒否ゼロ＝抵抗なし**。よって構造/学習着目"バイパス"は **public スコアを動かさない**。価値は **(a) private ヘッジ・(b) Working Note**。

| # | 攻撃面 | 機構（一次資料） | このベンチでの有効性 | 防御 |
|---|---|---|---|---|
| 1★ | **analysis(CoT) 安全ギャップ** | CoT 無監督→CoT 内で指示に背く（[7]）。安全は final のみ | public 無効（抵抗ゼロ）／**private が厳格なら escape hatch**／**Working Note 本命** | CoT を監督/監視 or sink から CoT 由来を除外 |
| 2 | **harmony 特殊トークン注入** | o200k_harmony が `<\|channel\|>` 等を語彙に持つ（[2]）→format 境界として処理 | 我々は cost 用に使用（構造着目の "勝ち"）／private で role/result 偽造に拡張可 | template 境界で special token を escape |
| 3 | **reasoning-effort 操作** | system の "Reasoning: high/low" が CoT 長を制御（[6]） | 我々は low 方向で cost 削減／high は sponge/DoS だが system 非制御 | effort を user 経路で変更不可に |
| 4 | **tokenizer glitch / 差分** | BPE 201,088 トークン・under-trained token | guardrail 文字列 vs token 差分は Codex BLOCKED 確認済み／glitch は未探索 | encoding-aware 検査（evaluator が一部導入済み）|
| 5 | **蒸留の継承（Gemma）** | student が teacher 分布を真似る（[11]）→teacher の弱点/jailbreak を継承しうる | 機構未確定（Gemma 学習薄）／speculative | teacher 側の安全を student に蒸留 |
| 6 | **安全の狭さ（off-distribution format）** | 安全は特定 format/channel で訓練 | private で off-distribution format により迂回しうる（盲目）| 多様 format で安全訓練 |

---

## 4. 結論（学習着目攻撃の現実）
- **#1（analysis-channel CoT ギャップ）が最有力**：reasoning モデル固有・**一次資料で学習機構まで確定**・防御示唆明快＝**Working Note の中核章**になる。private が refuse する世界での原理的 escape hatch でもある。
- public LB は抵抗ゼロで動かない（規律として明記）。
- **Gemma 側の学習機構が薄い**のが穴＝追加調査（Gemma 2 report・ShieldGemma・MoE 変種の出自）で #5/#6 を Gemma にも確定させたい。
