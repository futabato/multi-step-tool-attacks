# agent-redteaming-competition-lessons.md — ART コンペ（arXiv:2507.20526）の教訓

> 2026-06-27 DeepResearch（98 agents・17 確証 claim・一次資料）の統合。Gray Swan/CAIS×UK AISI の
> Agent Red Teaming（ART）コンペ＝史上最大の公開 red-teaming（22 frontier agents・44 シナリオ・
> 180万攻撃・6.2万成功・~2000 参加者・2025-03〜04）。我々の tool-using-agent 設定への転移を明記。

---

## 0. 我々の手法と直結する最重要知見

**★ "Faux Reasoning"（偽の内部推論注入）が top-3 universal transferable 手法の一つ**＝**我々の harmony analysis-injection と同一発想**。ART は「`<think>` 等で**モデルの内部推論を模した文を注入**」が**モデル横断で効く universal 技**だと実証。＝ 我々が独立に発見・使用している harmony `analysis` 注入は、**一般的な reasoning-model 脆弱性として裏付けられた**（[[llm-training-and-attack-surface]] §1 の「CoT 無監督」と一致）。**Working Note の最強の外部裏付け**。

**★ Indirect injection >> Direct**（全体 ASR **27.1% vs 5.7%**、agent/tool カテゴリで差最大：Prohibited Action 36.8% vs 4.2%・Confidentiality 29.8% vs 7.8%）。tool 出力/web/log に隠した指示が、直接チャット注入より**圧倒的に強い**。＝ 本ベンチが**意図した攻撃（web→exfil 等の indirect）**こそ本来の主戦場。我々の発見「モデルが単一メッセージで ≥3 step を踏めず indirect 多段が到達不能」は、**実エージェントでは indirect が支配的なのに、このベンチの単発設計がそれを縮約している**という gap を浮かす（Working Note の核）。

---

## 1. 攻撃手法 taxonomy（ART・名前付き universal 技）

| 手法 | 内容 | 我々との関係 |
|---|---|---|
| **System Prompt Overrides** | `<system>`/`<\|start_header_id\|>system` 等で system role を偽造 | 我々の `harmony_fake_system`（benign では無反応だが、**抵抗ある harmful 行動には有効**）|
| **★ Faux Reasoning** | `<think>` 等で偽の内部推論を注入 | **我々の harmony analysis-injection と同一**。reasoning モデル横断で効く |
| **New Session / Session Data Update** | セッション reset を偽造 | 未使用・private 用に検討余地 |
| universal template | `<harmful task>` placeholder 差替で再利用 | Gemini で **58/50/45%**・Command-R/Llama で **33%** の behavior を突破 |

**indirect の具体**：crafted log 行を tool 出力に仕込み、agent に system 権限変更をさせる（confused-deputy 型）。

## 2. 転移性・普遍性（meta）

- **攻撃は高転移・universal**：1度作れば**モデル横断・シナリオ横断**で再利用可能。
- **EVA**（arXiv:2505.14289）：indirect 注入を**意味次元のみで進化探索**、**85% ASR・1.18-1.71 iteration で収束**＝feedback 駆動/進化的探索の効率。**semantic deception（権威的・欺瞞的な文言）が成功の主因**（見た目でなく**もっともらしい権威的表現**が転移する）。

## 3. 防御の教訓（headline）

- **★ 堅牢性 ≠ サイズ/能力/推論計算**：ASR vs GPQA 能力相関 **-0.31**。GPT-4.5（4o の10倍規模）も比例して頑健にならず、extended reasoning も robustness にほぼ寄与せず。＝ **スケールだけでは adversarial robustness は解決しない**。我々の「モデル能力が防御」caveat（[[public-guardrail-viability]]）を**外部が定量裏付け**——能力↑が安全↑を意味しない。
- **100% behavior-level ASR**（全モデルが全 behavior で違反）・10-100 query 以内に陥落＝**脆弱性は critical かつ persistent**。
- モデル間 robustness は **4.4× 差**（Claude 3.7 Sonnet Thinking 1.47% 最頑健 / Llama 3.3-70b 6.49% 最脆弱）。
- 組織の結論：**追加の防御（モデル単体でなくシステム層）が必須**。

## 4. 我々の設定への転移（明示）

- **(a) private 一般化**：ART の「universal transferable 攻撃」教訓＝**普遍的に転移する注入（faux reasoning ＋ system override）の方が、盲目の private guardrail に一般化しやすい**。＝ private ヘッジは**narrow でなく universal な構造を狙え**（我々の SECRET_MARKER ＋ harmony injection は universal 寄りで整合）。
- **(b) 頑健な転移注入**：semantic deception（権威的文言）が主因＝我々の "connect/diagnostics" 文面（権威的・benign 偽装）が効く理由の外部裏付け。
- **(c) Working Note framing**：① 我々の harmony analysis-injection＝ART の **Faux Reasoning**（名前付き universal 技）と同定、② indirect>>direct なのに本ベンチが単発に縮約、③ 堅牢性≠スケール、を**ART の大規模実証で補強**。

> 規律：ART は HARMFUL behavior（抵抗あり）を測る。我々の public は benign exfil（抵抗ゼロ）で**バイパス技は public スコアを動かさない**点は不変。ART の価値は **private ヘッジの設計指針＋Working Note の外部裏付け**であって、public LB の新レバーではない。
