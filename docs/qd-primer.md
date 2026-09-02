# Quality-Diversity (QD) 探索 入門 ＋ 本コンペへの橋渡し

> deep-research（一次ソース・敵対的検証済み）の要約と、我々の得点式・attack.py への対応づけ。
> 背景は docs/mental-model.md / docs/scoring-strategy.md。

---

## 0. 一行
**QD（= illumination）は「1つの最適解」ではなく「behavior 空間の各領域で最良の解を集めた archive」を返す探索。**
**我々の得点式 `Σ severity + 2×(unique cell)` は、文字どおり QD-score（illumination 目的）。**

---

## 1. 3つの構成要素（候補ごとに評価）
| QD の語 | 我々での対応 |
|---|---|
| **quality（fitness）** = どれだけ良く解くか | **severity**（finding の predicate 重み） |
| **behavior descriptor (BD)** = どう解くか（多様性軸） | **cell ＝ tool-call signature**（`cell_signature(tool_events)`） |
| **archive** = niche ごとに最良 elite を保持 | cell ごとの候補集合（elite-per-niche） |

- **elite per niche**：各 niche（cell）に「最良の1個」を残す。＝MAP-Elites の核。
- QD ≠ 単目的最適化：**パラメータ空間でなく behavior 空間**を探し、**fitness の山でない領域も埋める**。
- QD ≠ 純 novelty search：novelty に**局所的な quality 競争**を足したのが QD（NSLC の local competition）。

## 2. コアアルゴリズム（関係）
- **MAP-Elites**（正準エンジン）：BD 空間を格子（cell）に離散化し、各 cell に最良個体を入れる。**我々の cell archive はこれ**。
- **NSLC**（Novelty Search + Local Competition）：behaviorally 近い個体間だけで fitness 競争。MAP-Elites と並ぶ2大手法。
- **CMA-ME / CMA-MAE**（emitter 改良・**連続空間向け**）：CMA-ES の自己適応で探索＋最適化。CMA-MAE は **soft archive ＋ archive learning rate α** で「純最適化(α=0)↔純多様性(α=1)」を連続補間。
  → 我々は**離散空間（文面・ドメイン）**なので CMA-* は直接は使わないが、**α＝探索/活用ノブ**の概念は移植できる。
- **Go-Explore**：cell archive ＋「有望な状態へ restore してから探索」。SDK の snapshot/restore がこれ（baseline 攻撃器が実装）。

## 3. 最大の落とし穴 → 我々の決定論が正解だった
- **elitist archive は確率的（noisy）評価で壊れる**：時間とともに fitness を過大評価し、高分散の不安定解を優先。noisy BD は archive 上で誤配置。
- 素朴な n 回平均化も3つの failure mode（試行数調整・高コスト・なお過大評価）。
- → **対策＝評価を決定論化（seed 固定）**。我々は **greedy temp-0 で決定論**を確認済（`docs/recon-*`）。**verify-and-keep ＋ cell archive が健全に成立する根拠**＝QD 理論が我々の設計判断を裏付ける（Working Note の②③に効く）。

## 4. QD × LLM red-teaming
- **Rainbow Teaming**：敵対プロンプト生成を QD 化。BD＝（Risk Category × Attack Style）、archive＝niche ごとの elite プロンプト。**1個でなく数百の相異なる有効攻撃**を産出（ASR>90%）。＝**breadth-over-depth の論拠**。
- **AgentVigil/AgentFuzzer**：seed corpus → **MCTS(UCB1) で seed 選択 → mutate → coverage** のループ。**coverage シグナル＝QD の多様性軸**。「当たりが未知」な探索の実用エンジン。

## 5. ★本コンペへの橋渡し（批判的に）
1. **目的は QD-score そのもの**：cell=BD、severity=quality、archive=elite-per-niche。breadth が支配（cell は線形・無上限、severity は cap）→ **多数 cell を埋める＞1つを深掘り**（Rainbow Teaming の教訓と一致）。
2. **ただし公開の marker-exfil では QD“機械”は退化する**：我々の cell（ドメイン粒度）は**毎回 fresh host で無限に安く distinct**＝**各 cell が singleton（niche 内競争が起きない）**。よって MAP-Elites の elite 競争・emitter・α は**ほぼ効かない**。**多様性がタダ**だから。
   - ＝公開の本質は「賢い QD 探索」ではなく「**発火率×候補数を replay 予算内で最大化**」（scoring-strategy と一致）。
3. **QD 機械が効くのは cell が“希少”な所**：
   - **private**（盲目・guardrail 未知）や**高 severity 述語**（各 cell に実データフローの工夫が要る）では、cell が安く量産できない → **AgentVigil 型 coverage 探索 ＋ MAP-Elites archive ＋ novelty** が本領を発揮。
   - ＝**「探索の賢さ」を private/難所に温存**、公開は活用で取り切る。
4. **決定論は死守**：noisy だと archive が壊れる（落とし穴）。greedy temp-0 を保ち、verify-and-keep で再現を担保。

## 6. アクションに落とすと
- 公開：**文面固定（f↑）× ドメイン変異（cell↑）× P=1 基調 × 候補数を replay 予算まで**。QD 的には「タダの多様性軸を最大限埋める」。
- private/難所：**seed → UCB1 で有望 seed 選択 → mutate → coverage で新 cell**（AgentVigil）。希少 cell を系統的に埋める MAP-Elites archive。
- 評価は**常に決定論**（QD の第一の落とし穴回避）。

---

## 出典（一次・検証済み）
- Mouret & Clune, *Illuminating search spaces by mapping elites*（MAP-Elites, arXiv:1504.04909）
- Pugh, Soros & Stanley, *QD: A New Frontier for Evolutionary Computation*（Front. Robotics AI 2016）
- Cully & Demiris, *Quality and Diversity Optimization: A Unifying Modular Framework*（arXiv:1708.09251）
- Chatzilygeroudis, Cully, Vassiliades, Mouret, *Quality-Diversity Optimization: a novel branch...*（arXiv:2012.04322）
- Fontaine & Nikolaidis, CMA-ME / CMA-MAE
- Lehman & Stanley, Novelty Search / NSLC
- *Rainbow Teaming*（QD for adversarial prompts）／*AgentVigil/AgentFuzzer*（coverage-guided agent attacks, arXiv:2505.05849）／*Go-Explore*
