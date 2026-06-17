# docs/ — 知識ベース インデックス

> 本コンペ「AI Agent Security: Multi-Step Tool Attacks」の白箱知見・戦略・用語の索引。
> プロジェクト全体の留意点は repo ルートの `CLAUDE.md`（living spec）が一次。

---

## まず読む（背骨）
- **[mental-model.md](mental-model.md)** — ★コンペの背骨。これは「セキュリティを題材にした探索(QD)競技」。
  攻撃面＝**guardrail のポリシー と predicate の危害定義 の“ギャップ”**。モデルは協力的 actuator。
  3関門（律速は guardrail）／なぜ軽量オープン／public-private／incidental vs real の妥当性メモ。**最初に読む1枚**。

## 推奨の読み順
1. mental-model.md（背骨）
2. [glossary.md](glossary.md)（用語）
3. [attack-success-conditions.md](attack-success-conditions.md)（何が得点か＝3関門・4述語の具体条件）
4. [scoring-strategy.md](scoring-strategy.md)（どう伸ばすか＝レバーの仮説マップ）
5. [bypass-techniques.md](bypass-techniques.md)（検証済みバイパス＋tool サンドボックス監査）
6. [model-and-redteam-recon.md](model-and-redteam-recon.md) / [reward-hacking_survey.md](reward-hacking_survey.md)（actuator 特性・手法）

---

## ファイル一覧

| ファイル | 内容 | 性質 |
|---|---|---|
| [mental-model.md](mental-model.md) | コンペの統合的見方（背骨6行） | 確定・統合 |
| [glossary.md](glossary.md) | 基本用語（cell / predicate vs guardrail / taint / commit-rerun…） | 確定 |
| [attack-success-conditions.md](attack-success-conditions.md) | 攻撃成功の3条件＋4述語の具体ツールコール・発火条件 | 確定（検証済） |
| [scoring-strategy.md](scoring-strategy.md) | 評価式に紐づくレバー（発火率 f・候補数 N・post/候補 P）と public-測定/private-盲目 | **仮説マップ**（実行計画ではない） |
| [bypass-techniques.md](bypass-techniques.md) | taint-aging・http.post data 非検査・severity 多重・tool サンドボックス監査（SSRF/allowlist/path） | 確定（ローカル検証済）／仮説／棄却 を分離 |
| [qd-primer.md](qd-primer.md) | Quality-Diversity 探索の入門（MAP-Elites/NSLC/CMA-MAE/Go-Explore）＋本コンペへの橋渡し（得点式＝QD-score、公開は機械が退化・private で本領） | 入門＋確定 |
| [model-and-redteam-recon.md](model-and-redteam-recon.md) | GPT-OSS/Gemma 特性、SDK パース面、AgentDojo/PAIR/TAP 等の手法をコンペにマップ | 確定＋公開情報 |
| [reward-hacking_survey.md](reward-hacking_survey.md) | RL/事後学習由来の reward-hacking 攻撃仮説（一次ソース vs 推論を分離） | サーベイ・仮説 |
| [multi-step-tool-attacks_survey.md](multi-step-tool-attacks_survey.md) | 攻略のための技術・研究・ガイドライン総覧 | サーベイ |
| [empirical-findings.md](empirical-findings.md) | 提出系列 v1→v8 の実測ログ、timeout 3機序の真因（出力トークン数）、multi-endpoint がモデルで死ぬ、local_score オラクル、55.8 メタ分解＋各防御示唆 | **確定（実測）** |

---

## Working Note 判定軸 × 素材マップ
（criteria: ①技術的明確さ・再現性 ②方法論 ③セキュリティ洞察 ④ベンチ有用性 ⑤責任ある開示）

| 軸 | 主な素材 |
|---|---|
| ① 再現性 | `attack.py` v2＋tests、各 bypass のローカル検証コード、glossary/attack-success-conditions |
| ② 方法論 | mental-model（QD 再フレーム）、scoring-strategy（発火率×候補数×P）、attack.py の runtime calibration |
| ③ セキュリティ洞察 | bypass-techniques（taint-aging/tool 監査）、mental-model の関門モデル・incidental vs real、model-and-redteam-recon |
| ④ ベンチ有用性 | incidental vs real ギャップ（妥当性）、各 failure case＋防御示唆、reward-hacking が actuator を説明 |
| ⑤ 責任ある開示 | 各発見を「ベンチマーク分析」として記述＋防御示唆を併記（bypass-techniques S-1〜S-4 が型） |

> 規律：発見は「**悪用可能性 ＋ なぜ得点に効く/効かないか ＋ どう直すか**」の3点セットで残す。
> 対象は常にこのベンチマーク（実システム一般化・無関係な脆弱性開示はしない）。検証してから確定。

---

## 現状（随時更新 / 2026-06-18）
- LB best：**v7 = 37.800**（予測 37.8 と完全一致＝local_score オラクル検証）。v8（N=750 純 exfil）採点中、予測 ~60。
- 提出系列・失敗機序・メタ分解は [empirical-findings.md](empirical-findings.md) に一次データとして確定。
- 確立した方法論：**`recon/local_score.py` でホスト実スコアをローカル測定 → 予測 → 提出**（盲目提出をやめる）。
- 公開 LB の本質：得点 ≈ 0.09×N（9h に詰める発火単発候補数）。multi-endpoint はモデルが高 K で multi-post せず不成立。
- SDK 監査：一巡（guardrail/predicate/cells/scoring/env/tools/agents/parsers/hooks/real_attack_detection）。
