# ipi-format-injection-research.md — DeepResearch 統合（IPI・構造注入・provenance 防御）

> 2026-06-21 DeepResearch（22 出典 fetch・104 claim 抽出・25 検証・21 確証・4 棄却）の統合。
> 我々の文脈（harmony/gemma・taint/provenance guardrail・direct marker + format 注入が動作）にマップ。
> **攻撃↔防御の双方向**で整理（各攻撃に防御を、各防御に既知バイパスを併記）。性質：外部文献ベース。

---

## 0. 我々への最重要含意（戦略検証）

**provenance は user 指示由来データを「信頼」する（CaMeL arXiv:2503.18813 / Design-Patterns arXiv:2506.08837・HIGH）**：lineage を flag するのは **read-then-exfiltrate** のみ。**user メッセージに置いた secret marker は untrusted-origin 扱いされない**。
→ 我々が SDK ソースで導いた「private(provenance) は marker-in-message を構造的に塞げない（`recent_sources`=read 由来のみ）」を**文献が独立に裏付け**。**我々の SECRET_MARKER marker-in-message exfil は private 枠でも得点する公算が高い**。
→ marker-in-message を殺す唯一の防御＝「**origin 非依存の secret-pattern sink check**」（held-out trace-derived 採点がこれ）。だが **SECRET_MARKER は常時発火 sentinel** で**それも生存**。＝ payload 選択 SECRET_MARKER は provenance・payload-check 双方に頑健で最適（二重確認）。

---

## 1. フォーマット/構造レベル注入（我々の harmony 注入の位置づけ）

- **ChatInject（arXiv:2509.22830）**：chat-template の role/control トークンを偽造し、攻撃文をモデルに「高優先度 role」として読ませる。**我々の harmony commentary-channel priming（inj_commentary）はこの一族**。
  - ⚠ **検証で棄却された主張（intellectual honesty）**：具体的 ASR 数値（5.18→32%、multi-turn 52% 等）と「chat-template は control トークンを一切サニタイズしない（普遍）」は **0-3〜1-2 で棄却**。＝ **効果の正確な大きさは不確実、サニタイズ有無はモデル/template 依存**。
  - 我々の実測：本コンペの SDK template は control トークンを**通す**（harmony 注入が動作）。＝ サニタイズ非搭載の実例。
  - **防御**：template 境界で control/special トークンを escape/サニタイズ（OpenAI harmony spec も special token の扱いを規定）。
- 関連手口（文献にある構造攻撃の幅・今後の実験候補）：response **prefilling/fake-completion**（assistant turn 偽造）、delimiter/boundary confusion、role/system-message 注入。我々の inj_fake_analysis（不安定）/inj_commentary（安定）はこの系統。

## 2. taint/provenance 防御とバイパス（private 攻略）

- **動作**：CaMeL = quarantined-LLM（信頼コードが untrusted データを「値」として扱い、capability/provenance で sink を制御）。Design-Patterns = 封じ込めパターン群。
- **既知バイパス/限界**：
  - **user 指示は trusted-origin**（§0）＝ marker-in-message は通る。
  - **taint laundering/aging**：untrusted データを中間変換で「漂白」。本コンペ public の 5-window taint はこれに脆弱（`docs/bypass-techniques` B-1）。
  - **over-block（誤検知）**：厳格 provenance は正規フローも止めうる→主催が「誤検知なしに塞ぐ」難しさ（§4 の CONFUSED_DEPUTY が robust な理由）。
- **防御**：origin 非依存の payload sink check ＋ read/write capability 分離 ＋ leaky-bucket で漏洩量を有界化。

## 3. egress filter の設計と限界（防御示唆＝Working Note の核）

- **強さ順（文献）**：宛先 allowlist/redirect＝**100% block**（最強）＞ provenance ＞ payload keyword filter（**再エンコードで 23.3% しか発火せず**＝recogniser-gap）＞ prompt hardening（egress を 1.0→0.667 しか下げない・delimiter は無効）。
- **recogniser-alignment 問題**：攻撃は「**何を exfil とみなすか**」と「**何を block するか**」の2つの認識器の**ギャップ**に棲む（nakamura の指摘と一致）。本コンペ public guardrail は url だけ見て data を見ない＝典型的ギャップ。
- **encoding-gap**：paraphrase/encoding は content filter を破る（Leak+Rewrite 81-87%）。本コンペ AUDIT の「encoding-aware 検出」追加はこれへの対策。literal-match と難読化耐性は二律背反。
- **防御の決定版**：allowlist（宛先）＋ payload 監査＋ entropy/leaky-bucket 量制御＋ read/write 分離。

## 3.9 MoE 攻撃面（DeepResearch 2026-06-21・negative result）

両モデルは MoE（GPT-OSS 21B-A3.6B / Gemma-4 26B-A4B）。MoE 固有攻撃を「我々の決定論・隔離・単一プロンプト・temp0 replay に適用できるか」で仕分け（全て高確信・検証済み）：

| MoE 攻撃クラス | 適用可否 | 理由 |
|---|---|---|
| **cross-batch prompt-stealing**（Hayes/Yona et al. arXiv:2410.22884・token-dropping/torch.topk tiebreak）| ❌ 不適用 | 攻撃者と被害者を**同一バッチに co-locate**する必要。隔離 replay では不成立。加えて GPT-OSS/Gemma は **token-choice top-k**（Expert-Choice でない）で機構が転送しない。|
| **routing による expert 偏向**（Misrouter/SAFEx）| ❌ 無関係 | 入力で routing を偏らせられるが、実証された payoff は **jailbreak/ASR 改善のみ**。我々は**拒否ゼロ**で不要。|
| **MoE コスト/計算量操作** | ❌ レバー無し | **MoE は per-token 計算量が固定**（Switch Transformer：top-k なので入力で expert 数＝計算量不変）。**唯一の生成コストレバー＝総出力トークン数**＝harmony/gemma 注入で既に突いている軸。MoE は新レバーを足さない。|
| **sponge / energy-latency**（Sponge Examples/Engorgio/LoopLLM）| ⚠ 逆効果 | 出力長を**増やす**＝**踏むべきでない失敗モード**（避ける対象。冗長出力を誘発しない）。|

**結論**：MoE 固有の攻撃面は我々の採点に**何も与えない**（cost レバー無し・jailbreak 不要）。生成コストは「総トークン数」のみで決まり、それは format 注入で削るのが正攻法（§3.8）。
**Working Note 位置づけ**：多くの agent-security ベンチは model を black box 扱い＝**MoE 構造は未探索の軸**。「MoE 固有チャネルは隔離・決定論採点で崩れる」という honest な negative result 自体がベンチ設計の知見。

## 4. ベンチマーク（位置づけ）

- **AgentDojo（arXiv:2406.13352, ACL）**：tool-filtering が最強防御（ASR 57.7→6.8%）**だが「危害に必要な tool が正規にも必要」な場合に失敗（17%）**＝ **read/write 非対称**。本コンペの http.post（正規にも使う）exfil がまさにこれ＝tool 制限では塞げない構造。
- **InjecAgent（arXiv:2403.02691）**：ReAct GPT-4 で ASR 24%。直接/間接注入の taxonomy。
- 我々の発見の新規性：① harmony channel-priming で **reasoning コスト**を突く（攻撃の throughput 最適化＝既存 taxonomy に無い角度）、② provenance が marker-in-message を通す構造を**得点ベンチで実証**。

## 5. 攻撃↔防御マッピング（双方向・Working Note 骨格）

| 攻撃クラス | 効く理由 | 対応する防御 | 防御の既知バイパス |
|---|---|---|---|
| direct marker-in-message exfil | guardrail が url のみ検査・provenance は user 由来を信頼 | origin 非依存 payload sink check | sentinel(SECRET_MARKER)/read-then-post は通る |
| harmony/format トークン注入 | template が control トークンを通す | 境界で special token escape | サニタイズ漏れ・cross-model 転移 |
| read-then-act IPI | （本コンペでは taint/provenance が**塞ぐ**）| taint/provenance | laundering/aging・over-block |
| encoding 難読化 exfil | literal filter を回避 | encoding-aware 検出＋allowlist | literal と難読化耐性の二律背反 |

> 規律：各発見は「攻撃可能性＋なぜ得点に効く/効かない＋防御」の3点。対象は本ベンチマーク。一次ソース優先・棄却された主張は明記。
