# side-channel-research.md — DeepResearch 統合（AIエージェントへのサイドチャネル攻撃と防御）

> 2026-06-22 DeepResearch（105 agents・3.4M tokens・446 tool calls・6 確証 finding）の統合。
> 我々の文脈（offline・isolated・deterministic・single-prompt replay／提出 wall-time のみ観測可能）にマップ。
> **攻撃↔防御の双方向**で整理。性質：外部文献ベース。一次ソース優先・我々の設定への転移可否を明記。

---

## 0. 我々への最重要結論（threat-model フィルタ済み）

**高帯域なサイドチャネル（プロンプト/秘密の復元）は全て「クロスユーザの cache 共有」か「ライブの暗号化ストリーム」を要求し、そのどちらも我々の隔離・決定論・単一プロンプト replay には存在しない**＝**直接適用不可**。唯一**転移する原理は Debenedetti et al.（USENIX Sec'24）の "privacy side channels"**：パイプラインの**フィルタ（= guardrail allow/deny）自体が binary oracle になり、モデル単体より遥かに多く漏らす**。これが competitor の「提出 wall-time で private guardrail を leak」案の理論的裏付け。だが我々は **(a) infra-gaming、(b) 月曜 enforcement の fail-fast が timing 信号を圧潰、(c) 責任ある開示の精神**から**使わない**（[[generation-uses-public-guardrail]]）。

**Working Note 価値**：本ベンチの**情報漏洩面＝「提出 wall-time guardrail oracle」**を Debenedetti で厳密に特徴づけ、各クラスに**防御（constant-time replay 等）**を対で付ける。さらに「**高帯域 LLM サイドチャネルは隔離決定論 replay では崩れる**」という honest な negative result 自体がベンチ設計の知見。

---

## 1. ★ Timing / guardrail-as-binary-oracle（唯一転移する・本命）

- **Debenedetti et al. "Privacy Side Channels in ML Systems"（USENIX Security 2024）**：training-data filtering / input preprocessing / **output post-processing** / **query filtering** の4カテゴリで、システム構成要素が「standalone model より遥かに高レートで」private 情報を漏らす。**出力抑制/ブロックするフィルタは情報漏洩 binary oracle**＝**guardrail の allow/deny（or fast-return vs timeout）が hidden private guardrail への唯一の観測信号**になる、と直結。
- **攻撃**：候補ごとに replay コストが private の allow/deny に依存するよう設計 → 総 wall-time を測って policy を推定（blind SQLi / padding-oracle と同型）。
- **防御**：フィルタ判定を**外部観測不能に**する＝**constant-time replay（decoy work で allow と deny の wall-time を等化）**、差分エラー/冗長性の抑制、フィルタ状態を private データに依存させない。
- **防御の限界/バイパス**：coarse padding を生き残る**残留スケジューリング分散**と per-decision のコスト非対称は、反復クエリで増幅されうる。
- **本ベンチ防御示唆**：月曜の per-phase fail-fast enforcement は**意図せず timing 信号を圧潰**して oracle を弱める（副次的に良い）。完全防御には constant-time replay を。

## 2. KV-cache / prefix-cache TTFT oracle（高帯域だが我々には N/A）

- **Early Bird（arXiv:2409.20002, IEEE TIFS）**：共有 prefix KV-cache で「cache 一致 prefix は高速」→ **TTFT の hit/miss timing で system prompt や他ユーザの prompt を token 単位復元**。hit/miss 検出 **99%（FPR 0.003）・prompt 復元 89%・112 query/token**。
- **InputSnatch（arXiv:2411.18191）/ CacheSolidarity**：guess-and-confirm oracle。候補を投げ、victim の cached prefix を再現する候補が TTFT 高速＝確定。**埋め込み秘密を ~20 候補で復元**。＝ competitor 案に**構造的に最も近い**が、差分は「cache-hit timing」であって「guardrail policy」ではない。
- **防御**：**per-user cache 隔離（クロステナント再利用なし）**で原理的に無効化。**コスト：TTFT +8〜38.9%**（LLaMA-2-70B）。選択的 **SafeKV**（arXiv:2508.08438）は sensitive KV だけ隔離し timing 攻撃の 94-97% を緩和しつつ throughput 2.66×回復。限界：sensitivity 分類の正しさに依存。
- **我々への適用**：❌ **クロスユーザ cache co-location が必要**。隔離・単一プロンプト replay には**存在しない**。

## 3. Token-length / streaming / packet-size（ストリーム前提・我々には N/A）

- **Weiss et al.（USENIX Security 2024)"What Was Your Prompt?"**：暗号化ストリームでも token は個別送信→**per-token packet サイズで token 長を推定**、LLM デコーダ＋既知平文 fine-tune で **応答の ~29% を逐語復元・~55% の話題推定**（ChatGPT-4/Copilot 実証）。
- **Whisper Leak（Microsoft Research 2025, arXiv:2511.03675）**：packet サイズ＋到着間隔だけで**暗号化会話の話題を分類**。28 商用 LLM で **>98% AUPRC**、10,000:1 ノイズ下でも 17/28 が precision 100%@5-20% recall。≒ 高精度の**単一ビット/話題 oracle**。
- **防御**：token batching / random padding / length bucketing（OpenAI/Cloudflare が開示後に導入。Google の非 token ストリームは元から非脆弱）。
- **我々への適用**：❌ **ライブ暗号化ストリームの観測が必要**。我々は**粗い総 wall-time のみ**＝適用外。

## 4. Batching / co-location / scheduling / MoE（共有バッチ前提・我々には N/A）

- continuous/dynamic batching の timing で co-tenant 活動が漏れる、speculative decoding の accept timing が内容を漏らす、**MoE expert-choice の cross-batch leakage**（token-dropping/capacity）。
- **我々への適用**：❌ **攻撃者と被害者の同一バッチ co-location が必要**。隔離・決定論・単一プロンプト replay では成立せず（我々の既存 MoE negative result `docs/ipi-format-injection-research §3.9` と整合）。

## 5. RAG / memory / embedding（本調査では具体ソース薄・低優先）

- RAG corpus の document membership を timing/behavior で漏らす、agent-memory/cache 状態の turn 跨ぎ漏洩、embedding ベース漏洩——理論上の面はあるが本調査で確証ソースは薄い（**unverified**）。本ベンチは RAG/永続 memory を持たないので優先度低。

---

## 6. 攻撃↔防御マッピング（Working Note 骨格）

| サイドチャネル | 漏れるもの | 我々への適用 | 防御 | 防御の限界 |
|---|---|---|---|---|
| **guardrail allow/deny timing oracle**（Debenedetti）| hidden guardrail の policy | △ 理論可・我々は不使用 | **constant-time replay**（decoy work で等化）| 残留分散・反復増幅 |
| KV/prefix-cache TTFT | system/他ユーザ prompt・秘密 | ❌ co-location 必要 | per-user cache 隔離 / SafeKV | TTFT +8-39%・分類依存 |
| token-length streaming | 応答内容・話題 | ❌ ストリーム必要 | padding / batching / bucketing | latency 増・特徴結合で部分回避 |
| batching/MoE co-location | co-tenant 活動・内容 | ❌ 共有バッチ必要 | テナント隔離・固定 batch | — |
| RAG/memory | document membership | ❌（本ベンチ非該当）| query 正規化・per-user 隔離 | unverified |

> 規律：各クラスに「漏れる物＋我々の threat-model への適用可否＋防御＋限界」。**高帯域攻撃は全て co-location/streaming 前提で隔離決定論 replay には転移しない**。唯一の転移は guardrail-as-oracle（Debenedetti）で、防御は constant-time replay。本ベンチでは月曜の fail-fast enforcement が副次的に oracle を弱める。
