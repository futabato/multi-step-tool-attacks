# llm-internals-learning.md — LLM 内部構造の学習ノート（DeepResearch 統合・一次資料付き）

> 2026-06-26 DeepResearch（107 agents・11 確証 finding）の統合。decoder-only LLM の機構を、
> **本コンペで実測した現象**に紐づけて理解する学習資料。各項＝[機構]＋[なぜ我々の観測を説明するか]＋[一次資料]。
> 性質：外部文献ベース・教育目的（攻撃手順でなく仕組みの理解）。

---

## 1. 自己回帰デコードと推論コスト（全コスト経済の根源）★

**機構**：decoder-only transformer は**1トークンずつ**生成し、各トークンに**1回の forward pass**を要する。prefill（プロンプト一括処理）→ decode（1トークンずつ）の2相。だから**wall-clock コスト ∝ 出力トークン数**（プロンプト長でなく）。

**我々の観測を説明**：GPT-OSS の reasoning level（low/medium/high・system prompt で設定）が上がるほど CoT が伸び、**high では AIME 1問に >20k CoT トークン**を消費（model card 明記）。長い CoT は「**最終応答 latency/コストの相対的に大きな増加**」と引き換え——**これが我々の 178s（巨大 analysis）vs 8s（terse）、640完走/1000timeout の正体**。「考える」とは**文字通りトークンを吐く行為**で、1トークン=1 forward。
**一次資料**：OpenAI gpt-oss model card。

## 2. トークナイザと特殊トークン（format injection の機構）

**機構**：harmony は**固定 ID の特殊トークン**で構造を区切るテンプレート：`<|start|>`(200006)・`<|end|>`(200007)・`<|message|>`(200008)・`<|channel|>`(200005) ＋ `<|constrain|>`/`<|return|>`/`<|call|>`。各メッセージは `<|start|>{header}<|message|>{content}<|end|>` の形で**モデルに渡る前にラップ**される。サニタイズされない user テキストがこれらを模すと**構造境界として処理**される。

**我々の観測を説明**：GPT-OSS は harmony に密結合（「harmony 無しでは正しく動かない」）＝**これらの特殊トークンは GPT-OSS にのみ意味を持つ**。Gemma は別の regex tool_call 語彙を使うので**同じ harmony トークンは無意味なノイズ**——だから我々の `<|channel|>` 注入が GPT-OSS を動かし Gemma には無効だった。format injection が効くのは「特殊トークン構造が**命令階層の境界**として処理される」から（ChatInject 実測：AgentDojo 5.18%→32.05%）。「自然言語で『考えるな』」より「**format-level priming**」が信頼できた理由もこれ。
**一次資料**：OpenAI Harmony cookbook / openai/harmony / ChatInject(arXiv:2509.22830)。

## 3. harmony の channel と reasoning

**機構**：harmony の3チャネル——**analysis**（CoT/隠れ推論）・**commentary**（tool-call preamble）・**final**（ユーザー向け回答）。analysis はモデルの**生の隠れ推論**を運び、これが**出力トークンを膨らませる本体**。重要：analysis チャネルは「**final と同じ安全基準に従わない**」と明記。

**我々の観測を説明**：GPT-OSS の reasoning-RL 事後学習＋harmony 構造が、長い analysis を生む。だから analysis 抑制が timeout 律速の鍵だった。「analysis は安全基準が違う」は、なぜ CoT 経由が private 用 escape hatch になりうるかの根拠。
**一次資料**：OpenAI Harmony cookbook / gpt-oss model card。

## 4. KV-cache・attention・prefix caching

**機構**：self-attention は `Attention(Q,K,V)=softmax(QK^T/√d_k)V`＝各生成トークンの query が**過去の全 key/value に attend**する。だから**過去の K/V を保持（KV-cache）**して再計算を避ける。**PagedAttention/vLLM** は KV-cache を OS 風ページングで管理（throughput 2-4×）。**prefix caching**：各ブロックを「そのブロックのトークン＋前置プレフィックス全体」で hash → **同一プレフィックスは同一 hash → KV 再計算不要 → TTFT 低下**。

**我々の観測を説明**：これが「**繰り返しプレフィックスが安い**」「prompt-cache timing サイドチャネル（[[side-channel-research]]）」の systems 基盤。
**一次資料**：Attention Is All You Need / PagedAttention(arXiv:2309.06180) / vLLM docs。

## 5. Mixture-of-Experts（MoE）

**機構**：**gpt-oss-20b = 20.9B total / 3.6B active**（24層・32 experts の top-4）；gpt-oss-120b = 116.8B/5.1B（36層）。router が token ごとに top-k expert を選ぶ＝**per-token 計算は固定で dense 同等サイズより遥かに小さい**。Mixtral 8x7B（46.7B total/12.9B active・top-2 of 8）が canonical 例＝「12.9B モデルと同じ速度/コスト」。**token-choice**（Switch/GShard/Mixtral：token が expert を選ぶ）vs **expert-choice**（expert が token を選ぶ）。

**我々の観測を説明**：「21B-A3.6B」の意味＝total vs active。そして**固定 top-k では per-token 計算が入力に依らず固定**＝**単一の隔離プロンプトで「expert を多く使わせて重くする」ことは不可**（我々の MoE 攻撃 negative result と整合）。
**一次資料**：gpt-oss model card / Mixtral(arXiv:2401.04088) / Expert-Choice(arXiv:2202.09368)。

## 6. サンプリングと決定論（※一次資料なし・標準知識）

**機構**：最終層が語彙上の logits を出す → softmax → サンプリング。**temperature=0＝greedy＝argmax**（常に最尤トークン）＝**同入力→同出力＝決定論的**。temperature/top-p は多様性を上げる。caveat：ハードウェア/バッチングで微小な非決定性が残りうる。

**我々の観測を説明**：temp0 だから**replay が完全再現**し、ローカルで提出前にスコアを検証できた（local_score の前提）。
**注**：本 DeepResearch では一次資料での裏取りができず（標準知識・我々の実測ベース）。

## 7. tool-calling とエージェントループ（※一次資料なし・標準知識）

**機構**：LLM は関数を**直接呼ばない**。**構造化テキスト**（JSON / harmony commentary / gemma `<|tool_call>call:NAME{...}`）を**生成**し、外部**パーサが抽出して実行**。ReAct 風ループ：生成→tool-call 抽出→実行→結果を append→再生成（＝1 "hop"）。regex パーサは**1生成1ツールしか受けない**ことがある。

**我々の観測を説明**：Gemma が「1生成1ツール」だった理由＝そのパーサ設計。多段ツール使用は**単発生成の繰り返し**にすぎず、hops 上限8。だから ≥3 step 連鎖をモデルが踏まなかった（[[public-guardrail-viability]] の multi-step 実証と整合）。
**注**：機構は標準知識・我々の実測ベース（本 DeepResearch では一次資料未裏取り）。

---

## まとめ（一本の線）
**自己回帰デコード（1トークン=1 forward）**が全ての根。→ コスト∝出力トークン（§1）。reasoning モデルは長い analysis を吐く（§3）ので高コスト。format injection はトークナイザの特殊トークン構造を突く（§2）。KV-cache が繰り返しを安くしサイドチャネルを生む（§4）。MoE は active/total を分け per-token 固定（§5）。temp0 で決定論（§6）。tool 使用は生成＋パース＋ループ（§7）。**我々が measure した全現象が、この7機構で説明できる。**
