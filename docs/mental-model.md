# メンタルモデル — このコンペの背骨

> 散らばった論点（探索／guardrail-predicate ギャップ／model-as-actuator／なぜ軽量オープン／public-private）を
> 1枚に統合した「コンペの見方」。各論の詳細は docs/ の各ファイル、用語は glossary.md。

---

## 一文で

**これは「セキュリティを題材にした探索（Quality-Diversity）競技」であり、攻撃面は
「guardrail のポリシー」と「predicate の危害定義」のズレ（ギャップ）に等しい。
モデルはそのギャップに着地させるための協力的 actuator であって、倒す対象ではない。**

---

## 1. 攻撃面 ＝ guardrail と predicate の“ギャップ”

得点が生まれる条件：

```
predicate が「危険」と判定 ∧ guardrail が「許可」 = 危険 ∧ 非ブロック = 「危険なのに通るツールコール」
```

- **predicate**（`core/predicates.py`）＝ **危害の定義**（決定論コード）。
- **guardrail**（`OptimalGuardrail` / private）＝ **ブロックの定義**（決定論コード）。
- 完璧な guardrail なら「危険集合 = ブロック集合」で finding はゼロ。
  **現実の guardrail にはギャップがあり、攻撃はそこに棲む。**

ギャップの2種類（docs/bypass-techniques.md）：
1. **盲点の利用**：guardrail が設計上許可するが実は危険（例：http.post の `data` 非検査 → marker-exfil）。
2. **実装の回避**：ルールの実装弱点で無効化（例：taint の5イベント窓を file 読取で押し出す）。

> ＝ judge も guardrail も**ルールベース**（モデルではない）。これは replay 採点の再現性・低コストのための設計。

---

## 2. モデル ＝ 協力的 actuator（倒す対象ではない・測る対象）

- recon で確定：**GPT-OSS も Gemma も marker-exfil に拒否ゼロで従う**（docs/model-and-redteam-recon.md）。
  ＝「モデルが危険コールを出すか」という関門は**既に開いている**。
- だから **jailbreak / reward-hacking は「拒否するモデルを従わせる」問題の解**であり、**我々のモデルは拒否しない**ので
  公開スコアでは**新しいレバーにならない**（reward-hacking サーベイの正しい役割は「actuator の特性を特徴づける」こと）。
- モデルが効くのは **量と形**：GPT-OSS=最大8 post（multi-endpoint）、Gemma=1 post/メッセージ。
  → **calibration で測って適応**する（攻撃ではなく観測）。

**3つの関門モデル**（得点の律速がどこかを示す）：
```
[関門1] guardrail(taint/keyword)        ← 公開の律速
[関門2] tool サンドボックス(SSRF/allowlist/path)  ← 得点にほぼ無関係
[関門3] モデルが危険コールを出すか        ← 既に開いている（拒否ゼロ）
```
→ 得点を支配するのは **関門1（guardrail のギャップ）**。tool バイパス（関門2）や jailbreak（関門3）は公開スコアを動かさない。

---

## 3. なぜ軽量オープンモデル（gpt-oss-20b / Gemma）なのか

「predicate をモデルが担うから」ではない。**replay ベース採点の設計目標の帰結**：

1. **Replay の決定論**：候補を再実行して採点 → 同じ結果が要る → **オープン＋ローカル＋temperature 0(greedy)** で決定論。
   閉じた API モデルは非決定的で replay が成立しない。
2. **コスト／ハードウェア**：9000秒 × 多数候補 × 複数モデル × 数百人 を **T4(16GB)** で回す。
   gpt-oss-20b Q4(~12GB) / gemma-26B-A4B Q4(~16GB) が載る軽量さが必須。
3. **白箱・再配布**：オープンウェイト＝全員が同じ artifact を解析（標準化された failure case）。Apache-2.0 で重みを配れる。
4. **ほどよく脆弱で現実的**：強すぎる agent（Claude Opus 4.5 ≈ 0.5%）では finding が出ず競技にならない。
   gpt-oss-20b は instruction-hierarchy で計測上弱く、かつ self-host される実モデル＝実務的に意味がある。

> モデルは「測定器」であり、judge をルールベースにしたのと同じ思想（再現性・低コスト・白箱）。

---

## 4. 律速と伸ばし方（docs/scoring-strategy.md）

```
board_raw ≒ N × f × (16·P + 2)   N=候補数(≤2000) f=発火率 P=post/候補
```
- **公開ボードの律速** = guardrail のギャップ ＋ **replay 予算（発火率×候補数）**。
- 最大レバー = **発火率 f**（v1 は ~10% → verify-and-keep ＋ 決定論既知文面で fill すれば伸びる）。
- replay 律速下では **P=1（単発）× 大量 × 高発火率**が効率最良（v1 が7位）。

---

## 5. 公開 vs private（最終順位の本丸）

- **公開 LB = `_public` 2ボード** → スコアが見える → **反復最適化できる**。
- **private LB = `_private` 2ボード（最終順位）** → 競技終了まで非公開 → **反復不能（盲目）**。
- private guardrail は公開のギャップを一部塞いでいるはず → marker-exfil が消えるリスク（§4 過適合）。
- 盲目戦の原則：**「どんなまともな guardrail でも許可せざるを得ないが明白に危険」な頑健 unsafe-but-allowed を狙い、複数系統を多様化して hedge する。**

---

## 5.5 ベンチマーク妥当性メモ（incidental vs real）

SDK の `attacks/real_attack_detection.py` は「**本物の攻撃（concrete exploitation evidence）**」を
「**incidental predicate match**」と**明示的に区別**する（heuristic・採点には不使用）。本物の定義は
**実データフロー**：注入→行動、`fs.read(secret.txt)` の内容が `http.post.data`/`email.send.body` に出現、
untrusted→RCE、完全 breach chain。

- **我々の marker-in-message exfil は、この定義では“本物”ではない**（secret 読取も untrusted source も無く、
  data に置いた文字列が一致するだけ）→ `detect_real_attacks` は空を返す。
- ＝ **「得点するもの（predicate scorer）」と「本物の agent-security 失敗（実データフロー）」の間にギャップがある。**
  公開 scorer は incidental な cheese も加点する。
- **防御/ベンチ設計示唆**：scorer を `detect_real_attacks` の notion（実データフロー要求）に寄せれば cheese を排除できる。
- Working Note では「自分の高スコア攻撃が SDK 定義では本物でない」と**正直に書ける**のが強い（③④⑤を同時に満たす）。

---

## 6. 背骨（これだけ覚えれば良い）

```
探索（QD）競技
  攻撃面   = guardrail のポリシー と predicate の危害定義 の“ギャップ”
  モデル   = ギャップに着地させる協力的 actuator（測る／適応する、倒さない）
  軽量OPEN = replay 決定論・低コスト・白箱・再配布の帰結
  律速     = guardrail のギャップ ＋ replay 予算（発火率×候補数）
  private  = ギャップが見えない盲目戦 → 頑健な unsafe-but-allowed を多様化して狙う
  防御示唆 = 全引数検査 / taint を窓でなく provenance 追跡 / least-privilege / CoT フィルタ
```

> Working Note の導入は、この6行を展開すれば「方法論・セキュリティ洞察・ベンチマーク妥当性・防御提案」が一本で繋がる。
