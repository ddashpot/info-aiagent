# info-aiagent

AIエージェントの実装パターン・基盤比較・**セキュリティ**を扱う情報サイト（workapps.ddashpot.com）。

## AI / エージェンティックAI セキュリティ評価スイート

AI（LLM）アプリおよびエージェンティックAIの脆弱性を体系化し、対応コントロール・実装基盤を
紐づけ、既存アプリを**回帰的・汎用的**に検査（既知＋未知）するための三位一体のスイート。

準拠フレームワーク: **OWASP Top 10 for LLM 2025** / **OWASP Agentic AI Threats (T1–T15)** /
**MITRE ATLAS** / **NIST AI RMF・ISO/IEC 42001**。

| 成果物 | 役割 |
|---|---|
| [`ai_security_catalog.json`](ai_security_catalog.json) | **共有ナレッジベース**。29件の脆弱性 × 攻撃ベクトル × コントロール（予防/検知/対応/統制）× 実装基盤 × フレームワーク・マッピング × 検査プローブ × 未知探索手法。HTML・スキャナ双方の真実の源。 |
| [`ai_security_assessment.html`](ai_security_assessment.html) | **自己評価ツール（単一HTML・オフライン動作）**。脆弱性カタログ閲覧、実装コントロールの自己評価とスコアリング、是正バックログ（残存リスク順・回帰的再計算）、レッドチーム計画とaiva設定のエクスポート。 |
| [`tools/aiva/`](tools/aiva/) | **汎用スキャナ（Python・依存ゼロ）**。BYO-endpoint（mock/http/openai互換）を能動検査。データ駆動プローブ＋変異・回帰深掘りによる未知脆弱性探索＋異常検知。md/json/htmlレポートをカタログへマッピング。 |

### 使い方（最短）

```bash
# 1) ブラウザで自己評価（インストール不要）
#    サイトのヘッダー「🛡 セキュリティ評価」からも開けます（index.html → ai_security_assessment.html）
open ai_security_assessment.html         # 実装コントロールを点検 → 態勢スコアと是正バックログ

# 2) スキャナでmockをデモ検査（ネットワーク・APIキー不要）
cd tools/aiva && python3 -m aiva scan --target mock --format md,html
#    あるいは `aiva` コマンドとして使う場合:
pip install -e tools/aiva && aiva scan --target mock --format md,html

# 3) 自社アプリを検査（所有/許可している対象のみ）
#    examples/config.template.json をコピーして target を自社エンドポイントに設定
aiva scan --config your-config.json --authorize
```

### 設計思想

- **汎用**: プローブ＝データ、検出器＝プラグイン、対象＝アダプタ。一過性ではなく追加・更新で育てる。
- **回帰的**: 自己評価は再評価のたびにスコア・バックログを再計算。スキャナはCI連携（脆弱性検出で exit 1）。
  発見した未知パターンはプローブとして登録（既知化）し、回帰スイートで継続再検査。
- **既知＋未知**: 既知はOWASP/ATLAS対応プローブ、未知は変異エンジン＋挙動異常検知で「仕様逸脱」を炙り出す。
- **責任ある利用**: 能動検査は対象所有者の許可（`authorized`/`--authorize`）が前提の防御的セキュリティ用途。

詳細は [`tools/aiva/README.md`](tools/aiva/README.md) を参照。

---

## その他のコンテンツ

- AIエージェント実装バリエーション選択UI（[`SKILL.md`](SKILL.md) / `index.html`）
- AIエージェント基盤比較（`AIエージェント基盤比較.xlsx`）
- AIエージェント ID・セキュリティ要件 4階層雛形（`AIエージェント_ID・セキュリティ要件_4階層_雛形.xlsx`）
