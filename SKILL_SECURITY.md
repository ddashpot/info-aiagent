# AI / エージェンティックAI セキュリティ評価スイート Skill

## 目的

このSkillは、AI（LLM）アプリおよびエージェンティックAIの**脆弱性を体系化**し、各脆弱性に対する
**コントロール（対策）と実装基盤**を紐づけ、既存アプリを**回帰的・汎用的に検査（既知＋未知）**する
ための成果物を作成・更新する手順を定義する。

対象となる出力は次の三位一体である。

1. 共有脆弱性カタログ（`ai_security_catalog.json`）
2. 単一HTML自己評価ツール（`ai_security_assessment.html`）
3. 汎用スキャナ（`tools/aiva/`、Python・依存ゼロ）

---

## このSkillを使うべき依頼

ユーザーが次のような依頼をした場合に使う。

- AI / LLM / エージェンティックAIの脆弱性を調べ上げたい
- 脆弱性に対するコントロールや実装基盤を検討したい
- 既存アプリに脆弱性があるか検査するツールを作りたい
- 既知だけでなく未知の脆弱性も検査したい
- 一過性でなく汎用的・回帰的に再検査できるようにしたい
- OWASP LLM Top10 / OWASP Agentic Threats / MITRE ATLAS / NIST AI RMF に沿って整理したい

---

## 基本方針

1. **準拠フレームワーク**を真実の基準にする。
   - OWASP Top 10 for LLM Applications 2025（LLM01–LLM10）
   - OWASP Agentic AI – Threats and Mitigations（T01–T15）
   - MITRE ATLAS（AML.Txxxx）
   - NIST AI RMF（GOVERN/MAP/MEASURE/MANAGE）・ISO/IEC 42001

2. **カタログを単一の真実の源**にする。HTMLとスキャナは必ずカタログを参照し、知見を重複定義しない。

3. **汎用性**を保つ。
   - プローブはデータ（`probes.json`）として追加する。
   - 検出器・対象アダプタはプラグインとして追加する。
   - 特定アプリ専用のハードコードをしない（BYO-endpoint）。

4. **既知＋未知の両輪**で検査する。
   - 既知：カタログ由来のシグネチャプローブ。
   - 未知：変異エンジン＋回帰的深掘り＋挙動異常検知（仕様逸脱を炙り出す）。

5. **回帰的**に運用する。発見した未知パターンはプローブとして登録（既知化）し、回帰スイートで再検査する。
   自己評価は再評価のたびにスコア・バックログを再計算する。

6. **責任ある利用**。能動検査は対象所有者の許可（`authorized`/`--authorize`）を前提とする防御的用途に限る。

---

## カタログのデータ構造（`ai_security_catalog.json`）

```jsonc
{
  "meta": { "version": "x.y.z", "frameworks": [ ... ] },
  "categories": [ { "id": "llm|agentic|infra|mcp|...", "name": "...", "framework": "...", "summary": "..." } ],
  "vulnerabilities": [
    {
      "id": "LLM01 / ASI-T01 / INF-01 / MCP-01 ...",  // フレームワーク準拠の安定ID
      "category": "llm",
      "name": "日本語の脆弱性名",
      "aka": ["英語別称", ...],
      "severity": "critical|high|medium|low|info",
      "summary": "1文の要約",
      "description": "詳細",
      "attack_vectors": ["...", ...],
      "affected_patterns": ["SKILL.mdのエージェント類型ID", ...],
      "controls": [
        { "id": "c-...", "type": "preventive|detective|responsive|governance",
          "name": "...", "desc": "...", "foundation": "実装基盤" }
      ],
      "foundations": ["実装基盤の短い一覧"],
      "atlas": ["AML.Txxxx ..."],
      "nist_rmf": ["GOVERN/MAP/MEASURE/MANAGE x.y"],
      "probes": ["対応するプローブID（tools/aiva/aiva/data/probes.json）"],
      "signals": ["検知すべきシグナル"],
      "references": ["URL または出典"]
    }
  ],
  "unknown_discovery": { "methods": [ ... ] }  // 未知探索の方法論
}
```

## プローブのデータ構造（`tools/aiva/aiva/data/probes.json`）

```jsonc
{
  "id": "snake_case_id",
  "vuln": "カタログの脆弱性ID（必須・存在すること）",
  "category": "llm|agentic|infra|mcp",
  "severity": "...",
  "mode": "active | passive",            // active=能動送信, passive=設計/設定の手動点検
  "expect": "refuse | sanitize | confirm | ground",  // 安全な振る舞い
  "mutatable": true,                      // 未知探索の変異対象にするか
  "technique": "AML.Txxxx",
  "title": "日本語タイトル",
  "tags": ["..."],
  "payloads": ["送信ペイロード", ...],     // 単発（mode=active）
  "turns": ["多ターン会話", ...],          // 任意：多ターン（最終応答を評価）
  "detectors": [ { "type": "refusal_absent|compliance|canary_leak|system_prompt_echo|secret_pattern|injection_echo|url_exfil|tool_abuse|regex", ... } ],
  "note": "passive時の点検観点"
}
```

---

## 更新時の手順

### 脆弱性を追加するとき
1. どの準拠フレームワークの項目か確認し、**安定IDを採番**する（例: 新カテゴリは `MCP-01` のように接頭辞＋連番）。
2. 既存 `categories` に入るか確認。入らなければ新カテゴリを追加（HTMLは categories を動的描画するので追従する）。
3. `controls` は予防→検知→対応→統制の順で並べ、各々に `foundation`（実装基盤）を必ず書く。
4. `atlas` / `nist_rmf` のマッピングを付ける。
5. 能動検査できるなら対応プローブIDを `probes` に列挙する。

### プローブを追加するとき
1. `data/probes.json` に1エントリ追加する（コード変更不要）。
2. `vuln` はカタログに存在するIDにする（テスト `test_every_probe_vuln_exists_in_catalog` が保証）。
3. 能動検査が困難（サプライチェーン/権限構成/監査証跡など）なら `mode: "passive"` にし、`note` に点検観点を書く。
4. 既存検出器で足りなければ `detectors/base.py` に `@detector("名前")` で追加する。

### カタログを変更したら（重要）
HTMLは**カタログのスナップショットを埋め込んで**オフライン動作する。カタログ更新後は必ず再埋め込みする。

```bash
python3 - <<'PY'
import json, re
obj=json.load(open('ai_security_catalog.json',encoding='utf-8'))
mini=json.dumps(obj,ensure_ascii=False,separators=(',',':')).replace('<','\\u003c')
html=open('ai_security_assessment.html',encoding='utf-8').read()
html=re.sub(r'(<script id="catalog-data" type="application/json">).*?(</script>)',
            lambda m:m.group(1)+mini+m.group(2), html, count=1, flags=re.S)
open('ai_security_assessment.html','w',encoding='utf-8').write(html)
print('re-embedded')
PY
```

### 検証
```bash
cd tools/aiva && python3 -m unittest discover -s tests   # 12+ tests
python3 -m aiva scan --target mock                        # mockでデモ検査
```

---

## HTML自己評価ツールの仕様（要点）

- 単一HTML・外部CDN非依存・カタログ埋め込みでオフライン動作。
- タブ：評価ダッシュボード／脆弱性カタログ＆自己評価／レッドチーム検査計画。
- 各コントロールの状態（実装済/部分/未実装/対象外）→ 残存リスク = 深刻度 ×（1 − カバレッジ）。
- 是正バックログは残存リスク順で、回答更新により回帰的に再計算。
- 回答は localStorage に永続化。評価レポート(MD)・状態(JSON)・aiva設定をエクスポート。
- 配色・レイアウトは既存サイト（左フィルタ／右詳細、淡色グラデ、日本語UI）に揃える。

---

## 完成物

- `ai_security_catalog.json` — 共有脆弱性・コントロールカタログ
- `ai_security_assessment.html` — 単一HTML自己評価ツール
- `tools/aiva/` — 汎用スキャナ（CLI・プローブ・検出器・変異・レポート・テスト）
- `SKILL_SECURITY.md` — 本Skill定義（体系・データ構造・更新ルール）
