# threat_intake — 新たな脅威の投入口

ここに置いた `*.json`（1ファイル=1脅威）が、`aiva ingest` によって検査プローブ
（`aiva/data/probes.json`）へ反映され、必要なら脆弱性カタログへも追記されます。
これにより「収集 → テスト反映 → 回帰」を回せます。

## フロー

```
（収集）aiva collect --collectors collectors.json   # 任意：フィードから自動収集して投入
   ↓
（投入）threat_intake/*.json                         # 手動 or コレクタが書き出す
   ↓
（反映）aiva ingest --write                          # プローブ／カタログへ upsert
   ↓
（回帰）aiva ingest --check && python -m unittest && aiva scan --target mock
```

GitHub Action（`.github/workflows/aiva.yml`）が push/PR と週次で `ingest --check`・
テスト・mock回帰を実行し、未反映や回帰を検知します。

## スキーマ（1ファイル=1脅威=1プローブ）

| フィールド | 必須 | 説明 |
|---|---|---|
| `id` | ✓ | 新プローブID（一意・snake_case） |
| `vuln` | ✓ | カタログ脆弱性ID（既存 or `vuln_def` を伴う新規） |
| `title` | ✓ | 日本語タイトル |
| `category` | ✓ | `llm` / `agentic` / `infra` / `mcp` |
| `severity` |  | `critical`〜`info` |
| `source` |  | 出所（URL・フィード名・レビュー記録）＝来歴 |
| `added` |  | 投入日 |
| `mode` |  | `active`（送信検査）/ `passive`（手動点検） |
| `expect` |  | `refuse` / `sanitize` / `confirm` / `ground` |
| `technique` |  | MITRE ATLAS 等 |
| `tags` |  | 任意タグ |
| `payloads` | active時 | 送信ペイロード配列 |
| `turns` |  | 多ターン会話（最終応答を評価） |
| `control_variant` |  | 差分オラクル用の対照（素の要求版） |
| `detectors` |  | 検出器指定（`{"type": "..."}`） |
| `vuln_def` | 新規vuln時 | カタログ用の完全エントリ（`surface`/`failure_mode` の MECE 軸必須） |

新規脆弱性を伴う場合は `vuln_def` に MECE 軸（`surface` × `failure_mode`）を必ず含めること。

`_` で始まるファイルは無視されます。例は `example__skeleton_key.json` を参照。
