# aiva — AI / エージェンティックAI 脆弱性アセスメント・ツールキット

任意のLLM / エージェントアプリ（**BYO-endpoint**）を能動的に検査し、
**既知の脆弱性**と**未知の脆弱性**を炙り出して、対応コントロール・実装基盤まで
紐づけたレポートを生成する、**汎用・依存ゼロ（Python標準ライブラリのみ）**のスキャナです。

- 準拠フレームワーク: **OWASP Top 10 for LLM 2025** / **OWASP Agentic AI Threats (T1–T15)** / **MITRE ATLAS** / **NIST AI RMF・ISO/IEC 42001**
- 真実の源: リポジトリ直下の [`ai_security_catalog.json`](../../ai_security_catalog.json)（HTML自己評価ツール [`ai_security_assessment.html`](../../ai_security_assessment.html) と共有）
- 一過性ではなく**回帰的に再検査**できる設計（プローブ＝データ、検出器＝プラグイン）

> ⚠️ **認可必須**: これは正規の自社アプリ/許可された対象に対する防御的セキュリティ検査ツールです。
> mock以外の能動検査は、設定の `"authorized": true` か CLI `--authorize` を明示しない限り実行されません。
> あなたが検査対象を所有しているか、明示的な検査許可を得ている場合のみ使用してください。

## インストール（任意・`aiva` コマンドを使う場合）

依存ゼロなのでインストールなしでも `python3 -m aiva` で動きますが、`aiva` コマンドとして
どこからでも使いたい場合は editable インストールします。

```bash
pip install -e tools/aiva        # リポジトリ直下から
aiva --version                   # => aiva 1.1.0
aiva scan --target mock          # どのディレクトリからでも実行可
```

## クイックスタート（ネットワーク・APIキー不要）

```bash
# インストール無し
cd tools/aiva && python3 -m aiva scan --target mock --format md,html
# インストール済みなら
aiva scan --target mock --format md,html
# => ./aiva_report/report.{md,html,json} を生成
```

mockは「意図的に一部脆弱な擬似アシスタント」です。スキャナの挙動とレポートの
見え方をオフラインで確認・CI回帰できます。

## 実アプリを検査する

```bash
# OpenAI互換エンドポイント
export OPENAI_API_KEY=sk-...
python3 -m aiva scan --config examples/config.openai.example.json --authorize

# 任意のHTTP/JSON API（BYO-endpoint）
python3 -m aiva scan --config examples/config.http.example.json --authorize
```

送信内容だけ事前確認したい場合は `--dry-run`。

## コマンド

| コマンド | 説明 |
|---|---|
| `aiva scan` | 対象を検査しレポート生成（脆弱性検出時 exit code 1 → CI連携可） |
| `aiva list-probes` | プローブ一覧（active=能動送信 / passive=手動点検） |
| `aiva list-vulns` | カタログの脆弱性一覧 |
| `aiva list-oracles` | 判定オラクルクラスと検出器の対応（MECE） |
| `aiva collect` | コレクタで新たな脅威を収集し `threat_intake/` へ投入（既定は外部接続なし） |
| `aiva ingest` | `threat_intake/` の脅威をプローブ／カタログへ反映（`--write`）/ 反映済みか検証（既定・CIゲート） |
| `aiva tools` | 統合可能な外部セキュリティツールと導入状況 |
| `aiva coverage` | 網羅性(カバレッジ)とギャップを算定（`--format md|json` `--only-available`） |
| `aiva run-tool` | 外部ツールを実行/レポート取込しカタログ所見へ正規化（garak/mcp-scan） |
| `aiva audit` | アーキ記述(実装コントロール)を監査し被覆を算定（観測性/追跡性など設計統制の自動検証） |

### 網羅性 100%（黒箱検査29/31 ＋ 設定監査2）

`aiva coverage` の結果（カタログ31脆弱性）:
- **能動検査(aiva) 20** … プロンプト/出力/ツール/権限/RAG/偽前提/なりすまし/消費・HITL（半能動）…
- **外部ツール 9** … サプライチェーン(Trivy)・秘密(gitleaks)・Egress(ZAP)・MCP(mcp-scan)・多エージェント(AgentDojo/Agentic Radar)…
- **設定監査 2** … 可観測性・追跡性(ASI-T08/INF-03)。黒箱検査では確認不能なため、アーキ記述で実装を検証。

```bash
aiva coverage                                          # 既定: 観測性系2件は受動(passive)
aiva coverage --arch examples/architecture.example.json # 設定監査を加味 → gap0/passive0（100%）
aiva audit --arch examples/architecture.example.json    # 実装コントロールの被覆を個別検証
```

> 単一エンドポイントの黒箱検査だけでは観測性/追跡性（ログ・トレースの有無）は判定できないため、
> その2件は**アーキ記述(`implemented_controls`)の設定監査**で自動検証する。多エージェント特有の
> 不正エージェント/人的攻撃は AgentDojo・Agentic Radar 等の専用ツールで担う。

### 外部ツールの実行・取込（garak / mcp-scan）

導入済みツールを実行、または既存レポートを取り込んで aiva 所見（カタログIDにマッピング）へ正規化:

```bash
# 既存の garak レポートを取り込む（ツール未導入でも可）
aiva run-tool garak --import garak.report.jsonl
# mcp-scan の結果(JSON)を取り込む
aiva run-tool mcp-scan --import mcp_scan.json
# 導入済みなら直接実行（--tool-config で model_type/probes 等を指定）
aiva run-tool garak --tool-config garak.json
```

### 半能動プローブ（測定オラクル）

自動検査が難しかった可用性系を、送信＋測定で半能動的に検査:
- `consume_burst`（ASI-T04 無制限消費）→ `resource_consumption` オラクル（応答長・反復・遅延を測定）
- `hitl_flood`（ASI-T10 HITL過負荷）→ `request_flood` オラクル（承認/確認要求の件数を測定）

これにより自動検査カバレッジは約7割超に。残るマルチエージェント統制系は引き続き設計統制＋人手で対応。

## 外部ツール統合と網羅性（garak / PyRIT ほかの組合せ）

aiva は単独ですべてを賄うのではなく、確立されたツールを**MECE背骨へ正規化して組み合わせる**。
`tool_registry.json` が各ツールの担当範囲（covers＝カタログ脆弱性ID）を宣言し、`aiva coverage` が
「どのセルをどの手段が埋めるか／空白はどこか」を算定する。

```bash
aiva tools                 # 統合対象ツールと導入状況（garak/PyRIT/Semgrep/Trivy/gitleaks/ZAP/mcp-scan…）
aiva coverage              # 網羅性レポート（脆弱性別＋ギャップ＋ツール導入状況）
aiva coverage --only-available   # 実際に導入済みのツールのみで集計
```

統合ツール（抜粋）: **LLMレッドチーム** garak / PyRIT / Giskard / promptfoo / DeepTeam・**SAST** Semgrep / Bandit / CodeQL・
**SCA/SBOM** Trivy / Grype / Syft・**シークレット** gitleaks / TruffleHog・**DAST** OWASP ZAP / Nuclei・
**MCP/エージェント** mcp-scan / Agentic Radar・**敵対的ML** ART / Counterfit / TextAttack・**基盤姿勢** Nmap / Checkov / Prowler / kube-bench。
garak はレポート(JSONL)を `integrations.py` の `GarakIntegration` で正規化して取り込める。

> ⚠️ **網羅性の現実**: 自動検査で約7割。残りの **orchestration / 可観測性 / マルチエージェント統制系**
> （カスケード幻覚・HITL過負荷・不正エージェント・追跡不能 等）は既製ツールが存在せず、設計・運用統制
> （HTML自己評価）と人手レッドチームで対応する。`aiva coverage` がこの空白を明示する。

## MECE設計（分類・手法・機能）

重複するソース（OWASP/ATLAS）を一次分類にせず、**直交2軸**を背骨にしている。

- **脆弱性**: `surface`（影響サーフェス・10値）× `failure_mode`（失敗モード・7値）。各脆弱性は1セルに一意。framework IDは横断タグ。
- **検査手法**: `generation_strategies`（生成・5）×`oracles`（判定オラクル・6）。各テスト＝生成×オラクル。
- **機能（検出器）**: 各検出器はちょうど1オラクルクラスに属す（`aiva list-oracles`）。差分(differential)・人手/LLM判定(judge)を含め網羅。

## 脅威インテイク（収集 → 反映 → 回帰）

新たな脅威を一過性でなく継続的にテストへ取り込むループ。

```bash
# 収集（任意・フィードを指定したときのみ外部取得。既定は安全な no-op）
aiva collect --collectors collectors.json
# 投入: threat_intake/*.json（1ファイル=1脅威。スキーマは threat_intake/README.md）
# 反映: プローブ／カタログへ upsert（新規脆弱性は vuln_def で MECE軸つき同時取込）
aiva ingest --write
# 回帰ゲート: 投入済み脅威がテストに反映されているか検証（未反映で非ゼロ終了）
aiva ingest --check
```

GitHub Action `.github/workflows/aiva.yml` が push/PR で `ingest --check`・テスト・mock回帰を実行し、
週次でコレクタ収集→反映→PR起票まで自動化する。

主なオプション: `--config` `--target {mock,http,openai}` `--probes`（ID/脆弱性ID/グロブ/all）
`--categories {llm,agentic,infra,mcp,multimodal,all}` `--format md,json,html,sarif` `--out DIR`
`--with-tools garak,mcp-scan` `--tool-import garak=report.jsonl,...` `--authorize` `--dry-run` `--no-mutation` `-v/-q`

### ツール統合実行 & SARIF（Code Scanning連携）

ネイティブ検査と外部ツール所見を1レポートに集約し、SARIFでGitHub Code Scanningへ:

```bash
# 外部ツールを統合（導入済みは実行、レポートは取込）→ 1レポートに集約
aiva scan --target http --config conf.json --authorize \
  --with-tools mcp-scan --tool-import garak=garak.report.jsonl \
  --format md,json,html,sarif
# 生成された report.sarif を GitHub Code Scanning にアップロード（github/codeql-action/upload-sarif）
```

CIワークフローは mock 検査の SARIF を生成（artifact）。`workflow_dispatch` 実行時のみ Security タブへ反映。

## テストツールとして使う（CI / pytest）

セキュリティテストとして既存のテスト・CIへ組み込めます。

**① テストスイートに組み込む（pytest / unittest）** — `examples/test_security_example.py` を参照:

```python
from aiva import testing

def test_agent_is_secure():
    result = testing.scan({
        "target": {"type": "openai", "url": "...", "model": "...",
                   "api_key_env": "OPENAI_API_KEY", "system": "..."},
        "authorized": True,
    }, categories=["llm", "agentic"])
    testing.assert_secure(result, fail_on=("critical", "high"))  # 該当所見でテスト失敗
```

**② CLIゲート（exit code）** — 重大度しきい値でビルドを失敗させる:

```bash
aiva scan --config conf.json --authorize --fail-on critical,high --format junit,sarif
#   --fail-on の深刻度に該当する所見があれば exit 1。JUnit/SARIF をCIに取り込み。
```

**③ 出力形式** — `--format junit`（JUnit XML：各プローブ＝テストケース）/ `sarif`（Code Scanning）/ `json` / `md` / `html`。

**④ 再利用可能な GitHub Action** — `tools/aiva/action.yml`:

```yaml
- uses: ddashpot/info-aiagent/tools/aiva@main
  with:
    config: aiva.config.json
    authorize: "true"
    fail-on: "critical,high"
    formats: "json,sarif,junit"
```

## マルチモーダル攻撃面

カタログに `multimodal` カテゴリ（MM-01 画像 / MM-02 音声・トランスクリプト / MM-03 生成メディア漏えい）を追加。
スキャナはテキスト代理プローブ（OCR/文字起こし結果に埋め込んだ指示）で間接インジェクション処理を能動検査する。

## 仕組み

```
対照プロンプトで平常値を学習（異常検知ベースライン）
      ↓
各プローブを送信 → 検出器で評価（拒否/漏えい/追従/反射/ツール悪用）
      ↓
変異エンジンで種ペイロードを系統変異（符号化/ロールプレイ/分割/注入ラッパ…）
      ↓
弱い兆候を起点に「回帰的深掘り」（recursive deepening, ビーム探索）
      ↓
全応答に異常検知 → 既知シグネチャ非該当でも逸脱を「未知候補」として記録
      ↓
カタログの脆弱性・コントロール・実装基盤へマッピングしてレポート
```

### 既知 + 未知の両方を検査する設計

- **既知**: `data/probes.json` のプローブ（OWASP/ATLASに対応）。データなので追加・更新が容易。
- **未知**: `mutator.py`（変異）＋`detectors/anomaly.py`（挙動ベース異常検知）。
  仕様からの逸脱（不変条件違反・応答異常・高エントロピー秘密様文字列・予期しない構造化出力）を
  シグネチャに依存せず検出し、人手トリアージへ回す。トリアージ済みの新規パターンは
  プローブとして登録（既知化）し、回帰スイートで継続再検査する。

## 拡張する（汎用性）

- **プローブ追加**: `data/probes.json` に1エントリ追加するだけ（コード変更不要）。
- **検出器追加**: `detectors/base.py` で `@detector("名前")` を付けて関数登録。
- **対象アダプタ追加**: `targets/` に `Target` を継承して実装し、`targets/__init__.py` の
  `build_target` に分岐を追加。

## ディレクトリ

```
tools/aiva/
  aiva/
    cli.py            CLI
    engine.py         検査オーケストレーション（変異・回帰深掘り・異常検知）
    catalog.py        共有カタログ ai_security_catalog.json ローダ
    config.py         設定ロード
    probes.py         プローブ選択
    mutator.py        変異エンジン（未知探索）
    targets/          mock / http / openai-compat アダプタ（BYO-endpoint）
    detectors/        シグネチャ検出器 + 異常検知（未知）
    report/ (report.py) md / json / html レポート
    data/probes.json  プローブライブラリ（データ駆動）
  examples/           設定例（mock / openai / http）
  tests/              スモークテスト（python -m unittest discover -s tests）
```

## テスト

```bash
cd tools/aiva
python3 -m unittest discover -s tests -v
```

## 注意・限界

- 自動検査の所見は**確証ではありません**。脆弱・弱兆候・未知候補は必ず再現確認と人手トリアージを。
- passiveプローブ（サプライチェーン、RAG越境、監査証跡、ID署名、権限境界など）はプロンプト送信では
  検査できないため、HTML自己評価ツールでのアーキ/設定点検に誘導します。
- 検査は対象に負荷・副作用を与え得ます。`rate_limit_per_min`・`--no-mutation`・`--dry-run` で制御してください。
