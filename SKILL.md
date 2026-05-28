# AIエージェント実装バリエーション選択UI Skill

## 目的

このSkillは、AIエージェントの実装形式を **シーケンシャル系 / スーパーバイザー系 / スウォーム系** に分類し、さらに実装バリエーションを選択・比較できるHTML UIを作成・更新するための手順を定義する。

対象となる出力は、単一HTMLファイルで動作するインタラクティブな選択UIである。

---

## このSkillを使うべき依頼

ユーザーが次のような依頼をした場合に使う。

- AIエージェントの実装形式を整理したい
- シーケンシャル、スーパーバイザー、スウォームを比較したい
- エージェント構成を選べるUIを作りたい
- 配置、メモリ、役割で実装パターンを分類したい
- HTML、Webページ、選択ツール、分類ツールとして出力したい
- AIエージェントアーキテクチャのカタログを作りたい

---

## 基本方針

1. 最上位分類は以下の3つにする。
   - シーケンシャル系
   - スーパーバイザー系
   - スウォーム系

2. 各バリエーションは以下の軸で整理する。
   - 配置
   - メモリ
   - 役割
   - 概要
   - 構成図
   - 向く用途
   - 強み
   - 注意点
   - キーワード

3. HTMLは単一ファイルで動作させる。
   - 外部ライブラリに依存しない
   - CSS、JavaScript、データを1ファイルに含める
   - ローカルで開いて動くようにする

4. UIには以下を含める。
   - 大分類フィルター
   - 実装バリエーション選択
   - 配置フィルター
   - メモリフィルター
   - 役割フィルター
   - キーワード検索
   - 詳細表示
   - 候補カード
   - 一覧表
   - 選択内容コピー機能

---

## 分類体系

### 1. シーケンシャル系

処理順序を明示的に決める実装形式。

| バリエーション | 配置 | メモリ | 役割 |
|---|---|---|---|
| 単純チェーン型 | 直列 | 前段出力の受け渡し | 工程担当 |
| パイプライン型 | 直列・継続処理 | ストリーム状態 | 処理段階担当 |
| DAGワークフロー型 | 分岐・合流 | 状態オブジェクト | ノード担当 |
| Map-Reduce型 | 並列＋集約 | 部分結果 | Worker＋Aggregator |
| 反復ループ型 | 循環 | 実行ログ・失敗履歴 | Executor＋Reviewer |
| Human-in-the-loop型 | 人間を途中挿入 | 承認履歴・コメント | Agent＋Human Reviewer |

#### 単純チェーン型

```text
Input
 ↓
Agent A
 ↓
Agent B
 ↓
Agent C
 ↓
Output
```

概要: 処理を A → B → C のように固定順で流す、最も基本的な実装形式。

向く用途:
- 記事生成
- 要件整理からレビューまでの定型処理
- 単純な業務フロー

強み:
- 実装しやすい
- デバッグしやすい
- 再現性が高い

注意点:
- 途中分岐に弱い
- 前段のミスが後段に伝播する

#### パイプライン型

```text
Collect Agent → Normalize Agent → Analyze Agent → Output Agent
```

概要: 継続的に流れる入力を、収集・整形・分析・出力などの工程に分けて処理する。

向く用途:
- メール処理
- ログ分析
- CRM登録
- データ変換

強み:
- 継続処理に強い
- 工程単位で交換しやすい

注意点:
- 工程間インターフェース設計が必要
- 遅い工程が詰まりやすい

#### DAGワークフロー型

```text
        ┌→ Research Agent ┐
Input → Planner          → Writer → Reviewer
        └→ Data Agent    ┘
```

概要: 処理を有向非巡回グラフとして表し、分岐・並列・合流を明示的に制御する。

向く用途:
- 複雑なレポート生成
- 審査業務
- データ分析
- 承認フロー

強み:
- 複雑な業務フローを表現できる
- 状態管理しやすい

注意点:
- グラフ設計が複雑になる
- 変更時の影響範囲が広い

#### Map-Reduce型

```text
          ┌→ Agent A ┐
Input → Split → Agent B → Aggregator → Output
          └→ Agent C ┘
```

概要: 入力を分割し、複数エージェントで並列処理した後、集約エージェントが統合する。

向く用途:
- 大量文書要約
- 複数候補の並列評価
- 調査結果の統合

強み:
- スケールしやすい
- 大量データに強い

注意点:
- 統合品質がAggregatorに依存
- 重複や矛盾の整理が必要

#### 反復ループ型

```text
Plan → Execute → Review
 ↑                  ↓
 └──── Improve ←────┘
```

概要: 実行、観察、レビュー、改善を繰り返す。コード生成や品質改善に向く。

向く用途:
- コード生成
- テスト修正
- 文章改善
- 計画の再立案

強み:
- 品質改善に強い
- 失敗から修正できる

注意点:
- 無限ループ対策が必要
- 停止条件の設計が重要

#### Human-in-the-loop型

```text
Agent A → Human Review → Agent B → Human Approval → Output
```

概要: エージェント処理の途中に人間の確認・承認・修正を挟む。

向く用途:
- 契約書レビュー
- 医療・金融判断
- 社外送信前確認
- 高リスク業務

強み:
- 安全性を高めやすい
- 責任分界を作りやすい

注意点:
- 処理速度が落ちる
- 承認UIとログ管理が必要

---

### 2. スーパーバイザー系

中央の管理者が判断・委任・統合する実装形式。

| バリエーション | 配置 | メモリ | 役割 |
|---|---|---|---|
| Router型Supervisor | 中央ルーター | 最小文脈 | Router＋専門Agent |
| Manager-Worker型 | 中央管理 | Managerが全体保持 | Manager＋Worker |
| Planner-Executor型 | 計画役＋実行役 | 計画・実行ログ | Planner＋Executor＋Observer |
| Agents-as-Tools型 | 中央Agentが呼出 | 中央状態 | Tool化Agent |
| 階層型Supervisor | ツリー構造 | 階層別状態 | 上位Supervisor＋下位Worker |
| Critic付きSupervisor | 中央＋評価役 | 出力・評価履歴 | Worker＋Critic＋Verifier |
| Memory Manager付きSupervisor | 中央＋記憶管理 | 短期・長期・RAG分離 | Supervisor＋Memory Manager |

#### Router型Supervisor

```text
User
 ↓
Router Agent
 ├→ FAQ Agent
 ├→ SQL Agent
 ├→ Search Agent
 └→ Coding Agent
```

概要: ユーザー入力を分類し、適切な専門エージェントに振り分ける。

向く用途:
- 問い合わせ分類
- 社内ヘルプデスク
- 専門窓口切替

強み:
- 構成が単純
- 責務分離しやすい

注意点:
- ルーティングミスが致命的
- 曖昧な依頼に弱い

#### Manager-Worker型

```text
User
 ↓
Manager
 ├→ Researcher
 ├→ Analyst
 ├→ Writer
 └→ Reviewer
 ↓
Final Answer
```

概要: Managerがタスクを分解・割当・統合し、Workerが専門処理を行う。

向く用途:
- 複雑な業務タスク
- リサーチレポート
- 社内AIアシスタント

強み:
- 全体制御しやすい
- 専門性を分離できる

注意点:
- Managerがボトルネック
- Workerの情報が要約で失われる

#### Planner-Executor型

```text
Planner → Tool Executor → Observer → Replanner
```

概要: 計画作成と実行を分離し、観察結果に応じて再計画する。

向く用途:
- ブラウザ操作
- RPA
- ツール利用
- タスク自動実行

強み:
- 計画と実行を分けられる
- ツール利用と相性が良い

注意点:
- 計画が現実とズレる
- 観察と再計画の設計が必要

#### Agents-as-Tools型

```text
Supervisor
 ├─ call SearchAgent()
 ├─ call CodeAgent()
 └─ call ReportAgent()
```

概要: 専門エージェントをツール関数のようにSupervisorから呼び出す。

向く用途:
- 本番業務アプリ
- API連携
- ツール実行基盤

強み:
- 制御しやすい
- テストしやすい
- 権限管理しやすい

注意点:
- Workerの自律性は低い
- Supervisor設計に依存

#### 階層型Supervisor

```text
Global Supervisor
 ├→ Research Supervisor
 │    ├→ Web Agent
 │    └→ Paper Agent
 └→ Engineering Supervisor
      ├→ Backend Agent
      └→ Test Agent
```

概要: 上位Supervisorの下に、領域別Supervisorと専門Workerを置く大規模構成。

向く用途:
- 大規模業務
- 自律開発
- 研究支援
- 複数部門の業務自動化

強み:
- 大規模化しやすい
- 領域ごとに責任を分離できる

注意点:
- 構成が複雑
- 階層間の情報落ちが起きる

#### Critic付きSupervisor

```text
Supervisor
 ├→ Worker
 ├→ Critic
 └→ Safety Checker
```

概要: 生成担当とは別に、批評・検証・安全確認のエージェントを置く。

向く用途:
- 高品質回答
- 法務・医療・金融
- 社外文書
- 事実確認

強み:
- 品質管理しやすい
- 安全性を高めやすい

注意点:
- 処理コストが増える
- Criticの基準設計が必要

#### Memory Manager付きSupervisor

```text
Supervisor
 ├→ Task Agent
 ├→ Memory Manager
 └→ Retrieval Agent
```

概要: メモリの読み書きを専門エージェントに分離し、記憶の品質と権限を管理する。

向く用途:
- 長期利用アシスタント
- 社内ナレッジAI
- パーソナルAI

強み:
- 記憶管理を統制できる
- 長期文脈に強い

注意点:
- 古い記憶や誤記憶の管理が必要
- 書き込み基準が難しい

---

### 3. スウォーム系

複数エージェントが動的・分散的に協調する実装形式。

| バリエーション | 配置 | メモリ | 役割 |
|---|---|---|---|
| Handoff Swarm型 | 動的引き継ぎ | 会話文脈の引き継ぎ | 専門窓口Agent |
| Group Chat型 | 共有会話空間 | チャット履歴 | 発言者Agent |
| Blackboard型 | 共有作業場 | 共有メモリ | 協調Agent |
| Debate / Committee型 | 複数意見＋判定役 | 議論履歴・評価基準 | Proposer＋Critic＋Judge |
| Market / Bidding型 | 分散選択 | タスクボード・能力情報 | Bidder＋Executor |
| Role-playing Crew型 | チーム型 | 共有文脈＋個別記憶 | 職能Agent |
| Event-driven Swarm型 | イベントバス中心 | イベントログ・状態ストア | Subscriber Agent |

#### Handoff Swarm型

```text
Triage Agent → Billing Agent → Technical Agent → Refund Agent
```

概要: 現在のエージェントが、より適切な専門エージェントへ制御を渡す。

向く用途:
- カスタマーサポート
- 相談窓口
- 専門部門への引き継ぎ

強み:
- 自然な担当切替ができる
- 専門性を出しやすい

注意点:
- handoff条件が曖昧だと迷走する
- 責任所在がぼやける

#### Group Chat型

```text
Shared Chat
 ├→ Researcher
 ├→ Coder
 ├→ Reviewer
 └→ Planner
```

概要: 複数エージェントが同じ会話に参加し、状況に応じて発言・作業する。

向く用途:
- 設計議論
- ブレスト
- レビュー
- 複数専門家の相談

強み:
- 多面的な検討がしやすい
- 柔軟性が高い

注意点:
- 会話が冗長化しやすい
- 発言者選択の制御が必要

#### Blackboard型

```text
          ┌→ Agent A
Blackboard ├→ Agent B
          └→ Agent C
```

概要: 共有作業場に仮説・調査結果・未解決タスクを書き込み、各エージェントが協調する。

向く用途:
- 複雑な調査
- 科学研究
- 障害対応
- 設計作業

強み:
- 協調しやすい
- 中間成果物を共有できる

注意点:
- 共有メモリが汚れやすい
- 衝突・重複・上書き対策が必要

#### Debate / Committee型

```text
Proposer A
Proposer B
Proposer C
   ↓
Judge / Aggregator
```

概要: 複数エージェントが異なる立場で提案・反論し、Judgeが評価する。

向く用途:
- 意思決定
- リスク評価
- 企画案比較
- 品質評価

強み:
- 多角的に検討できる
- 評価基準を明示しやすい

注意点:
- 議論コストが高い
- Judgeの基準が偏ると結論も偏る

#### Market / Bidding型

```text
Task Board
 ├→ Agent A: can do, cost 3
 ├→ Agent B: can do, cost 5
 └→ Agent C: cannot do
 ↓
Selected Agent executes
```

概要: 各エージェントがタスクに対して実行可能性やコストを提示し、選ばれたエージェントが実行する。

向く用途:
- 動的タスク割当
- リソース制約下の処理
- 大規模自動化

強み:
- 柔軟な割当ができる
- 負荷・コストを考慮しやすい

注意点:
- 入札基準の設計が難しい
- 過剰設計になりやすい

#### Role-playing Crew型

```text
Crew
 ├→ Product Manager
 ├→ Engineer
 ├→ Designer
 ├→ QA
 └→ Writer
```

概要: PM、Engineer、Designer、QAなど職能ベースのロールを持つエージェント群で作業する。

向く用途:
- プロダクト開発
- 記事制作
- 調査チーム
- 企画立案

強み:
- 職能分担が直感的
- 人間チームに近い設計ができる

注意点:
- ロール設定が形骸化しやすい
- 会話が長くなりやすい

#### Event-driven Swarm型

```text
Event Bus
 ├─ new_email → Mail Agent
 ├─ error_log → Debug Agent
 ├─ new_ticket → Support Agent
 └─ payment_failed → Billing Agent
```

概要: イベント発生をトリガーに、購読しているエージェントが非同期に反応する。

向く用途:
- 業務自動化
- 監視
- 通知
- 非同期RPA
- 障害対応

強み:
- 非同期処理に強い
- システム連携しやすい

注意点:
- イベント順序や重複処理が難しい
- 観測性が重要

---

## HTML出力仕様

### 必須レイアウト

HTMLは以下の構造にする。

```text
header
  - タイトル
  - 説明

aside.panel
  - 大分類 select
  - 実装バリエーション select
  - 配置 select
  - メモリ select
  - 役割 select
  - キーワード検索 input
  - リセット button
  - 選択内容コピー button

main.content
  - 選択中バリエーションの詳細
  - 候補カード
  - 一覧表
```

### 必須データ構造

JavaScriptの配列 `variations` に以下の形式で格納する。

```javascript
{
  id: "unique-id",
  category: "シーケンシャル系",
  name: "単純チェーン型",
  placement: "直列",
  memory: "前段出力の受け渡し",
  role: "工程担当",
  summary: "処理を A → B → C のように固定順で流す。",
  diagram: "Input\\n ↓\\nAgent A\\n ↓\\nOutput",
  useCases: ["記事生成", "定型処理"],
  strengths: ["実装しやすい", "再現性が高い"],
  risks: ["途中分岐に弱い"],
  keywords: ["chain", "workflow", "直列"]
}
```

### 必須機能

- フィルター条件を変更すると即時反映する
- 実装バリエーションを選ぶと詳細が切り替わる
- 候補カードをクリックすると詳細が切り替わる
- 一覧表もフィルターに追従する
- コピー機能で選択内容をクリップボードに保存できる
- 条件に該当しない場合は空状態を表示する

---

## デザイン方針

- 日本語UIにする
- モダンで読みやすいカードUIにする
- 背景は薄いグラデーションまたは淡色
- 左側にフィルター、右側に詳細表示を置く
- モバイルでは1カラムにする
- 外部CDNを使わず、単一HTMLで完結させる

---

## 更新時の注意

分類やバリエーションを追加する場合は、以下を守る。

1. 既存の3大分類に入るか確認する。
2. 入らない場合は、新しい大分類ではなく、まず既存分類の下位パターンとして表現できるか検討する。
3. `placement`、`memory`、`role` は短く一貫した語彙にする。
4. `summary` は1文で要点を書く。
5. `diagram` はテキスト図にする。
6. `useCases`、`strengths`、`risks` はそれぞれ2〜5個にする。
7. `keywords` には日本語と英語の両方を入れる。

---

## 完成物

このSkillで生成する主な完成物は以下。

- `ai_agent_variation_selector.html`
  - インタラクティブな選択UI
- `SKILL.md`
  - 分類体系、HTML出力仕様、更新ルールをまとめたSkill定義ファイル
