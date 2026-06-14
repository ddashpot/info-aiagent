# 開発カタログ MECE 分類設計（分析と提案）

> **背景**: セキュリティ側カタログ（`ai_security_catalog.json`）は `surface(10) × failure_mode(7)` という**直交2軸のMECEバックボーン**を持ち、各脆弱性が一意の1セルに対応する。一方、開発側カタログ（`ai_agent_catalog_v8-1_data.json`）には等価の骨格がなく、**「配置・メモリ設計・役割」が自由記述**になっている。本書はその問題を定量化し、MECEな分類軸を提案する。
>
> **方針（厳守）**: 本書は**分析と提案**であり、カタログは**変更していない**。提案を採用する場合も、既存の自由記述フィールドは**削除せず人間可読ラベルとして残し**、構造化軸を**追加**する形を推奨する（省略・削除しない）。軸の確定は要レビュー（勝手に確定しない）。

---

## 1. 現状の問題（定量）

| ドメイン | フィールド | 種類数 / 件数 | 判定 |
|---|---|---|---|
| agent(20) | `category` | 3 / 20 | 分類体（系統）として機能 |
| agent(20) | `placement`（配置） | **20 / 20** | ❌ 全件一意の自由記述＝軸でない |
| agent(20) | `memory`（記述） | **20 / 20** | ❌ 自由記述（※別に `familyCodes` 構造化あり） |
| agent(20) | `role` | **20 / 20** | ❌ 自由記述 |
| tool(10) | `placement` | **10 / 10** | ❌ 自由記述（連携方式の素材ではある） |
| memory(10) | `placement` | **10 / 10** | ❌ 自由記述（※ `familyCode` 構造化あり） |

**結論**: 実際に分類軸として成立しているのは `domain`(3) と agent の `category`(3) のみ。`placement` / `role` は 1項目1ラベルの説明文で、**MECE（相互排他・網羅）な軸ではない**。メモリだけは別途 `families`(10種) の構造化タクソノミーがあり比較的整っている（後述）。

---

## 2. 設計原則（セキュリティ側に倣う）

- **直交2軸**を一次分類（MECEバックボーン）とし、各項目は一意のセルに対応。
- フレームワーク的なラベル（系統名など）は**横断タグ**として保持（重複ソースを一次分類にしない）。
- 自由記述は**人間可読の補助ラベル**として残し、機械処理は構造化軸で行う。

---

## 3. 提案：エージェント構成（agent）の直交2軸

### 軸A 制御の所在（Control Locus）＝「次の行動を誰が決めるか」［相互排他・網羅］
| ID | 値 | 定義 | 現 `category` 対応 |
|---|---|---|---|
| A1 | 定義済みフロー | 事前に決めた手順で進む（人/コードが順序を固定） | シーケンシャル系 |
| A2 | 中央オーケストレータ | 1つの監督役が動的に委任・ルーティング | スーパーバイザー系 |
| A3 | 分散ピア協調 | 対等なエージェントが協調・引き継ぎ | スウォーム系 |

### 軸B 連携トポロジ（Flow Topology）＝「処理がどう流れるか」［相互排他・網羅］
| ID | 値 | 定義 |
|---|---|---|
| B1 | 直列 | 一本道で順に流す |
| B2 | 分岐・合流(DAG) | 条件分岐・並走・合流 |
| B3 | 並列・分割統治 | fan-out して集約 |
| B4 | 反復 | 生成→評価→改善のループ |
| B5 | 動的委任 | 実行時に担当/手順を選ぶ・引き継ぐ |
| B6 | 共有空間協調 | 共有メモリ/会話空間で協調 |
| B7 | イベント駆動 | イベント/メッセージで起動 |

### 全20構成の (A × B) マッピング（提案・要レビュー）
| ID | 名称 | A 制御の所在 | B 連携トポロジ | 補助タグ |
|---|---|---|---|---|
| simple-chain | 単純チェーン | A1 | B1 直列 | |
| pipeline | パイプライン | A1 | B1 直列 | ストリーム |
| dag-workflow | DAGワークフロー | A1 | B2 分岐合流 | |
| map-reduce | Map-Reduce | A1 | B3 並列 | |
| iterative-loop | 反復ループ | A1 | B4 反復 | |
| human-in-loop | Human-in-the-loop | A1 | B1 直列 | HITL |
| router-supervisor | Router型Supervisor | A2 | B5 動的委任 | ルーティング |
| manager-worker | Manager-Worker | A2 | B3 並列 | |
| planner-executor | Planner-Executor | A2 | B5 動的委任 | 計画→実行 |
| agents-as-tools | Agents-as-Tools | A2 | B5 動的委任 | ツール化 |
| hierarchical-supervisor | 階層型Supervisor | A2 | B5 動的委任 | 階層/ツリー |
| critic-supervisor | Critic付きSupervisor | A2 | B4 反復 | 生成→評価 |
| memory-manager | Memory Manager付き | A2 | B5 動的委任 | 記憶管理 |
| handoff-swarm | Handoff Swarm | A3 | B5 動的委任 | 引き継ぎ |
| group-chat | Group Chat | A3 | B6 共有空間 | |
| blackboard | Blackboard | A3 | B6 共有空間 | ブラックボード |
| debate-committee | Debate/Committee | A3 | B4 反復 | 合議（要検討※） |
| market-bidding | Market/Bidding | A3 | B5 動的委任 | 入札 |
| role-playing-crew | Role-playing Crew | A3 | B6 共有空間 | 役割分担（要検討※） |
| event-driven-swarm | Event-driven Swarm | A3 | B7 イベント駆動 | |

> ※ `debate-committee`（反復 or 共有空間）/`role-playing-crew`（共有空間 or 直列）/`planner-executor`（動的委任 or 直列）は主分類の判断が分かれうる。**主軸は1つに確定し、もう一方は補助タグ**にする方針を提案（要レビュー）。

### MECE検証（提案軸）
- **網羅(Collectively Exhaustive)**: 20件すべてが (A,B) のいずれかに収まる ✓
- **相互排他(Mutually Exclusive)**: 各件を主分類1セルに割当（複合的性質は補助タグ）✓
- セル分布（3×7、空セル可）:

| A \ B | B1直列 | B2分岐 | B3並列 | B4反復 | B5動的 | B6共有 | B7イベント |
|---|---|---|---|---|---|---|---|
| A1 定義済み | simple-chain, pipeline, human-in-loop | dag-workflow | map-reduce | iterative-loop | — | — | — |
| A2 中央 | — | — | manager-worker | critic-supervisor | router, planner-executor, agents-as-tools, hierarchical, memory-manager | — | — |
| A3 分散 | — | — | — | debate-committee | handoff-swarm, market-bidding | group-chat, blackboard, role-playing-crew | event-driven-swarm |

---

## 4. 提案：メモリ設計（memory）の軸

メモリは既に `families`(10種) の構造化タクソノミーを持ち、**最もMECEに近い**。これを一次軸として正式採用することを提案。

### 軸M メモリファミリ（既存 `families`・相互排他の主分類）
| コード | 名称 | 代表メモリ項目 |
|---|---|---|
| F_SHORT | 短期・作業記憶 | memory-stateless, memory-session |
| F_STATE | 状態・ワークフロー記憶 | memory-workflow-state |
| F_SHARED | 共有・チーム記憶 | memory-shared |
| F_INDIV | 個別・専門記憶 | memory-per-agent |
| F_RAG | RAG・外部知識 | memory-rag |
| F_LONG | 長期・エピソード記憶 | memory-episodic |
| F_PROC | 手続き・スキル記憶 | memory-procedural |
| F_CACHE | キャッシュ・一時保存 | memory-cache |
| F_AUDIT | ログ・監査記憶 | memory-audit-event |
| F_EVENT | イベント・キュー状態 | （専用項目なし※） |

> **MECEの綻び（要対応）**: ①`F_SHORT` に2項目（stateless/session）が同居＝粒度差。②`F_EVENT` に対応するメモリ項目が無く `memory-audit-event` が F_AUDIT を兼ねる。→ memory項目とファミリの対応を1:1に近づけるか、ファミリ定義を見直すか要判断。

### 軸N メモリ属性（横断・既存 `memoryCommon`）＝直交する補助軸
`retention`（保持期間）/ `granularity`（粒度）/ `ownership`（所有）/ `controls` / `risks`。
→ ファミリ(軸M) × 属性(軸N) で、メモリ設計を直交的に記述できる。各 agent の `familyCodes` は既にこの軸Mで構造化済み（自由記述 `memory` は人間ラベルとして残す）。

---

## 5. 提案：ツールユース（tool）の軸

agent/memory と同様、`placement` を**連携方式の統制語彙**へ整理する。

### 軸T 連携方式（Integration Mechanism）［相互排他］
| クラス | 値（既存 placement 由来） | 代表項目 |
|---|---|---|
| 同期呼出 | 関数呼び出し | function-calling |
| 同期呼出 | HTTP API | rest-api |
| プロトコル | MCP | mcp |
| エージェント間 | A2A通信 | a2a |
| 非同期 | Webhook（コールバック） | webhook |
| 非同期 | Queue/PubSub | event-queue |
| 取得 | 検索・取得(RAG) | rag-retrieval |
| 取得 | DB/SQL | database-sql |
| 実行環境 | 隔離実行(サンドボックス) | sandbox-executor |
| 実行環境 | 画面操作(ブラウザ) | browser-automation |

→ 上位クラス（同期呼出 / プロトコル / エージェント間 / 非同期 / 取得 / 実行環境）でMECEにまとめ、詳細値を下位に持つ2層構成を提案。

---

## 6. `role` の扱い

`role`（工程担当、Router＋専門Agent 等）は**構成要素の説明**であり分類軸ではない。
→ 軸にせず**人間可読ラベルとして保持**。必要なら「構成ロール」の統制語彙（例: Orchestrator / Worker / Reviewer / Router / Planner / Executor / Critic / Memory-Manager / Peer）を**タグ集合**として別途付与する案（多対多なのでMECE一次軸にはしない）。

---

## 7. 適用案（カタログ更新の提案・要承認）

採用する場合の最小変更（**既存フィールドは削除しない**）:
1. agent 各項目に `control_locus`(A1–A3) と `flow_topology`(B1–B7) を**追加**。
2. tool 各項目に `integration_class` を**追加**（`placement` は残す）。
3. memory はファミリの綻び（F_SHORT 2項目・F_EVENT 無項目）を是正するか定義を明確化。
4. `axes` メタ（セキュリティ側同様）を開発カタログにも追加し、軸定義を明文化。
5. HTML（詳細比較マトリクス等）で新軸を一次分類として利用。

> いずれも**未実施**。軸の値・割当（特に §3 の※印）の確定はレビュー後に行う（勝手に確定しない）。

---

## 出典・根拠

- 既存データ: `ai_agent_catalog_v8-1_data.json`（items / families / memoryCommon）、`SKILL.md`（系統定義）。
- 設計の範: `ai_security_catalog.json` の `axes`（surface×failure_mode のMECEバックボーン）。
