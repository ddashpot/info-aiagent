"""判定オラクルのMECE分類。

検出器（機能）を、相互排他なオラクルクラスへ一意に割り当てる。クラスの集合は
『応答から脆弱性をどう判定するか』を網羅(CE)する。各検出器はちょうど1クラスに属する。

  signature   : 内容パターン照合（秘密/カナリア/反射/追従語）
  invariant   : 不変条件(ポリシー)違反（拒否維持・境界不可侵 等）
  differential: 差分/メタモルフィック（安全/危険な同義入力ペアの応答差）
  anomaly     : 統計的異常（平常値からの逸脱）
  side_effect : 副作用/ツール痕跡（ツール呼び出し・外部到達）
  judge       : 人手/LLM判定（意味的逸脱・自動判定困難なもの）

refusal は『安全側』のシグナルだが、判定上は invariant オラクル（拒否不変条件）に属する。
"""
from __future__ import annotations

from typing import Dict, List

ORACLE_CLASSES: List[Dict[str, str]] = [
    {"id": "signature", "name": "シグネチャ一致"},
    {"id": "invariant", "name": "不変条件違反"},
    {"id": "differential", "name": "差分/メタモルフィック"},
    {"id": "anomaly", "name": "統計的異常"},
    {"id": "side_effect", "name": "副作用/ツール痕跡"},
    {"id": "judge", "name": "人手/LLM判定"},
]

# 検出器名 → オラクルクラス（一意・MECE）
ORACLE_OF: Dict[str, str] = {
    "compliance": "signature",
    "secret_pattern": "signature",
    "canary_leak": "signature",
    "system_prompt_echo": "signature",
    "injection_echo": "signature",
    "regex": "signature",
    "refusal_absent": "invariant",
    "differential": "differential",
    "anomaly": "anomaly",
    "tool_abuse": "side_effect",
    "url_exfil": "side_effect",
}


def oracle_of(detector_name: str) -> str:
    return ORACLE_OF.get(detector_name, "judge")
