"""アーキテクチャ設定監査。

ブラックボックスのプロンプト検査では確認できない設計・運用統制（監査証跡・トレーシング・
エージェント登録・委任境界など）を、対象の宣言的アーキ記述(arch.json)に対して検査する。
これにより、観測性/追跡性/多エージェント統制といった『能動検査できない』脅威も、
実装コントロールの有無として自動検証でき、網羅性の裏付けになる。

arch.json::

    { "implemented_controls": ["c-audit-trail", "c-tracing", "c-agent-registry", ...] }

各脆弱性の controls（カタログ）に対し、実装済みコントロールの被覆率を算定する。
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Set

from .catalog import Catalog


def load_arch(path: str) -> Set[str]:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return set(data.get("implemented_controls", []))


def analyze(catalog: Catalog, implemented: Set[str]) -> Dict[str, Any]:
    rows = []
    counts = {"ok": 0, "partial": 0, "missing": 0, "n/a": 0}
    for v in catalog.vulns:
        req = [c["id"] for c in v.get("controls", [])]
        if not req:
            counts["n/a"] += 1
            rows.append({"id": v["id"], "name": v["name"], "status": "n/a",
                         "implemented": [], "required": []})
            continue
        impl = [c for c in req if c in implemented]
        status = "ok" if len(impl) == len(req) else ("partial" if impl else "missing")
        counts[status] += 1
        rows.append({"id": v["id"], "name": v["name"], "status": status,
                     "implemented": impl, "required": req,
                     "missing": [c for c in req if c not in implemented]})
    return {"counts": counts, "rows": rows, "total": len(catalog.vulns)}


def render_markdown(model: Dict[str, Any]) -> str:
    c = model["counts"]
    label = {"ok": "実装済", "partial": "一部実装", "missing": "未実装", "n/a": "対象外"}
    L = ["# アーキテクチャ設定監査（実装コントロール）", "",
         f"- 充足 {c['ok']} / 一部 {c['partial']} / 未実装 {c['missing']} / 対象外 {c['n/a']}", "",
         "| 脆弱性 | 状態 | 実装済 / 必要 | 不足 |", "|---|---|---|---|"]
    order = {"missing": 0, "partial": 1, "ok": 2, "n/a": 3}
    for r in sorted(model["rows"], key=lambda x: order[x["status"]]):
        miss = ", ".join(r.get("missing", [])) or "—"
        L.append(f"| {r['id']} {r['name']} | {label[r['status']]} | "
                 f"{len(r['implemented'])}/{len(r['required'])} | {miss} |")
    return "\n".join(L)
