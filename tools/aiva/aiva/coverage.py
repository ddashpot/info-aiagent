"""網羅性（カバレッジ）分析。

カタログの脆弱性(surface×failure_mode)を母集合とし、各脆弱性が
  - aiva ネイティブの能動プローブ
  - 受動点検（設計/設定の手動確認）
  - 外部ツール（レジストリの covers 宣言）
のどれでカバーされているかを算定し、空白(ギャップ)を明示する。
『garak/PyRITほかを組み合わせて全て網羅できているか』に定量的に答える。
"""
from __future__ import annotations

from typing import Any, Dict, List

from .catalog import Catalog
from .integrations import load_registry, tool_availability
from .probes import load_probes


def analyze(catalog: Catalog = None, *, only_available: bool = False,
            arch_controls=None) -> Dict[str, Any]:
    catalog = catalog or Catalog.load()
    arch_controls = set(arch_controls or [])
    probes = load_probes()
    registry = load_registry()
    avail = tool_availability(registry)

    # 脆弱性ID -> ネイティブプローブ状況
    active_by_vuln: Dict[str, int] = {}
    passive_by_vuln: Dict[str, int] = {}
    for p in probes:
        d = active_by_vuln if p.is_active else passive_by_vuln
        d[p.vuln] = d.get(p.vuln, 0) + 1

    # 脆弱性ID -> 対応ツール
    tools_by_vuln: Dict[str, List[str]] = {}
    for t in registry.get("tools", []):
        if only_available and not avail.get(t["id"]):
            continue
        for vid in t.get("covers", []):
            tools_by_vuln.setdefault(vid, []).append(t["id"])

    rows = []
    counts = {"active": 0, "tool": 0, "audit": 0, "passive": 0, "gap": 0}
    cell_cov: Dict[str, Dict[str, int]] = {}
    for v in catalog.vulns:
        vid = v["id"]
        has_active = active_by_vuln.get(vid, 0) > 0
        tools = sorted(set(tools_by_vuln.get(vid, [])))
        has_passive = passive_by_vuln.get(vid, 0) > 0
        impl_ctrls = [c["id"] for c in v.get("controls", []) if c["id"] in arch_controls]
        if has_active:
            status = "active"        # 能動検査でカバー
        elif tools:
            status = "tool"          # 外部ツールでカバー
        elif impl_ctrls:
            status = "audit"         # 設定監査でコントロール実装を確認
        elif has_passive:
            status = "passive"       # 受動点検のみ
        else:
            status = "gap"           # 未カバー
        counts[status] += 1
        cell = f"{v['surface']}×{v['failure_mode']}"
        cc = cell_cov.setdefault(cell, {"active": 0, "tool": 0, "audit": 0, "passive": 0, "gap": 0})
        cc[status] += 1
        rows.append({
            "id": vid, "name": v["name"], "severity": v.get("severity"),
            "surface": v["surface"], "failure_mode": v["failure_mode"],
            "native_active": active_by_vuln.get(vid, 0),
            "native_passive": passive_by_vuln.get(vid, 0),
            "tools": tools, "status": status,
        })

    total = len(catalog.vulns)
    covered = counts["active"] + counts["tool"]
    return {
        "total": total,
        "counts": counts,
        "covered_pct": round(100 * covered / total) if total else 0,
        "active_or_passive_or_tool_pct": round(100 * (total - counts["gap"]) / total) if total else 0,
        "rows": rows,
        "cells": cell_cov,
        "tool_availability": avail,
        "only_available": only_available,
    }


_STATUS_LABEL = {
    "active": "能動検査でカバー", "tool": "外部ツールでカバー",
    "audit": "設定監査でカバー", "passive": "受動点検のみ", "gap": "未カバー(要対応)",
}


def render_markdown(model: Dict[str, Any], registry: Dict[str, Any] = None) -> str:
    registry = registry or load_registry()
    tool_name = {t["id"]: t["name"] for t in registry.get("tools", [])}
    c = model["counts"]
    L = ["# AIセキュリティ 網羅性(カバレッジ)レポート", "",
         f"- 母集合: カタログ脆弱性 {model['total']} 件"
         + ("（導入済みツールのみ集計）" if model["only_available"] else "（レジストリの全ツールで集計）"),
         f"- 能動検査: **{c['active']}** / 外部ツール: **{c['tool']}** / 設定監査: {c.get('audit',0)} / 受動点検のみ: {c['passive']} / **未カバー: {c['gap']}**",
         f"- 何らかの手段で対応可能: **{model['active_or_passive_or_tool_pct']}%** "
         f"（うち能動自動検査={model['covered_pct']}%）", "",
         "## 脆弱性別カバレッジ", "",
         "| 脆弱性 | サーフェス×失敗モード | 状態 | aiva | 外部ツール |",
         "|---|---|---|---|---|"]
    order = {"gap": 0, "passive": 1, "audit": 2, "tool": 3, "active": 4}
    for r in sorted(model["rows"], key=lambda x: (order[x["status"]], x["id"])):
        tools = ", ".join(tool_name.get(t, t) for t in r["tools"]) or "—"
        native = (f"能動×{r['native_active']}" if r["native_active"]
                  else (f"受動×{r['native_passive']}" if r["native_passive"] else "—"))
        L.append(f"| {r['id']} {r['name']} | {r['surface']}×{r['failure_mode']} | "
                 f"{_STATUS_LABEL[r['status']]} | {native} | {tools} |")

    gaps = [r for r in model["rows"] if r["status"] in ("gap", "passive")]
    if gaps:
        L += ["", "## ギャップ（自動検査で未カバー＝受動/手動のみ・要対応）", ""]
        for r in gaps:
            L.append(f"- **{r['id']} {r['name']}**（{r['surface']}×{r['failure_mode']}）: "
                     f"{_STATUS_LABEL[r['status']]}。設計・運用での統制（HTML自己評価）か、"
                     f"対応ツール/プローブの追加を検討。")
    L += ["", "## ツール導入状況", ""]
    for t in registry.get("tools", []):
        mark = "✓導入済" if model["tool_availability"].get(t["id"]) else "未導入"
        L.append(f"- [{mark}] **{t['name']}** ({t['kind']}) → {', '.join(t.get('covers', []))}  〈{t.get('install','')}〉")
    return "\n".join(L)
