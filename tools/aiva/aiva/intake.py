"""脅威インテイク：新たな脅威を収集し、検査（プローブ）と知識（カタログ）へ反映する仕組み。

回帰ループの自動化を担う中核。``threat_intake/*.json`` に投入された脅威定義を
検証し、プローブライブラリ（data/probes.json）へ upsert し、必要なら新規脆弱性を
カタログ（ai_security_catalog.json）へ追記する。GitHub Action から
``aiva ingest --check`` で「投入済み脅威がテストに反映されているか」を回帰ゲートとして検証し、
``aiva ingest --write`` で実際に反映する。

新たな脅威の「収集」は collectors.py のコレクタが threat_intake/ にファイルを書き出す形で
プラグイン化されており、ここはそれらを取り込んで検査へ落とし込む段を担う。

インテイク・スキーマ（1ファイル=1脅威=1プローブ）:
{
  "id": "probe_id",                 // 新プローブID（必須・一意）
  "vuln": "LLM01 / 新規ID",          // カタログ脆弱性ID（既存 or vuln_def を伴う新規）
  "title": "...", "category": "llm|agentic|infra|mcp", "severity": "...",
  "source": "出所(URL/フィード名)", "added": "YYYY-MM-DD",
  "mode": "active|passive", "expect": "refuse|sanitize|confirm|ground",
  "technique": "AML.Txxxx", "tags": [...],
  "payloads": [...], "turns": [...], "control_variant": "...",
  "detectors": [ {"type": "..."} ],
  "vuln_def": { ... 新規脆弱性のときカタログ用の完全エントリ ... }
}
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Tuple

from .catalog import Catalog, _default_catalog_path

_HERE = os.path.dirname(os.path.abspath(__file__))
PROBES_PATH = os.path.join(_HERE, "data", "probes.json")
DEFAULT_INTAKE_DIR = os.path.normpath(os.path.join(_HERE, "..", "threat_intake"))

_PROBE_FIELDS = ["id", "vuln", "title", "category", "severity", "mode", "expect",
                 "mutatable", "technique", "tags", "payloads", "turns",
                 "control_variant", "detectors", "note"]


def load_intake(intake_dir: str) -> List[Dict[str, Any]]:
    if not os.path.isdir(intake_dir):
        return []
    out = []
    for name in sorted(os.listdir(intake_dir)):
        if not name.endswith(".json") or name.startswith("_"):
            continue
        with open(os.path.join(intake_dir, name), "r", encoding="utf-8") as fh:
            data = json.load(fh)
        data["__file__"] = name
        out.append(data)
    return out


def validate(entry: Dict[str, Any], catalog: Catalog) -> List[str]:
    errs: List[str] = []
    for req in ("id", "vuln", "title", "category"):
        if not entry.get(req):
            errs.append(f"必須フィールド欠落: {req}")
    mode = entry.get("mode", "active")
    if mode == "active" and not (entry.get("payloads") or entry.get("turns")):
        errs.append("active プローブには payloads か turns が必要")
    vuln = entry.get("vuln")
    if vuln and not catalog.get(vuln) and not entry.get("vuln_def"):
        errs.append(f"未知の脆弱性ID {vuln}（既存IDにするか vuln_def を添付）")
    if entry.get("vuln_def"):
        vd = entry["vuln_def"]
        if vd.get("id") != vuln:
            errs.append("vuln_def.id は vuln と一致する必要がある")
        for req in ("surface", "failure_mode", "name", "severity", "category"):
            if not vd.get(req):
                errs.append(f"vuln_def に {req} が必要（MECE軸を含む）")
    return errs


def _probe_from_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    p = {k: entry[k] for k in _PROBE_FIELDS if k in entry}
    p.setdefault("mode", "active")
    p.setdefault("expect", "refuse")
    return p


def _load_probes_raw() -> Dict[str, Any]:
    with open(PROBES_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


def ingest(intake_dir: str = DEFAULT_INTAKE_DIR, *, write: bool = False,
           catalog_path: str = None) -> Tuple[int, List[str]]:
    """インテイクを取り込む。

    返り値: (反映が必要/実施された件数, メッセージ一覧)。
    write=False（--check）では書き込まず、未反映があればメッセージに記録し件数>0で返す。
    """
    catalog_path = catalog_path or _default_catalog_path()
    catalog = Catalog.load(catalog_path)
    entries = load_intake(intake_dir)
    msgs: List[str] = []
    if not entries:
        return 0, ["threat_intake にエントリがありません。"]

    probes_doc = _load_probes_raw()
    existing = {p["id"]: p for p in probes_doc["probes"]}
    catalog_ids = {v["id"] for v in catalog.vulns}

    pending = 0
    new_vulns: List[Dict[str, Any]] = []
    for e in entries:
        errs = validate(e, catalog)
        if errs:
            msgs.append(f"[NG] {e.get('__file__')}: " + "; ".join(errs))
            pending += 1
            continue
        pid = e["id"]
        probe = _probe_from_entry(e)
        # 新規脆弱性の取り込み
        if e.get("vuln_def") and e["vuln"] not in catalog_ids:
            new_vulns.append(e["vuln_def"])
            catalog_ids.add(e["vuln"])
            msgs.append(f"[+catalog] 新規脆弱性 {e['vuln']} を取り込み")
        # プローブの upsert 判定
        cur = existing.get(pid)
        if cur != probe:
            pending += 1
            msgs.append(f"[{'+' if cur is None else '~'}probe] {pid} ({e['vuln']}) {e['title']}"
                        + (f"  source={e.get('source')}" if e.get("source") else ""))
            existing[pid] = probe

    if write and pending:
        # probes.json 書き戻し（meta は保持、probes を upsert 後の集合で再構築）
        order = list(existing.values())
        probes_doc["probes"] = order
        with open(PROBES_PATH, "w", encoding="utf-8") as fh:
            json.dump(probes_doc, fh, ensure_ascii=False, indent=2)
        if new_vulns:
            cat_doc = json.load(open(catalog_path, encoding="utf-8"))
            cat_doc["vulnerabilities"].extend(new_vulns)
            with open(catalog_path, "w", encoding="utf-8") as fh:
                json.dump(cat_doc, fh, ensure_ascii=False, indent=2)
        msgs.append(f"[written] probes.json 更新（{pending} 件）"
                    + (f" / catalog に脆弱性 {len(new_vulns)} 件追加" if new_vulns else ""))
    elif pending and not write:
        msgs.append(f"未反映が {pending} 件あります。`aiva ingest --write` で反映してください。")
    else:
        msgs.append("インテイクは全て反映済みです（テストに反映されています）。")
    return pending, msgs
