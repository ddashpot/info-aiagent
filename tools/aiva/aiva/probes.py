"""プローブライブラリ（data/probes.json）のロードと選択。"""
from __future__ import annotations

import fnmatch
import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Probe:
    id: str
    vuln: str
    title: str
    category: str
    severity: str
    mode: str = "active"
    expect: str = "refuse"
    mutatable: bool = False
    technique: str = ""
    tags: List[str] = field(default_factory=list)
    payloads: List[str] = field(default_factory=list)
    turns: List[str] = field(default_factory=list)
    detectors: List[Dict[str, Any]] = field(default_factory=list)
    control_variant: str = ""  # 差分オラクル用：対照（素の要求版）。これが拒否され主payloadが追従なら枠組み依存バイパス
    note: str = ""

    @property
    def is_active(self) -> bool:
        return self.mode == "active"

    @property
    def messages(self) -> List[List[str]]:
        """検査で送る会話列。単発はpayloadごとに1会話、turnsは1会話で連続送信。"""
        if self.turns:
            return [self.turns]
        return [[p] for p in self.payloads]


def _probes_path() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "probes.json")


def load_probes(path: Optional[str] = None) -> List[Probe]:
    with open(path or _probes_path(), "r", encoding="utf-8") as fh:
        data = json.load(fh)
    out: List[Probe] = []
    for p in data.get("probes", []):
        out.append(Probe(
            id=p["id"], vuln=p["vuln"], title=p["title"], category=p["category"],
            severity=p.get("severity", "medium"), mode=p.get("mode", "active"),
            expect=p.get("expect", "refuse"), mutatable=p.get("mutatable", False),
            technique=p.get("technique", ""), tags=p.get("tags", []),
            payloads=p.get("payloads", []), turns=p.get("turns", []),
            detectors=p.get("detectors", []), control_variant=p.get("control_variant", ""),
            note=p.get("note", ""),
        ))
    return out


def select_probes(probes: List[Probe], *, selectors: List[str],
                  categories: List[str]) -> List[Probe]:
    """selectors（"all"/プローブID/脆弱性ID/グロブ）と categories で絞り込む。"""
    cats = [c.lower() for c in categories]
    cat_ok = "all" in cats
    sel_all = "all" in selectors

    def match_sel(pr: Probe) -> bool:
        if sel_all:
            return True
        for s in selectors:
            if s == pr.id or s == pr.vuln:
                return True
            if any(ch in s for ch in "*?[") and (
                fnmatch.fnmatch(pr.id, s) or fnmatch.fnmatch(pr.vuln, s)):
                return True
        return False

    out = []
    for pr in probes:
        if not (cat_ok or pr.category.lower() in cats):
            continue
        if not match_sel(pr):
            continue
        out.append(pr)
    return out
