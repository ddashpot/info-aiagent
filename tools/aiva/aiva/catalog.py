"""共有脆弱性カタログ（ai_security_catalog.json）のローダ。

スキャナのプローブ結果をカタログの脆弱性ID・コントロール・準拠フレームワークへ
マッピングするために使う。カタログはリポジトリ直下に置かれる単一の真実の源。
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional


def _default_catalog_path() -> str:
    """リポジトリ直下の ai_security_catalog.json を探索する。"""
    here = os.path.dirname(os.path.abspath(__file__))
    # tools/aiva/aiva -> tools/aiva -> tools -> repo root
    candidates = [
        os.path.join(here, "ai_security_catalog.json"),
        os.path.normpath(os.path.join(here, "..", "..", "..", "ai_security_catalog.json")),
        os.path.normpath(os.path.join(here, "..", "..", "ai_security_catalog.json")),
        os.path.join(os.getcwd(), "ai_security_catalog.json"),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return candidates[1]


class Catalog:
    """脆弱性カタログへの読み取り専用アクセサ。"""

    def __init__(self, data: Dict[str, Any]):
        self.data = data
        self.meta: Dict[str, Any] = data.get("meta", {})
        self.vulns: List[Dict[str, Any]] = data.get("vulnerabilities", [])
        self.categories: List[Dict[str, Any]] = data.get("categories", [])
        self._by_id = {v["id"]: v for v in self.vulns}

    @classmethod
    def load(cls, path: Optional[str] = None) -> "Catalog":
        path = path or _default_catalog_path()
        with open(path, "r", encoding="utf-8") as fh:
            return cls(json.load(fh))

    def get(self, vuln_id: str) -> Optional[Dict[str, Any]]:
        return self._by_id.get(vuln_id)

    def name_of(self, vuln_id: str) -> str:
        v = self.get(vuln_id)
        return v["name"] if v else vuln_id

    def severity_of(self, vuln_id: str) -> str:
        v = self.get(vuln_id)
        return v.get("severity", "medium") if v else "medium"

    def controls_for(self, vuln_id: str) -> List[Dict[str, Any]]:
        v = self.get(vuln_id)
        return v.get("controls", []) if v else []

    def foundations_for(self, vuln_id: str) -> List[str]:
        v = self.get(vuln_id)
        return v.get("foundations", []) if v else []

    def references_for(self, vuln_id: str) -> List[str]:
        v = self.get(vuln_id)
        refs: List[str] = []
        if v:
            refs += v.get("references", [])
            refs += v.get("atlas", [])
        return refs
