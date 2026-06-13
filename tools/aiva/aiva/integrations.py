"""外部セキュリティツールの統合（オーケストレーション）。

garak / PyRIT をはじめとする確立されたツールを、共有カタログの脆弱性へ
正規化して取り込むためのアダプタ基盤。aiva 自身は依存ゼロを保ち、外部ツールは
「あれば使う（無ければスキップ）」。各ツールの担当範囲(covers)はレジストリで宣言され、
aiva coverage の網羅性算定に使われる（ツール未導入でも『どのツールで埋まるか』は分かる）。

新しいツールを足すには tool_registry.json に1エントリ追加するだけ。実行・正規化まで
したい場合は Integration を実装し register する。
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
from typing import Any, Callable, Dict, List, Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
REGISTRY_PATH = os.path.join(_HERE, "data", "tool_registry.json")


def load_registry(path: Optional[str] = None) -> Dict[str, Any]:
    with open(path or REGISTRY_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


def is_available(detect: Dict[str, Any]) -> bool:
    """ツールが実行環境に存在するか（CLI: which / Python: import可能か）。"""
    if not detect:
        return False
    t, v = detect.get("type"), detect.get("value")
    if t == "cmd":
        return shutil.which(v) is not None
    if t == "module":
        try:
            return importlib.util.find_spec(v) is not None
        except (ImportError, ValueError, ModuleNotFoundError):
            return False
    return False


def tool_availability(registry: Optional[Dict[str, Any]] = None) -> Dict[str, bool]:
    reg = registry or load_registry()
    return {t["id"]: is_available(t.get("detect", {})) for t in reg.get("tools", [])}


# --- 実行アダプタ（任意・ツールが導入済みのときのみ動く） ---
class Integration:
    """外部ツール実行アダプタの基底。"""
    id = "base"
    covers: List[str] = []

    def __init__(self, spec: Dict[str, Any]):
        self.spec = spec
        self.id = spec["id"]
        self.covers = spec.get("covers", [])

    def available(self) -> bool:
        return is_available(self.spec.get("detect", {}))

    def run(self, target_cfg: Dict[str, Any]) -> Any:  # pragma: no cover - 外部ツール依存
        raise NotImplementedError(f"{self.id}: 実行アダプタ未実装（covers宣言のみ）")

    def normalize(self, raw: Any) -> List[Dict[str, Any]]:  # pragma: no cover
        raise NotImplementedError


class GarakIntegration(Integration):
    """garak のレポート(JSONL)を aiva 所見へ正規化する。

    実行は `garak --model_type <t> --model_name <n> --probes <...> --report_prefix <p>`。
    ここでは正規化（probe名→カタログ脆弱性）と、JSONLパースを提供する。
    """
    # garak プローブ接頭辞 → カタログ脆弱性ID の対応
    PROBE_MAP = {
        "promptinject": "LLM01", "dan": "LLM01", "encoding": "LLM01", "latentinjection": "LLM01",
        "leakreplay": "LLM02", "xss": "LLM05", "exploitation": "LLM05",
        "packagehallucination": "LLM09", "snowball": "LLM09", "misleading": "LLM09",
        "promptleak": "LLM07", "grandma": "LLM01", "malwaregen": "LLM05",
    }

    def normalize(self, raw: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for rec in raw:
            if rec.get("entry_type") != "attempt":
                continue
            probe = str(rec.get("probe_classname", "")).split(".")[0].lower()
            # 1つでも失敗(=脆弱)した試行か
            scores = rec.get("detector_results", {}) or {}
            hit = any(any(s and s > 0.5 for s in v) for v in scores.values() if isinstance(v, list))
            if not hit:
                continue
            vuln = next((vid for key, vid in self.PROBE_MAP.items() if key in probe), None)
            out.append({
                "source": "garak", "vuln": vuln or "LLM01",
                "probe": rec.get("probe_classname", probe),
                "evidence": (rec.get("prompt") or "")[:200],
            })
        return out

    @staticmethod
    def parse_report(path: str) -> List[Dict[str, Any]]:
        recs = []
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        recs.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return recs


class PyritIntegration(Integration):
    """PyRIT 連携（検出のみ）。PyRITはスクリプトで構成するため、実行は利用側に委ねる。"""
    def run(self, target_cfg: Dict[str, Any]) -> Any:  # pragma: no cover
        raise NotImplementedError(
            "PyRIT はオーケストレーションをスクリプトで定義します。"
            "PyRITのスコアラ結果を normalize() に渡して取り込んでください。")


_ADAPTERS: Dict[str, Callable[[Dict[str, Any]], Integration]] = {
    "garak": GarakIntegration,
    "pyrit": PyritIntegration,
}


def build_integration(spec: Dict[str, Any]) -> Optional[Integration]:
    a = spec.get("adapter")
    if a and a in _ADAPTERS:
        return _ADAPTERS[a](spec)
    if a is None:
        return None
    return Integration(spec)
