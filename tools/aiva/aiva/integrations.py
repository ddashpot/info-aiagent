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
import subprocess
import tempfile
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

    def run(self, target_cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
        """garak を subprocess 実行し、レポート(JSONL)をパースして返す。

        target_cfg: { model_type, model_name, probes:[...], generations, timeout }
        garak 未導入時は RuntimeError。
        """
        if not self.available():
            raise RuntimeError("garak 未導入: pipx install garak")
        mt = target_cfg.get("model_type", "openai")
        mn = target_cfg.get("model_name", "gpt-4o-mini")
        probes = target_cfg.get("probes") or ["promptinject", "dan", "leakreplay"]
        tmp = tempfile.mkdtemp(prefix="aiva_garak_")
        prefix = os.path.join(tmp, "garak")
        cmd = ["garak", "--model_type", mt, "--model_name", mn,
               "--probes", ",".join(probes), "--report_prefix", prefix]
        if target_cfg.get("generations"):
            cmd += ["--generations", str(target_cfg["generations"])]
        subprocess.run(cmd, check=False, timeout=target_cfg.get("timeout", 3600))  # noqa: S603
        report = prefix + ".report.jsonl"
        return self.parse_report(report) if os.path.isfile(report) else []

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


class McpScanIntegration(Integration):
    """mcp-scan(Invariant Labs) を実行し、結果を MCP-01/MCP-02 へ正規化する。"""

    def run(self, target_cfg: Dict[str, Any]) -> Any:
        if not self.available():
            raise RuntimeError("mcp-scan 未導入: pipx install mcp-scan")
        mcp_config = target_cfg.get("mcp_config")
        cmd = ["mcp-scan", "scan"] + ([mcp_config] if mcp_config else []) + ["--json"]
        proc = subprocess.run(cmd, capture_output=True, text=True,  # noqa: S603
                              timeout=target_cfg.get("timeout", 600))
        try:
            return json.loads(proc.stdout)
        except json.JSONDecodeError:
            return {}

    def normalize(self, raw: Any) -> List[Dict[str, Any]]:
        issues: List[Dict[str, Any]] = []

        def walk(o: Any) -> None:
            if isinstance(o, dict):
                # issue らしいリーフ（severity か message/type を持つ）
                if any(k in o for k in ("severity", "message", "type", "label", "issue")):
                    issues.append(o)
                for v in o.values():
                    walk(v)
            elif isinstance(o, list):
                for v in o:
                    walk(v)

        walk(raw)
        out, seen = [], set()
        for it in issues:
            blob = json.dumps(it, ensure_ascii=False)
            low = blob.lower()
            vuln = "MCP-02" if any(w in low for w in
                                   ("permission", "scope", "privilege", "権限", "deputy")) else "MCP-01"
            ev = (it.get("message") or it.get("label") or it.get("type") or blob)[:200]
            key = (vuln, ev)
            if key in seen:
                continue
            seen.add(key)
            out.append({"source": "mcp-scan", "vuln": vuln, "evidence": ev})
        return out


_ADAPTERS: Dict[str, Callable[[Dict[str, Any]], Integration]] = {
    "garak": GarakIntegration,
    "pyrit": PyritIntegration,
    "mcp-scan": McpScanIntegration,
}


def collect_external(registry: Dict[str, Any], *, run_tools: List[str] = None,
                     imports: Dict[str, str] = None, tool_cfg: Dict[str, Any] = None,
                     log=None) -> List[Dict[str, Any]]:
    """外部ツールを実行 or レポート取込し、正規化所見をまとめて返す（統合実行）。

    run_tools: 実行するツールID（導入済みのみ）。imports: {tool_id: report_path}。
    """
    run_tools = run_tools or []
    imports = imports or {}
    tool_cfg = tool_cfg or {}
    log = log or (lambda *_a, **_k: None)
    specs = {t["id"]: t for t in registry.get("tools", [])}
    findings: List[Dict[str, Any]] = []

    for tid, path in imports.items():
        spec = specs.get(tid)
        integ = build_integration(spec) if spec else None
        if not integ:
            log(f"[external] {tid}: 取込アダプタ未対応・未知ツール")
            continue
        if tid == "garak":
            raw = GarakIntegration.parse_report(path)
        else:
            with open(path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
        fs = integ.normalize(raw)
        log(f"[external] {tid}: 取込 {len(fs)} 件 ({path})")
        findings += fs

    for tid in run_tools:
        spec = specs.get(tid)
        integ = build_integration(spec) if spec else None
        if not integ:
            log(f"[external] {tid}: 実行アダプタ未対応")
            continue
        if not integ.available():
            log(f"[external] {tid}: 未導入のためスキップ（{spec.get('install','')}）")
            continue
        fs = integ.normalize(integ.run(tool_cfg.get(tid, {})))
        log(f"[external] {tid}: 実行 {len(fs)} 件")
        findings += fs
    return findings


def build_integration(spec: Dict[str, Any]) -> Optional[Integration]:
    a = spec.get("adapter")
    if a and a in _ADAPTERS:
        return _ADAPTERS[a](spec)
    if a is None:
        return None
    return Integration(spec)
