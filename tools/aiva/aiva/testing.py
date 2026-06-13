"""テストツールとしての利用ヘルパー。

pytest / unittest など既存のテストスイートから aiva をセキュリティテストとして
呼び出すための薄いAPI。依存ゼロ。

例（pytest / unittest どちらでも）::

    from aiva import testing

    def test_my_agent_is_secure():
        result = testing.scan({
            "target": {"type": "openai", "url": "...", "model": "...",
                       "api_key_env": "OPENAI_API_KEY", "system": "..."},
            "authorized": True,
        })
        testing.assert_secure(result, fail_on=("critical", "high"))

mock を対象にすれば外部接続なしで配線確認できる::

    result = testing.scan({"target": {"type": "mock"}})
    assert testing.findings(result, status=("vulnerable",))  # mockは脆弱
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

from .catalog import Catalog
from .config import load_config
from .engine import Engine, Finding, ScanResult
from .probes import load_probes, select_probes
from .targets import build_target

_FAIL_STATUS = ("vulnerable", "weak", "anomaly")


def scan(config: Optional[Dict[str, Any]] = None, *, catalog_path: Optional[str] = None,
         **scan_overrides: Any) -> ScanResult:
    """設定（辞書）でスキャンを実行し ScanResult を返す。

    config は cli の設定JSONと同じ構造（target/scan/authorized 等）。
    scan_overrides は config["scan"] への上書き（probes, categories, mutation 等）。
    mock 以外は config["authorized"] が True であること（テスト対象の許可前提）。
    """
    cfg = load_config(None)
    if config:
        # 浅いマージで十分（テスト用途）
        for k, v in config.items():
            if isinstance(v, dict) and isinstance(cfg.get(k), dict):
                cfg[k].update(v)
            else:
                cfg[k] = v
    cfg["scan"].update(scan_overrides)

    ttype = cfg["target"].get("type", "mock")
    if ttype != "mock" and not cfg.get("authorized"):
        raise PermissionError("能動検査には authorized=True（対象の検査許可）が必要です。")

    catalog = Catalog.load(catalog_path)
    target = build_target(cfg["target"])
    probes = select_probes(load_probes(), selectors=cfg["scan"].get("probes", ["all"]),
                           categories=cfg["scan"].get("categories", ["all"]))
    return Engine(target, catalog, cfg["scan"]).run(probes)


def findings(result: ScanResult, *, status: Iterable[str] = _FAIL_STATUS,
             severity: Optional[Iterable[str]] = None) -> List[Finding]:
    """条件に合う所見を返す。"""
    st = set(status)
    sev = set(severity) if severity else None
    return [f for f in result.findings
            if f.status in st and (sev is None or f.severity in sev)]


def assert_secure(result: ScanResult, *, fail_on: Iterable[str] = ("critical", "high"),
                  status: Iterable[str] = _FAIL_STATUS) -> None:
    """fail_on の深刻度に該当する所見があれば AssertionError を送出（テストを失敗させる）。"""
    bad = findings(result, status=status, severity=fail_on)
    if bad:
        lines = [f"- [{f.severity}] {f.probe_id} ({f.vuln}) {f.title}: {f.status}" for f in bad]
        raise AssertionError(
            f"セキュリティ所見 {len(bad)} 件（fail_on={sorted(set(fail_on))}）:\n" + "\n".join(lines))
