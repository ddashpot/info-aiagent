"""スキャン設定（JSON）のロードと既定値マージ。

YAMLは標準ライブラリに含まれないため、依存ゼロを保つためJSON設定を採用する。
設定例は examples/ を参照。
"""
from __future__ import annotations

import copy
import json
from typing import Any, Dict

DEFAULTS: Dict[str, Any] = {
    # 検査対象（BYO-endpoint）
    "target": {
        "type": "mock",          # mock | http | openai
        "timeout": 30,
        "rate_limit_per_min": 0,  # 0 = 無制限（ローカルmock向け）
        "system": "",
    },
    # 能動検査は対象所有者の許可が前提。mock以外はこのフラグかCLI --authorize が必須。
    "authorized": False,
    "scan": {
        "probes": ["all"],          # ["all"] / 個別ID / "LLM01" 等のvuln-id / "pi_*" のグロブ
        "categories": ["all"],      # llm | agentic | infra | all
        "max_payloads_per_probe": 0,  # 0 = 無制限
        "mutation": {
            "enabled": True,
            "max_variants": 6,
            "recursive_depth": 2,
            "beam": 3,
        },
        "unknown": {"enabled": True},
        "dry_run": False,
    },
    "report": {
        "formats": ["md", "json"],
        "out_dir": "./aiva_report",
        "title": "AI/エージェンティックAI 脆弱性検査レポート",
    },
}


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def load_config(path: str | None) -> Dict[str, Any]:
    if not path:
        return copy.deepcopy(DEFAULTS)
    with open(path, "r", encoding="utf-8") as fh:
        user = json.load(fh)
    return _deep_merge(DEFAULTS, user)
