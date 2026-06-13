"""検査対象アダプタ（BYO-endpoint）。

設定の ``target.type`` に応じて適切なアダプタを生成する。
拡張は build_target にタイプを追加するか、Target を継承して登録するだけでよい。
"""
from __future__ import annotations

from typing import Any, Dict

from .base import Response, Target
from .mock import MockTarget
from .http import HTTPTarget
from .openai import OpenAICompatTarget

__all__ = ["Response", "Target", "MockTarget", "HTTPTarget", "OpenAICompatTarget", "build_target"]


def build_target(cfg: Dict[str, Any]) -> Target:
    t = (cfg.get("type") or "mock").lower()
    if t == "mock":
        return MockTarget(cfg)
    if t == "http":
        return HTTPTarget(cfg)
    if t in ("openai", "openai-compat", "chat"):
        return OpenAICompatTarget(cfg)
    raise ValueError(f"未知のtarget.type: {t!r}（mock|http|openai）")
