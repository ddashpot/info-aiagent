"""ターゲットアダプタの基底インタフェース。"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Response:
    """ターゲットからの応答を正規化したもの。"""
    text: str
    raw: Any = None
    tool_calls: List[Dict[str, Any]] = field(default_factory=list)
    latency_ms: int = 0
    error: Optional[str] = None
    meta: Dict[str, Any] = field(default_factory=dict)


class Target:
    """検査対象の抽象基底。

    サブクラスは ``_send(messages)`` を実装する。``messages`` はOpenAI形式の
    ``[{"role": "system|user|assistant", "content": str}, ...]``。
    レート制限はここで一元的に適用される。
    """

    def __init__(self, cfg: Dict[str, Any]):
        self.cfg = cfg
        self.system_prompt: str = cfg.get("system", "") or ""
        self.timeout: float = float(cfg.get("timeout", 30))
        self._min_interval = 0.0
        rpm = float(cfg.get("rate_limit_per_min", 0) or 0)
        if rpm > 0:
            self._min_interval = 60.0 / rpm
        self._last_call = 0.0

    # --- public API ---
    def send(self, user_prompt: str, *, system: Optional[str] = None,
             history: Optional[List[Dict[str, str]]] = None) -> Response:
        messages: List[Dict[str, str]] = []
        sys = system if system is not None else self.system_prompt
        if sys:
            messages.append({"role": "system", "content": sys})
        if history:
            messages.extend(history)
        messages.append({"role": "user", "content": user_prompt})
        self._throttle()
        t0 = time.time()
        try:
            resp = self._send(messages)
        except Exception as exc:  # noqa: BLE001 - 検査継続のため握りつぶしてResponseに格納
            resp = Response(text="", error=f"{type(exc).__name__}: {exc}")
        resp.latency_ms = int((time.time() - t0) * 1000)
        return resp

    # --- to override ---
    def _send(self, messages: List[Dict[str, str]]) -> Response:  # pragma: no cover - abstract
        raise NotImplementedError

    def describe(self) -> str:
        return f"{type(self).__name__}"

    # --- helpers ---
    def _throttle(self) -> None:
        if self._min_interval <= 0:
            return
        elapsed = time.time() - self._last_call
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)
        self._last_call = time.time()
