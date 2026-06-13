"""OpenAI互換 Chat Completions アダプタ。

OpenAI / Azure OpenAI / ローカル(vLLM, Ollama の OpenAI 互換エンドポイント) 等、
``/v1/chat/completions`` 形式のAPIに対応する。

設定例::

    "target": {
      "type": "openai",
      "url": "https://api.openai.com/v1/chat/completions",
      "model": "gpt-4o-mini",
      "api_key_env": "OPENAI_API_KEY",
      "system": "あなたは社内アシスタントです。",
      "temperature": 0
    }
"""
from __future__ import annotations

import json
import os
import urllib.request
from typing import Any, Dict, List

from .base import Response, Target


class OpenAICompatTarget(Target):
    def __init__(self, cfg: Dict[str, Any]):
        super().__init__(cfg)
        self.url = cfg.get("url", "https://api.openai.com/v1/chat/completions")
        self.model = cfg.get("model", "gpt-4o-mini")
        self.temperature = cfg.get("temperature", 0)
        key_env = cfg.get("api_key_env", "OPENAI_API_KEY")
        self.api_key = cfg.get("api_key") or os.environ.get(key_env, "")
        self.extra_headers = cfg.get("headers", {})

    def describe(self) -> str:
        return f"OpenAICompatTarget({self.model} @ {self.url})"

    def _send(self, messages: List[Dict[str, str]]) -> Response:
        body = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
        }
        headers = {"Content-Type": "application/json", **self.extra_headers}
        if self.api_key:
            headers.setdefault("Authorization", f"Bearer {self.api_key}")
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(self.url, data=data, method="POST", headers=headers)
        with urllib.request.urlopen(req, timeout=self.timeout) as r:  # noqa: S310 - 設定された対象のみ
            parsed = json.loads(r.read().decode("utf-8", "replace"))
        choice = (parsed.get("choices") or [{}])[0]
        msg = choice.get("message", {})
        text = msg.get("content") or ""
        tool_calls = msg.get("tool_calls") or []
        return Response(text=text, raw=parsed, tool_calls=tool_calls,
                        meta={"finish_reason": choice.get("finish_reason")})
