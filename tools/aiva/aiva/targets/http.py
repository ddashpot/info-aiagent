"""汎用HTTPアダプタ（任意のJSON APIに対応）。

設定例::

    "target": {
      "type": "http",
      "url": "https://your-app.example.com/api/chat",
      "method": "POST",
      "headers": {"Authorization": "Bearer ${env:APP_TOKEN}", "Content-Type": "application/json"},
      "body_template": {"messages": "${messages}", "input": "${prompt}"},
      "response_path": "data.reply",       // 応答テキストの取り出し先（ドット区切り）
      "tool_calls_path": "data.tool_calls" // 任意：ツール呼び出しの取り出し先
    }

``${prompt}`` は最新ユーザ発話、``${messages}`` はOpenAI形式メッセージ配列、
``${system}`` はシステムプロンプトに置換される。``${env:NAME}`` は環境変数に置換。
"""
from __future__ import annotations

import json
import os
import re
import urllib.request
from typing import Any, Dict, List

from .base import Response, Target

_ENV_RE = re.compile(r"\$\{env:([A-Za-z_][A-Za-z0-9_]*)\}")


def _subst_env(value: Any) -> Any:
    if isinstance(value, str):
        return _ENV_RE.sub(lambda m: os.environ.get(m.group(1), ""), value)
    if isinstance(value, dict):
        return {k: _subst_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_subst_env(v) for v in value]
    return value


def _subst_body(value: Any, ctx: Dict[str, Any]) -> Any:
    """body_template内のプレースホルダを文脈で置換する。"""
    if isinstance(value, str):
        if value == "${messages}":
            return ctx["messages"]
        if value == "${prompt}":
            return ctx["prompt"]
        if value == "${system}":
            return ctx["system"]
        out = value.replace("${prompt}", ctx["prompt"]).replace("${system}", ctx["system"])
        return _subst_env(out)
    if isinstance(value, dict):
        return {k: _subst_body(v, ctx) for k, v in value.items()}
    if isinstance(value, list):
        return [_subst_body(v, ctx) for v in value]
    return value


def _dig(obj: Any, path: str) -> Any:
    """ドット区切りパスでネストしたJSONを取り出す（数値は配列添字）。"""
    if not path:
        return obj
    cur = obj
    for part in path.split("."):
        if cur is None:
            return None
        if isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return None
        elif isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


class HTTPTarget(Target):
    def __init__(self, cfg: Dict[str, Any]):
        super().__init__(cfg)
        self.url = cfg["url"]
        self.method = (cfg.get("method") or "POST").upper()
        self.headers = _subst_env(cfg.get("headers", {"Content-Type": "application/json"}))
        self.body_template = cfg.get("body_template", {"prompt": "${prompt}"})
        self.response_path = cfg.get("response_path", "")
        self.tool_calls_path = cfg.get("tool_calls_path", "")

    def describe(self) -> str:
        return f"HTTPTarget({self.method} {self.url})"

    def _send(self, messages: List[Dict[str, str]]) -> Response:
        user = messages[-1]["content"] if messages else ""
        system = next((m["content"] for m in messages if m["role"] == "system"), "")
        ctx = {"messages": messages, "prompt": user, "system": system}
        body = _subst_body(self.body_template, ctx)
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(self.url, data=data, method=self.method,
                                     headers={**self.headers})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:  # noqa: S310 - 設定された対象のみ
            payload = r.read().decode("utf-8", "replace")
        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError:
            return Response(text=payload, raw=payload)
        text = _dig(parsed, self.response_path) if self.response_path else parsed
        if not isinstance(text, str):
            text = json.dumps(text, ensure_ascii=False)
        tool_calls = []
        if self.tool_calls_path:
            tc = _dig(parsed, self.tool_calls_path)
            if isinstance(tc, list):
                tool_calls = tc
        return Response(text=text, raw=parsed, tool_calls=tool_calls)
