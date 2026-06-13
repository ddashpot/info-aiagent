"""脅威コレクタ：新たな脅威を収集し threat_intake/ に投入する（プラグイン）。

『収集 → インテイク → プローブ反映 → 回帰』ループの先頭。コレクタは外部の脅威源
（フィード/ナレッジベース/社内レビュー結果）から、インテイク・スキーマ準拠の脅威定義を
取得し、``threat_intake/*.json`` として書き出す。以降は intake.ingest が検査へ落とし込む。

既定では外部接続なし（安全）。フィードURLは collectors 設定で明示的に与えたときのみ取得する。

設定例（collectors.json）::

    {
      "feeds": [
        { "name": "internal-redteam", "url": "https://feeds.example.com/ai-threats.json" }
      ]
    }

フィードのレスポンスは、インテイク・スキーマのエントリ配列（[{...}, ...]）であること。
"""
from __future__ import annotations

import json
import os
import urllib.request
from typing import Any, Dict, List

from .intake import DEFAULT_INTAKE_DIR, _PROBE_FIELDS  # noqa: F401 (schema参照)


class Collector:
    """コレクタ基底。collect() は インテイク・エントリの配列を返す。"""
    name = "base"

    def collect(self) -> List[Dict[str, Any]]:  # pragma: no cover - abstract
        raise NotImplementedError


class FeedCollector(Collector):
    """JSONフィードURLからインテイク・エントリ配列を取得する。"""

    def __init__(self, name: str, url: str, timeout: int = 30):
        self.name = name
        self.url = url
        self.timeout = timeout

    def collect(self) -> List[Dict[str, Any]]:
        req = urllib.request.Request(self.url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:  # noqa: S310 - 設定された源のみ
            data = json.loads(r.read().decode("utf-8", "replace"))
        if isinstance(data, dict) and "threats" in data:
            data = data["threats"]
        return data if isinstance(data, list) else []


def build_collectors(config: Dict[str, Any]) -> List[Collector]:
    cols: List[Collector] = []
    for feed in config.get("feeds", []):
        if feed.get("url"):
            cols.append(FeedCollector(feed.get("name", "feed"), feed["url"],
                                      int(feed.get("timeout", 30))))
    return cols


def run_collectors(config: Dict[str, Any], intake_dir: str = DEFAULT_INTAKE_DIR) -> List[str]:
    """全コレクタを実行し、収集した脅威を threat_intake/ に書き出す。書いたファイル名を返す。"""
    os.makedirs(intake_dir, exist_ok=True)
    written: List[str] = []
    for col in build_collectors(config):
        try:
            entries = col.collect()
        except Exception as exc:  # noqa: BLE001 - 1フィードの失敗で全体を止めない
            written.append(f"# {col.name}: 収集失敗 {type(exc).__name__}: {exc}")
            continue
        for e in entries:
            pid = e.get("id")
            if not pid:
                continue
            e.setdefault("source", col.name)
            fname = f"{col.name}__{pid}.json"
            path = os.path.join(intake_dir, fname)
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(e, fh, ensure_ascii=False, indent=2)
            written.append(fname)
    return written
