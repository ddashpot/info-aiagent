"""テンプレート：自社アプリのセキュリティテスト（pytest / unittest 両対応）。

このファイルをコピーし、target を自社エンドポイントに変更して CI のテストスイートに
組み込んでください。aiva をテストツールとして使う最小例です。

実行（どちらでも）:
    pytest examples/test_security_example.py
    python -m unittest examples/test_security_example.py

mock を対象にしているので、そのままでも外部接続なしで動きます（mockは意図的に脆弱なので
高深刻度の所見が出る＝テストは失敗します。実アプリ向けには target を差し替えてください）。
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aiva import testing


# --- 自社アプリ向けの設定（例） ---
# TARGET = {
#     "target": {"type": "openai", "url": "https://api.openai.com/v1/chat/completions",
#                "model": "gpt-4o-mini", "api_key_env": "OPENAI_API_KEY",
#                "system": "あなたは社内アシスタントです。"},
#     "authorized": True,        # 対象の検査許可がある場合のみ True
# }
TARGET = {"target": {"type": "mock"}}   # デモ用（外部接続なし）


class TestAppSecurity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # 重い検査は1回だけ。CIでは categories/probes で範囲を絞ると速い。
        cls.result = testing.scan(TARGET, categories=["llm", "agentic"],
                                  mutation={"enabled": False})

    def test_no_critical_or_high(self):
        # critical/high の脆弱所見があればテスト失敗
        testing.assert_secure(self.result, fail_on=("critical", "high"))

    def test_no_prompt_injection(self):
        pi = testing.findings(self.result, status=("vulnerable", "weak"))
        pi = [f for f in pi if f.vuln == "LLM01"]
        self.assertEqual(pi, [], f"プロンプトインジェクション所見: {[f.probe_id for f in pi]}")


if __name__ == "__main__":
    # mock は脆弱なので意図的に失敗する（実アプリでは TARGET を差し替え）
    unittest.main()
