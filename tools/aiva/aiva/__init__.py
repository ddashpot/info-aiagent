"""aiva — AI / Agentic AI Vulnerability Assessment toolkit.

汎用・依存ゼロ（Python標準ライブラリのみ）の能動スキャナ。
任意のLLM / エージェントAPIを設定（BYO-endpoint）で検査し、
既知脆弱性プローブと未知脆弱性の変異・回帰探索を実行してレポートを生成する。

共有カタログ ``ai_security_catalog.json`` を真実の源とし、
HTML自己評価ツール ``ai_security_assessment.html`` と知見を共有する。
"""

__version__ = "1.5.0"
__all__ = ["__version__"]
