"""所見をレポート（JSON / Markdown / HTML）として出力する。

各所見をカタログの脆弱性・コントロール・実装基盤・準拠フレームワークへ
マッピングし、是正の指針まで含める。
"""
from __future__ import annotations

import html
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List

from .catalog import Catalog
from .detectors import oracle_of
from .engine import Finding, ScanResult

_STATUS_LABEL = {
    "vulnerable": "脆弱（要対応）",
    "weak": "弱兆候（要確認）",
    "anomaly": "未知候補（要トリアージ）",
    "pass": "合格",
    "manual": "手動点検",
    "error": "エラー",
    "skipped": "未実施",
}
_STATUS_ORDER = ["vulnerable", "weak", "anomaly", "manual", "error", "pass", "skipped"]
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _sorted_findings(findings: List[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda f: (_STATUS_ORDER.index(f.status) if f.status in _STATUS_ORDER else 9,
                                           _SEV_ORDER.get(f.severity, 5), -f.score))


def build_report_model(result: ScanResult, catalog: Catalog, cfg: Dict[str, Any],
                       external: List[Dict[str, Any]] = None) -> Dict[str, Any]:
    findings = _sorted_findings(result.findings)
    oracle_counts: Dict[str, int] = {}
    items = []
    for f in findings:
        for s in f.matched_signals:
            oc = oracle_of(s.get("detector", ""))
            s["oracle"] = oc
            if f.status in ("vulnerable", "weak", "anomaly"):
                oracle_counts[oc] = oracle_counts.get(oc, 0) + 1
        items.append({
            "probe_id": f.probe_id,
            "vuln_id": f.vuln,
            "vuln_name": catalog.name_of(f.vuln),
            "title": f.title,
            "category": f.category,
            "severity": f.severity,
            "status": f.status,
            "status_label": _STATUS_LABEL.get(f.status, f.status),
            "score": f.score,
            "expect": f.expect,
            "best_payload": f.best_payload,
            "best_response": f.best_response,
            "best_lineage": f.best_lineage,
            "matched_signals": f.matched_signals,
            "attempts": f.attempts,
            "note": f.note,
            "controls": catalog.controls_for(f.vuln),
            "foundations": catalog.foundations_for(f.vuln),
            "references": catalog.references_for(f.vuln),
        })
    return {
        "meta": {
            "title": cfg.get("title", "AI脆弱性検査レポート"),
            "generated_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
            "target": result.target_desc,
            "requests": result.requests,
            "duration_s": result.duration_s,
            "catalog_version": catalog.meta.get("version"),
        },
        "summary": result.summary(),
        "oracle_counts": oracle_counts,
        "findings": items,
        "external": [
            {**e, "vuln_name": catalog.name_of(e.get("vuln", "")),
             "severity": catalog.severity_of(e.get("vuln", ""))}
            for e in (external or [])
        ],
    }


def write_reports(model: Dict[str, Any], cfg: Dict[str, Any]) -> List[str]:
    out_dir = cfg.get("out_dir", "./aiva_report")
    os.makedirs(out_dir, exist_ok=True)
    formats = cfg.get("formats", ["md", "json"])
    written: List[str] = []
    if "json" in formats:
        p = os.path.join(out_dir, "report.json")
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(model, fh, ensure_ascii=False, indent=2)
        written.append(p)
    if "md" in formats:
        p = os.path.join(out_dir, "report.md")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(render_markdown(model))
        written.append(p)
    if "html" in formats:
        p = os.path.join(out_dir, "report.html")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(render_html(model))
        written.append(p)
    if "sarif" in formats:
        p = os.path.join(out_dir, "report.sarif")
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(render_sarif(model), fh, ensure_ascii=False, indent=2)
        written.append(p)
    if "junit" in formats:
        p = os.path.join(out_dir, "report.junit.xml")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(render_junit(model))
        written.append(p)
    return written


def render_junit(model: Dict[str, Any]) -> str:
    """JUnit XML（CIのテストレポータが各プローブをテストケースとして表示）。

    vulnerable/weak/anomaly → failure、manual/skipped → skipped、それ以外 → 成功。
    """
    from xml.sax.saxutils import escape, quoteattr
    findings = model["findings"]
    fail_st = {"vulnerable", "weak", "anomaly"}
    skip_st = {"manual", "skipped"}
    failures = sum(1 for f in findings if f["status"] in fail_st)
    skipped = sum(1 for f in findings if f["status"] in skip_st)
    lines = ['<?xml version="1.0" encoding="UTF-8"?>']
    suite_attrs = (f'name="aiva" tests="{len(findings)}" failures="{failures}" '
                   f'skipped="{skipped}" time="{model["meta"].get("duration_s",0)}"')
    lines.append(f'<testsuites><testsuite {suite_attrs}>')
    for f in findings:
        cls = f'{f["category"]}.{f["vuln_id"]}'
        name = f'{f["probe_id"]} {f["title"]}'
        lines.append(f'  <testcase classname={quoteattr(cls)} name={quoteattr(name)}>')
        if f["status"] in fail_st:
            msg = f'[{f["vuln_id"]} {f["vuln_name"]}] {f["status_label"]} score={f["score"]}'
            detail = f'payload: {f.get("best_payload","")}\nresponse: {f.get("best_response","")}'
            lines.append(f'    <failure message={quoteattr(msg)} type={quoteattr(f["severity"])}>'
                         f'{escape(detail)}</failure>')
        elif f["status"] in skip_st:
            lines.append(f'    <skipped message={quoteattr(f.get("note") or f["status_label"])}/>')
        lines.append('  </testcase>')
    lines.append('</testsuite></testsuites>')
    return "\n".join(lines)


_SARIF_LEVEL = {"vulnerable": "error", "weak": "warning", "anomaly": "note"}
_SEC_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}


def render_sarif(model: Dict[str, Any]) -> Dict[str, Any]:
    """SARIF 2.1.0 出力（GitHub Code Scanning にアップロード可能）。"""
    m = model["meta"]
    rules: Dict[str, Dict[str, Any]] = {}
    results = []

    def add_rule(rid, name, sev):
        if rid not in rules:
            rules[rid] = {
                "id": rid, "name": name,
                "shortDescription": {"text": name},
                "properties": {"security-severity": _SEC_SEVERITY.get(sev, "5.5"),
                               "tags": ["ai-security", "owasp-llm"]},
            }

    for f in model["findings"]:
        level = _SARIF_LEVEL.get(f["status"])
        if not level:
            continue
        rid = f["probe_id"]
        add_rule(rid, f["title"], f["severity"])
        results.append({
            "ruleId": rid, "level": level,
            "message": {"text": f"[{f['vuln_id']} {f['vuln_name']}] {f['title']} "
                                f"(score={f['score']}, {f['status_label']})"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": m["target"]}}}],
            "properties": {"vuln": f["vuln_id"], "severity": f["severity"],
                           "score": f["score"], "source": "aiva"},
        })
    for e in model.get("external", []):
        rid = f"ext.{e.get('source')}.{e.get('vuln')}"
        add_rule(rid, f"{e.get('source')}: {e.get('vuln_name')}", e.get("severity", "medium"))
        results.append({
            "ruleId": rid, "level": "warning",
            "message": {"text": f"[{e.get('vuln')} {e.get('vuln_name')}] "
                                f"{str(e.get('evidence',''))[:200]} (via {e.get('source')})"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": m["target"]}}}],
            "properties": {"vuln": e.get("vuln"), "source": e.get("source")},
        })
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "aiva",
                "informationUri": "https://github.com/ddashpot/info-aiagent",
                "version": str(m.get("catalog_version", "1.0")),
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }


def render_markdown(model: Dict[str, Any]) -> str:
    m = model["meta"]
    s = model["summary"]
    lines = [
        f"# {m['title']}", "",
        f"- 生成日時: {m['generated_at']}",
        f"- 対象: `{m['target']}`",
        f"- リクエスト数: {m['requests']} / 所要 {m['duration_s']}s",
        f"- カタログ版: {m.get('catalog_version')}",
        "",
        "## サマリ", "",
        "| ステータス | 件数 |", "|---|---|",
    ]
    for st in _STATUS_ORDER:
        if st in s:
            lines.append(f"| {_STATUS_LABEL.get(st, st)} | {s[st]} |")
    lines += ["", "## 所見", ""]
    for f in model["findings"]:
        lines.append(f"### [{f['status_label']}] {f['probe_id']} — {f['title']}")
        lines.append("")
        lines.append(f"- 脆弱性: **{f['vuln_id']} {f['vuln_name']}** / 深刻度: {f['severity']} / スコア: {f['score']} / 試行: {f['attempts']}")
        if f["best_lineage"] and f["best_lineage"] != "seed":
            lines.append(f"- 成功した変異系譜: `{f['best_lineage']}`")
        if f["note"]:
            lines.append(f"- 備考: {f['note']}")
        if f["status"] in ("vulnerable", "weak", "anomaly") and f["best_payload"]:
            lines.append("")
            lines.append("再現ペイロード:")
            lines.append("```")
            lines.append(f["best_payload"])
            lines.append("```")
            lines.append("応答（抜粋）:")
            lines.append("```")
            lines.append(f["best_response"])
            lines.append("```")
            if f["matched_signals"]:
                sig = "; ".join(f"{x.get('label','')}({x.get('detector','')})" for x in f["matched_signals"])
                lines.append(f"- 検出シグナル: {sig}")
        if f["status"] in ("vulnerable", "weak", "anomaly", "manual"):
            if f["controls"]:
                lines.append("- 推奨コントロール:")
                for c in f["controls"]:
                    lines.append(f"  - [{c.get('type')}] **{c.get('name')}**: {c.get('desc')}（基盤: {c.get('foundation')}）")
            if f["foundations"]:
                lines.append(f"- 実装基盤: {', '.join(f['foundations'])}")
            if f["references"]:
                lines.append(f"- 参照: {', '.join(f['references'])}")
        lines.append("")
    ext = model.get("external", [])
    if ext:
        lines += ["## 外部ツール所見（統合実行）", "",
                  "| ツール | 脆弱性 | 深刻度 | 根拠 |", "|---|---|---|---|"]
        for e in ext:
            lines.append(f"| {e.get('source')} | {e.get('vuln')} {e.get('vuln_name')} | "
                         f"{e.get('severity')} | {str(e.get('evidence',''))[:120]} |")
        lines.append("")
    return "\n".join(lines)


def render_html(model: Dict[str, Any]) -> str:
    m = model["meta"]
    s = model["summary"]
    e = html.escape

    def chip(st: str, n: int) -> str:
        return f'<span class="chip {st}">{e(_STATUS_LABEL.get(st, st))}: {n}</span>'

    summary_chips = "".join(chip(st, s[st]) for st in _STATUS_ORDER if st in s)
    rows = []
    for f in model["findings"]:
        sigs = "; ".join(f"{e(str(x.get('label','')))}" for x in f["matched_signals"]) or "—"
        ctrls = "".join(
            f"<li><b>[{e(str(c.get('type')))}] {e(str(c.get('name')))}</b>: {e(str(c.get('desc')))} "
            f"<i>（基盤: {e(str(c.get('foundation')))}）</i></li>"
            for c in f["controls"]
        )
        payload_block = ""
        if f["status"] in ("vulnerable", "weak", "anomaly") and f["best_payload"]:
            payload_block = (
                f'<div class="repro"><div class="lbl">再現ペイロード'
                f'{(" / 変異: " + e(f["best_lineage"])) if f["best_lineage"]!="seed" else ""}</div>'
                f'<pre>{e(f["best_payload"])}</pre>'
                f'<div class="lbl">応答（抜粋）</div><pre>{e(f["best_response"])}</pre>'
                f'<div class="lbl">検出シグナル</div><div class="sig">{sigs}</div></div>'
            )
        rows.append(
            f'<details class="card {f["status"]}"><summary>'
            f'<span class="badge {f["status"]}">{e(f["status_label"])}</span> '
            f'<span class="sev {e(f["severity"])}">{e(f["severity"])}</span> '
            f'<code>{e(f["probe_id"])}</code> — {e(f["title"])} '
            f'<span class="vid">{e(f["vuln_id"])} {e(f["vuln_name"])}</span>'
            f'<span class="score">score {f["score"]}</span></summary>'
            f'<div class="body">'
            f'{("<p class=note>"+e(f["note"])+"</p>") if f["note"] else ""}'
            f'{payload_block}'
            f'{("<div class=ctrl><div class=lbl>推奨コントロール</div><ul>"+ctrls+"</ul></div>") if ctrls else ""}'
            f'{("<div class=found>実装基盤: "+e(", ".join(f["foundations"]))+"</div>") if f["foundations"] else ""}'
            f'{("<div class=ref>参照: "+e(", ".join(f["references"]))+"</div>") if f["references"] else ""}'
            f'</div></details>'
        )
    body = "\n".join(rows)
    return f"""<!doctype html><html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(m['title'])}</title>
<style>
:root{{--bg:#0f1420;--card:#1a2233;--mut:#8aa0c0;--fg:#e7eefc;--line:#2a3550}}
*{{box-sizing:border-box}} body{{margin:0;background:linear-gradient(180deg,#0c1018,#121a2b);color:var(--fg);font-family:system-ui,'Hiragino Kaku Gothic ProN',Meiryo,sans-serif;line-height:1.6}}
header{{padding:22px 18px;border-bottom:1px solid var(--line)}} h1{{margin:0 0 6px;font-size:20px}}
.meta{{color:var(--mut);font-size:13px}} main{{padding:18px;max-width:1000px;margin:0 auto}}
.chips{{margin:10px 0 18px}} .chip{{display:inline-block;padding:4px 10px;border-radius:999px;margin:3px;font-size:13px;background:#223;border:1px solid var(--line)}}
.chip.vulnerable{{background:#3a1620;color:#ffb4c0}} .chip.weak{{background:#3a2e16;color:#ffe0a0}} .chip.anomaly{{background:#2a1a3a;color:#d9b4ff}} .chip.pass{{background:#16321f;color:#a8f0c0}}
.card{{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--line);border-radius:10px;margin:10px 0;padding:6px 12px}}
.card.vulnerable{{border-left-color:#ff5d73}} .card.weak{{border-left-color:#ffc14d}} .card.anomaly{{border-left-color:#b07dff}} .card.manual{{border-left-color:#5d8bff}} .card.pass{{border-left-color:#3ec97a}}
summary{{cursor:pointer;display:flex;flex-wrap:wrap;gap:8px;align-items:center;font-size:14px}}
.badge{{padding:2px 8px;border-radius:6px;font-size:12px;font-weight:700}}
.badge.vulnerable{{background:#ff5d73;color:#1a0006}} .badge.weak{{background:#ffc14d;color:#2a1c00}} .badge.anomaly{{background:#b07dff;color:#1a0030}} .badge.manual{{background:#5d8bff;color:#001033}} .badge.pass{{background:#3ec97a;color:#002814}}
.sev{{font-size:11px;padding:1px 6px;border-radius:5px;border:1px solid var(--line);color:var(--mut)}}
.sev.critical{{color:#ff8da0;border-color:#ff5d73}} .sev.high{{color:#ffc14d}}
code{{background:#0c1322;padding:1px 6px;border-radius:5px}} .vid{{color:var(--mut);font-size:12px}} .score{{margin-left:auto;color:var(--mut);font-size:12px}}
.body{{padding:6px 2px 10px}} .lbl{{color:var(--mut);font-size:12px;margin:8px 0 3px}} pre{{background:#0a0f1c;border:1px solid var(--line);border-radius:8px;padding:10px;overflow:auto;white-space:pre-wrap;word-break:break-word;font-size:12.5px}}
.sig{{color:#ffd28a;font-size:13px}} ul{{margin:4px 0 4px 18px;padding:0}} li{{margin:3px 0;font-size:13px}} .found,.ref,.note{{color:var(--mut);font-size:12.5px;margin-top:6px}}
</style></head><body>
<header><h1>{e(m['title'])}</h1>
<div class="meta">対象: <code>{e(m['target'])}</code> ・ 生成: {e(m['generated_at'])} ・ リクエスト {m['requests']} ・ {m['duration_s']}s ・ カタログ v{e(str(m.get('catalog_version')))}</div></header>
<main><div class="chips">{summary_chips}</div>
<p class="meta">⚠ これは自動検査の所見です。脆弱・弱兆候・未知候補は再現確認と人手トリアージを行ってください。各項目に推奨コントロールと実装基盤を併記しています。</p>
{body}
</main></body></html>"""
