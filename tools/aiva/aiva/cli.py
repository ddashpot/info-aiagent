"""aiva コマンドラインインタフェース。

使用例::

    python -m aiva scan                      # ローカルmockを検査（デモ・自己テスト）
    python -m aiva scan --config conf.json    # BYO-endpointを検査
    python -m aiva scan --config conf.json --authorize --format md,html
    python -m aiva list-probes
    python -m aiva list-vulns

能動検査（mock以外）は対象所有者の許可が前提。設定の "authorized": true か
CLI --authorize を明示しない限り実行を拒否する（責任ある利用のためのガード）。
"""
from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import __version__
from .catalog import Catalog
from .config import load_config
from .engine import Engine
from .probes import load_probes, select_probes
from .report import build_report_model, write_reports
from .targets import build_target


def _eprint(*a, **k):
    print(*a, file=sys.stderr, **k)


def cmd_list_probes(args) -> int:
    probes = load_probes()
    cat = Catalog.load()
    for p in probes:
        active = "active" if p.is_active else "passive"
        print(f"{p.id:30s} {p.vuln:8s} [{active:7s}] {p.severity:8s} {p.title}")
    print(f"\n合計 {len(probes)} プローブ / カタログ脆弱性 {len(cat.vulns)} 件", file=sys.stderr)
    return 0


def cmd_list_vulns(args) -> int:
    cat = Catalog.load()
    for v in cat.vulns:
        print(f"{v['id']:10s} [{v['category']:8s}] {v.get('severity','?'):8s} {v['name']}")
    return 0


def cmd_ingest(args) -> int:
    from .intake import ingest, DEFAULT_INTAKE_DIR
    intake_dir = args.intake_dir or DEFAULT_INTAKE_DIR
    pending, msgs = ingest(intake_dir, write=args.write, catalog_path=args.catalog)
    for m in msgs:
        print(m)
    if args.write:
        return 0
    # --check: 未反映があれば非ゼロ（CI回帰ゲート）
    return 1 if pending else 0


def cmd_collect(args) -> int:
    import json as _json
    from .collectors import run_collectors
    cfg = {}
    if args.collectors:
        with open(args.collectors, "r", encoding="utf-8") as fh:
            cfg = _json.load(fh)
    written = run_collectors(cfg, args.intake_dir) if cfg.get("feeds") else []
    if not cfg.get("feeds"):
        print("コレクタ設定にフィードがありません（既定: 外部収集なし）。"
              "--collectors でフィードを指定するか、threat_intake/ に手動投入してください。")
        return 0
    print(f"収集して threat_intake/ に書き出し: {len(written)} 件")
    for w in written:
        print(f"  - {w}")
    return 0


def cmd_list_oracles(args) -> int:
    from .detectors import ORACLE_CLASSES, ORACLE_OF
    by_class = {}
    for det, oc in ORACLE_OF.items():
        by_class.setdefault(oc, []).append(det)
    for oc in ORACLE_CLASSES:
        dets = ", ".join(by_class.get(oc["id"], [])) or "（拡張点）"
        print(f"{oc['id']:12s} {oc['name']:16s} : {dets}")
    return 0


def cmd_tools(args) -> int:
    from .integrations import load_registry, tool_availability
    reg = load_registry()
    avail = tool_availability(reg)
    for t in reg.get("tools", []):
        mark = "✓" if avail.get(t["id"]) else " "
        print(f"[{mark}] {t['id']:14s} {t['kind']:14s} covers={','.join(t.get('covers', []))}")
    n_av = sum(1 for v in avail.values() if v)
    print(f"\n導入済み {n_av}/{len(avail)} ・ 防御(コントロール実装)は registry.defenses 参照", file=sys.stderr)
    return 0


def cmd_audit(args) -> int:
    import json as _json
    from .audit import load_arch, analyze as audit_analyze, render_markdown as audit_md
    catalog = Catalog.load(args.catalog)
    implemented = load_arch(args.arch)
    model = audit_analyze(catalog, implemented)
    if args.format == "json":
        print(_json.dumps(model, ensure_ascii=False, indent=2))
    else:
        print(audit_md(model))
    c = model["counts"]
    return 1 if c["missing"] else 0


def cmd_coverage(args) -> int:
    import json as _json
    from .coverage import analyze, render_markdown
    from .integrations import load_registry
    from .audit import load_arch
    catalog = Catalog.load(args.catalog)
    arch_controls = load_arch(args.arch) if getattr(args, "arch", None) else None
    model = analyze(catalog, only_available=args.only_available, arch_controls=arch_controls)
    if args.format == "json":
        print(_json.dumps(model, ensure_ascii=False, indent=2))
    else:
        print(render_markdown(model, load_registry()))
    c = model["counts"]
    print(f"\n=== 網羅性: 対応可能 {model['active_or_passive_or_tool_pct']}% "
          f"(自動検査 {model['covered_pct']}%) / 未カバー {c['gap']} 件 ===", file=sys.stderr)
    return 0


def cmd_run_tool(args) -> int:
    import json as _json
    from .integrations import load_registry, build_integration, GarakIntegration
    reg = load_registry()
    spec = next((t for t in reg["tools"] if t["id"] == args.tool), None)
    if not spec:
        _eprint(f"未知のツール: {args.tool}（aiva tools で一覧）")
        return 2
    integ = build_integration(spec)
    if integ is None:
        _eprint(f"{args.tool} は実行アダプタ未対応（covers宣言のみ）。aiva coverage を参照。")
        return 2

    # 取り込み（既存レポートを正規化）か、実行
    if args.import_file:
        if args.tool == "garak":
            raw = GarakIntegration.parse_report(args.import_file)
        else:
            with open(args.import_file, "r", encoding="utf-8") as fh:
                raw = _json.load(fh)
        findings = integ.normalize(raw)
    else:
        if not integ.available():
            _eprint(f"{args.tool} 未導入: {spec.get('install','')}  "
                    f"（既存レポートを取り込むなら --import FILE）")
            return 2
        tool_cfg = {}
        if args.tool_config:
            with open(args.tool_config, "r", encoding="utf-8") as fh:
                tool_cfg = _json.load(fh)
        findings = integ.normalize(integ.run(tool_cfg))

    catalog = Catalog.load(args.catalog)
    enriched = [{**f, "vuln_name": catalog.name_of(f.get("vuln", "")),
                 "severity": catalog.severity_of(f.get("vuln", ""))} for f in findings]
    if args.format == "json":
        print(_json.dumps(enriched, ensure_ascii=False, indent=2))
    else:
        print(f"# {spec['name']} 正規化所見（{len(enriched)} 件 → カタログにマッピング）\n")
        for f in enriched:
            print(f"- **{f.get('vuln')} {f['vuln_name']}** ({f['severity']}) "
                  f"〔{f.get('source')}〕 {str(f.get('evidence',''))[:160]}")
    print(f"\n{len(enriched)} 件を取り込み。`aiva coverage` で網羅性に反映。", file=sys.stderr)
    return 0


def cmd_scan(args) -> int:
    cfg = load_config(args.config)

    # CLIオーバーライド
    if args.target:
        cfg["target"]["type"] = args.target
    if args.dry_run:
        cfg["scan"]["dry_run"] = True
    if args.no_mutation:
        cfg["scan"]["mutation"]["enabled"] = False
    if args.probes:
        cfg["scan"]["probes"] = args.probes.split(",")
    if args.categories:
        cfg["scan"]["categories"] = args.categories.split(",")
    if args.out:
        cfg["report"]["out_dir"] = args.out
    if args.format:
        cfg["report"]["formats"] = args.format.split(",")
    if args.authorize:
        cfg["authorized"] = True

    target_type = cfg["target"].get("type", "mock")

    # --- 認可ゲート（mock以外の能動検査は明示同意が必須） ---
    if target_type != "mock" and not cfg.get("authorized") and not cfg["scan"].get("dry_run"):
        _eprint("✋ 能動検査には対象所有者の許可が必要です。")
        _eprint("   設定に \"authorized\": true を入れるか、--authorize を付けて、")
        _eprint("   あなたが検査対象を所有/明示的に検査許可されていることを確認してください。")
        _eprint("   （許可なきスキャンは行わないでください。--dry-run で送信内容の確認は可能です）")
        return 2

    catalog = Catalog.load(args.catalog)
    target = build_target(cfg["target"])
    all_probes = load_probes()
    probes = select_probes(all_probes,
                           selectors=cfg["scan"].get("probes", ["all"]),
                           categories=cfg["scan"].get("categories", ["all"]))
    if not probes:
        _eprint("対象プローブが0件です。--probes / --categories を確認してください。")
        return 2

    log = (lambda *a, **k: _eprint(*a, **k)) if not args.quiet else (lambda *a, **k: None)
    log(f"aiva v{__version__} — 対象: {target.describe()}  プローブ {len(probes)} 件"
        + ("  [DRY-RUN]" if cfg['scan'].get('dry_run') else ""))

    engine = Engine(target, catalog, cfg["scan"], verbose=args.verbose, log=log)
    result = engine.run(probes)

    # 外部ツール統合実行（--with-tools / --tool-import）
    external = []
    if args.with_tools or args.tool_import:
        from .integrations import load_registry, collect_external
        run_tools = args.with_tools.split(",") if args.with_tools else []
        imports = dict(kv.split("=", 1) for kv in args.tool_import.split(",")) if args.tool_import else {}
        external = collect_external(load_registry(), run_tools=run_tools, imports=imports, log=log)
        log(f"外部ツール所見: {len(external)} 件を統合")

    model = build_report_model(result, catalog, cfg["report"], external=external)
    written = write_reports(model, cfg["report"])

    s = result.summary()
    print("\n=== 検査サマリ ===")
    for k in ("vulnerable", "weak", "anomaly", "manual", "error", "pass", "skipped"):
        if k in s:
            print(f"  {k:11s}: {s[k]}")
    print(f"  リクエスト数: {result.requests} / {result.duration_s}s")
    if written:
        print("レポート:")
        for w in written:
            print(f"  - {w}")

    # 脆弱性が見つかればexit code 1（CI連携用）
    return 1 if (s.get("vulnerable", 0) or s.get("weak", 0) or s.get("anomaly", 0)) else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aiva",
                                description="AI/エージェンティックAI 脆弱性アセスメント（汎用・依存ゼロ）")
    p.add_argument("--version", action="version", version=f"aiva {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    sc = sub.add_parser("scan", help="ターゲットを検査する")
    sc.add_argument("--config", help="スキャン設定JSON（examples/ 参照）")
    sc.add_argument("--catalog", help="脆弱性カタログJSON（既定: リポジトリ直下）")
    sc.add_argument("--target", choices=["mock", "http", "openai"], help="target.type を上書き")
    sc.add_argument("--probes", help="カンマ区切り（プローブID/脆弱性ID/グロブ/all）")
    sc.add_argument("--categories", help="カンマ区切り（llm,agentic,infra,all）")
    sc.add_argument("--format", help="md,json,html,sarif のカンマ区切り")
    sc.add_argument("--out", help="レポート出力先ディレクトリ")
    sc.add_argument("--with-tools", help="統合実行する外部ツールID（例: garak,mcp-scan・導入済みのみ）")
    sc.add_argument("--tool-import", help="外部ツールのレポート取込（例: garak=report.jsonl,mcp-scan=res.json）")
    sc.add_argument("--authorize", action="store_true", help="検査対象の所有/検査許可を明示する")
    sc.add_argument("--dry-run", action="store_true", help="送信せず対象プローブのみ表示")
    sc.add_argument("--no-mutation", action="store_true", help="変異・未知探索を無効化")
    sc.add_argument("-v", "--verbose", action="store_true")
    sc.add_argument("-q", "--quiet", action="store_true")
    sc.set_defaults(func=cmd_scan)

    lp = sub.add_parser("list-probes", help="プローブ一覧")
    lp.set_defaults(func=cmd_list_probes)

    lv = sub.add_parser("list-vulns", help="カタログの脆弱性一覧")
    lv.set_defaults(func=cmd_list_vulns)

    lo = sub.add_parser("list-oracles", help="判定オラクルクラスと検出器の対応（MECE）")
    lo.set_defaults(func=cmd_list_oracles)

    to = sub.add_parser("tools", help="統合可能な外部セキュリティツールと導入状況")
    to.set_defaults(func=cmd_tools)

    cv = sub.add_parser("coverage", help="網羅性(カバレッジ)とギャップを算定")
    cv.add_argument("--catalog", help="脆弱性カタログJSON")
    cv.add_argument("--format", choices=["md", "json"], default="md")
    cv.add_argument("--only-available", action="store_true",
                    help="導入済みツールのみで集計（既定はレジストリ全ツールの潜在カバレッジ）")
    cv.add_argument("--arch", help="アーキ記述JSON（実装済みコントロール）を設定監査として加味")
    cv.set_defaults(func=cmd_coverage)

    au = sub.add_parser("audit", help="アーキ記述(実装コントロール)を監査し被覆を算定")
    au.add_argument("--arch", required=True, help="アーキ記述JSON（implemented_controls）")
    au.add_argument("--catalog", help="脆弱性カタログJSON")
    au.add_argument("--format", choices=["md", "json"], default="md")
    au.set_defaults(func=cmd_audit)

    rt = sub.add_parser("run-tool", help="外部ツールを実行/レポート取込しカタログ所見へ正規化（garak/mcp-scan）")
    rt.add_argument("tool", help="ツールID（例: garak, mcp-scan）")
    rt.add_argument("--import", dest="import_file", help="既存レポートを取り込んで正規化（garak=JSONL / mcp-scan=JSON）")
    rt.add_argument("--tool-config", help="実行時のツール設定JSON（model_type/probes 等）")
    rt.add_argument("--catalog", help="脆弱性カタログJSON")
    rt.add_argument("--format", choices=["md", "json"], default="md")
    rt.set_defaults(func=cmd_run_tool)

    ig = sub.add_parser("ingest", help="threat_intake の脅威を検査(プローブ)へ反映")
    ig.add_argument("--intake-dir", help="インテイク・ディレクトリ（既定: tools/aiva/threat_intake）")
    ig.add_argument("--catalog", help="脆弱性カタログJSON")
    ig.add_argument("--write", action="store_true", help="実際に反映する（既定はcheckのみ・未反映で非ゼロ終了）")
    ig.add_argument("--check", action="store_true", help="検証のみ（既定動作。未反映があれば非ゼロ終了）")
    ig.set_defaults(func=cmd_ingest)

    co = sub.add_parser("collect", help="コレクタで新たな脅威を収集し threat_intake へ投入")
    co.add_argument("--collectors", help="コレクタ設定JSON（feeds[].url）")
    co.add_argument("--intake-dir", help="インテイク・ディレクトリ")
    co.set_defaults(func=cmd_collect)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
