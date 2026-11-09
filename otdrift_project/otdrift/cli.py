"""
CLI entry point for otdrift - OT/ICS Baseline Configuration Drift & MITRE ATT&CK Analyzer.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

# Ensure UTF-8 output encoding on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

import click
from rich.console import Console
from rich.table import Table

from otdrift.core.comparator import DriftComparator
from otdrift.core.loader import load_config, ConfigLoadError
from otdrift.rules.engine import SecurityRuleEngine
from otdrift.rules.mitre_ics import MITRE_ICS_TECHNIQUES
from otdrift.reporters.console_reporter import ConsoleReporter
from otdrift.reporters.json_reporter import JsonReporter
from otdrift.reporters.markdown_reporter import MarkdownReporter
from otdrift.reporters.html_reporter import HtmlReporter


console = Console()
err_console = Console(stderr=True)

SEVERITY_LEVELS = {
    "NEVER": 99,
    "CRITICAL": 1,
    "HIGH": 2,
    "MEDIUM": 3,
    "LOW": 4,
    "INFO": 5,
}


@click.group()
@click.version_option(version="1.0.0", prog_name="otdrift")
def cli():
    """🛡 otdrift - OT/ICS 工控設定飄移比對與 MITRE ATT&CK for ICS 資安稽核引擎."""
    pass


@cli.command(name="check")
@click.option("-b", "--baseline", required=True, type=click.Path(exists=True), help="黃金標準設定檔 (JSON 或 YAML)")
@click.option("-c", "--current", required=True, type=click.Path(exists=True), help="現場現況快照設定檔 (JSON 或 YAML)")
@click.option("-r", "--rules", type=click.Path(exists=True), default=None, help="自訂安全稽核規則檔 (YAML)")
@click.option("-f", "--format", "report_format", type=click.Choice(["console", "json", "html", "markdown"], case_sensitive=False), default="console", help="輸出報告格式")
@click.option("-o", "--output", type=click.Path(), default=None, help="報告儲存目標路徑 (若未指定 console 則輸出至終端)")
@click.option("--fail-on", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEVER"], case_sensitive=False), default="HIGH", help="觸發中斷 (Exit 1) 的最高風險門檻")
def check(baseline: str, current: str, rules: Optional[str], report_format: str, output: Optional[str], fail_on: str):
    """執行黃金標準與現況快照之設定飄移比對，自動對應 MITRE ATT&CK for ICS 威脅。"""
    try:
        baseline_data, baseline_meta = load_config(baseline)
        current_data, current_meta = load_config(current)
    except ConfigLoadError as e:
        err_console.print(f"[bold red]載入錯誤：[/bold red] {e}")
        sys.exit(2)

    # 1. Diff comparison
    comparator = DriftComparator()
    result = comparator.compare(
        baseline=baseline_data,
        current=current_data,
        baseline_meta=baseline_meta,
        current_meta=current_meta,
    )

    # 2. Rule evaluation & MITRE ICS mapping
    engine = SecurityRuleEngine(custom_rules_path=rules)
    result = engine.evaluate(result)

    # 3. Report generation
    reporters = {
        "console": ConsoleReporter(console=console),
        "json": JsonReporter(),
        "markdown": MarkdownReporter(),
        "html": HtmlReporter(),
    }
    reporter = reporters[report_format.lower()]

    if output:
        out_path = Path(output)
        reporter.save(result, out_path)
        console.print(f"[bold green]✓ 稽核報告已成功儲存至：[/bold green] [bold cyan]{out_path.resolve()}[/bold cyan]")
        if report_format.lower() == "console":
            # Also render to screen
            ConsoleReporter(console=console).print_to_stdout(result)
    else:
        if report_format.lower() == "console":
            ConsoleReporter(console=console).print_to_stdout(result)
        else:
            click.echo(reporter.generate(result))

    # 4. Exit code logic for CI/CD and automated alerts
    if fail_on.upper() != "NEVER":
        fail_threshold = SEVERITY_LEVELS.get(fail_on.upper(), 2)
        current_max_lvl = SEVERITY_LEVELS.get(result.max_severity, 99)

        if current_max_lvl <= fail_threshold:
            err_console.print(
                f"\n[bold red]🚨 警告：偵測到飄移風險 [{result.max_severity}] 達到或超過中斷門檻 [{fail_on.upper()}]！自動中斷管線。[/bold red]"
            )
            sys.exit(1)
    sys.exit(0)


@cli.command(name="rules")
@click.option("-r", "--rules", type=click.Path(exists=True), default=None, help="載入自訂規則檔")
def list_rules(rules: Optional[str]):
    """列出目前已載入的所有工控安全規則與 MITRE ATT&CK for ICS 對應。"""
    engine = SecurityRuleEngine(custom_rules_path=rules)
    table = Table(title="🛡 系統載入之工控安全飄移規則清單", header_style="bold magenta")
    table.add_column("規則編號", justify="center", width=14)
    table.add_column("等級", justify="center", width=10)
    table.add_column("檢驗參數路徑 (Path)", justify="left", width=34)
    table.add_column("MITRE ICS", justify="center", width=12)
    table.add_column("規則說明", justify="left")

    for r in engine.rules:
        sev_color = "red" if r.severity == "CRITICAL" else ("yellow" if r.severity == "HIGH" else "cyan")
        table.add_row(
            r.rule_id,
            f"[{sev_color}]{r.severity}[/]",
            r.path_pattern,
            r.mitre_technique_id,
            r.name,
        )
    console.print(table)


@cli.command(name="mitre")
def list_mitre():
    """查詢內建之 MITRE ATT&CK for ICS 戰術與技術知識庫清單。"""
    table = Table(title="🏭 MITRE ATT&CK for Industrial Control Systems (ICS) 知識庫", header_style="bold blue")
    table.add_column("技術 ID", justify="center", width=10)
    table.add_column("技術名稱 (Technique Name)", justify="left", width=25)
    table.add_column("工控戰術分類 (Tactic)", justify="left", width=25)
    table.add_column("威脅衝擊 (Impact)", justify="left")

    for tech_id, t in MITRE_ICS_TECHNIQUES.items():
        table.add_row(
            f"[bold cyan]{tech_id}[/]",
            t.name,
            t.tactic,
            t.impact,
        )
    console.print(table)


@cli.group(name="edge")
def edge_group():
    """🌐 OpenWrt 邊緣閘道器與 Modbus 現場總線雙軌審計管理。"""
    pass


@edge_group.command(name="scan")
@click.option("-b", "--baseline", required=True, type=click.Path(exists=True), help="黃金標準 (UCI 或 JSON)")
@click.option("-c", "--current", type=click.Path(exists=True), default=None, help="現場現況快照 (UCI 或 JSON)")
@click.option("--modbus-host", default="127.0.0.1", help="下向 PLC Modbus 主機 IP")
@click.option("--modbus-port", type=int, default=502, help="下向 PLC Modbus 通訊埠")
@click.option("--live", is_flag=True, default=False, help="即時自 OpenWrt UCI 與 Modbus PLC 採集")
def edge_scan(baseline: str, current: Optional[str], modbus_host: str, modbus_port: int, live: bool):
    """在 OpenWrt 閘道端執行雙軌稽核（網關防火牆 + 下向 Modbus 暫存器）。"""
    from otdrift.edge.agent import OpenWrtCarrierAgent

    agent = OpenWrtCarrierAgent(
        uci_firewall_path=current or "/etc/config/firewall",
        modbus_host=modbus_host,
        modbus_port=modbus_port,
    )

    console.print(f"[bold cyan]🔍 正在啟動 OpenWrt 工控閘道器邊緣雙軌審計...[/bold cyan]")
    report = agent.audit(
        baseline_file=baseline,
        current_uci_file=current if not live else None,
        live_modbus=live,
    )

    status_color = SEVERITY_LEVELS.get(report["max_severity"], 99)
    color_tag = "bold red" if report["max_severity"] == "CRITICAL" else ("bold green" if report["max_severity"] == "CLEAN" else "bold yellow")

    console.print(f"\n[bold white]審計評定：[/bold white] [{color_tag}]{report['max_severity']}[/{color_tag}]")
    console.print(f" • 飄移總數: [cyan]{report['total_drifts']}[/cyan]")
    console.print(f" • W-STED 距離 (D): [yellow]{report['w_sted_distance']:.2f}[/yellow]")
    console.print(f" • 歸一化飄移指數 (NDI): [magenta]{report['normalized_drift_index']:.4f}[/magenta]")
    console.print(f" • 整體風險分值: [red]{report['normalized_risk_score']}/100[/red]")

    if report["has_drift"]:
        table = Table(title="OpenWrt 網關與下向 PLC 飄移細項", header_style="bold blue")
        table.add_column("等級", justify="center", width=10)
        table.add_column("路徑 (Path)", justify="left", width=34)
        table.add_column("基準", justify="center", width=12)
        table.add_column("現況", justify="center", width=12)
        table.add_column("距離", justify="center", width=8)
        table.add_column("MITRE 技術", justify="center", width=14)

        for d in report["drifts"]:
            sev_col = "red" if d["severity"] == "CRITICAL" else "yellow"
            table.add_row(
                f"[{sev_col}]{d['severity']}[/]",
                d["path"],
                str(d["baseline_value"]),
                str(d["current_value"]),
                f"{d['drift_distance']:.2f}",
                d["mitre"]["technique_id"],
            )
        console.print(table)
    else:
        console.print("\n[bold green]✓ 網關與現場設備完全合規，未發現任何設定飄移！[/bold green]")


def main():
    cli()


if __name__ == "__main__":
    main()
