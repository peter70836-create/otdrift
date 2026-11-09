"""
Console reporter using rich for colorized, human-readable terminal output.
"""

from __future__ import annotations

import io
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from otdrift.core.comparator import DriftResult
from otdrift.reporters.base import BaseReporter


SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "bold color(208)",  # Orange
    "MEDIUM": "bold yellow",
    "LOW": "bold cyan",
    "INFO": "dim white",
    "CLEAN": "bold green",
}


class ConsoleReporter(BaseReporter):
    """Renders formatted drift report directly to console or string."""

    def __init__(self, console: Console | None = None):
        self.console = console or Console()

    def generate(self, result: DriftResult) -> str:
        """Render report to string using in-memory string console."""
        string_io = io.StringIO()
        mem_console = Console(file=string_io, force_terminal=True, width=110)
        self._render_to_console(result, mem_console)
        return string_io.getvalue()

    def print_to_stdout(self, result: DriftResult) -> None:
        """Render directly to standard output console."""
        self._render_to_console(result, self.console)

    def _render_to_console(self, result: DriftResult, c: Console) -> None:
        # Header Panel
        status_color = SEVERITY_COLORS.get(result.max_severity, "white")
        header_text = Text()
        header_text.append("OT/ICS Configuration Drift & Security Audit\n", style="bold white")
        header_text.append(f"Maximum Severity: {result.max_severity}  |  ", style=status_color)
        header_text.append(f"Total Drifts: {result.total_drifts}  |  ", style="bold cyan")
        header_text.append(f"Drift Distance: {result.total_drift_distance:.2f}  |  ", style="bold yellow")
        header_text.append(f"Risk Score: {result.normalized_risk_score}/100\n", style="bold red" if result.normalized_risk_score >= 70 else "bold yellow")
        header_text.append(f"Audited: {result.compared_at}\n", style="dim white")
        header_text.append(f"Baseline: {result.baseline_metadata.get('file_name', 'N/A')}\n", style="dim")
        header_text.append(f"Current : {result.current_metadata.get('file_name', 'N/A')}", style="dim")

        c.print()
        c.print(Panel(header_text, title="[bold cyan]otdrift Audit Report[/bold cyan]", border_style=status_color))

        if not result.has_drift:
            c.print("\n[bold green]✓ 完美吻合：目前組態完全符合黃金標準 (Baseline)，未偵測到任何設定飄移！[/bold green]\n")
            return

        # Summary Table
        summary_table = Table(title="飄移統計摘要 (Drift Summary by Severity)", show_header=True, header_style="bold magenta")
        summary_table.add_column("等級 (Severity)", justify="center")
        summary_table.add_column("數量 (Count)", justify="center")
        summary_table.add_column("工控安全影響評估 (ICS Security Impact)", justify="left")

        impact_desc = {
            "CRITICAL": "嚴重威脅：核心安全互鎖、身分驗證或控制程式遭修改，實體製程可能失控",
            "HIGH": "高風險：遠端管理埠、通訊白名單或作業模式偏離安全基準",
            "MEDIUM": "中風險：憑證複雜度、維護協定配置等次要安全參數漂移",
            "LOW": "低風險：一般運作設定調整，未直接影響安全防線",
            "INFO": "資訊：非安全關鍵之資訊變更",
        }

        for sev, count in result.severity_counts.items():
            if count > 0:
                summary_table.add_row(
                    f"[{SEVERITY_COLORS.get(sev, 'white')}]{sev}[/]",
                    str(count),
                    impact_desc.get(sev, ""),
                )
        c.print(summary_table)
        c.print()

        # Detailed Drift Items Table
        detail_table = Table(title="設定飄移細項與 MITRE ATT&CK for ICS 對應", show_header=True, header_style="bold blue")
        detail_table.add_column("嚴重度", justify="center", width=10)
        detail_table.add_column("參數路徑 (Parameter Path)", justify="left", width=32)
        detail_table.add_column("黃金標準 (Baseline)", justify="center", width=14)
        detail_table.add_column("現況設定 (Current)", justify="center", width=14)
        detail_table.add_column("語意距離 (D)", justify="center", width=12)
        detail_table.add_column("MITRE ICS 技術", justify="center", width=22)

        for item in result.items:
            color = SEVERITY_COLORS.get(item.severity, "white")
            b_val = str(item.baseline_value) if item.baseline_value is not None else "[dim]--[/dim]"
            c_val = str(item.current_value) if item.current_value is not None else "[dim]--[/dim]"
            mitre_str = f"{item.mitre_technique_id}\n[dim]{item.mitre_technique_name}[/dim]"

            detail_table.add_row(
                f"[{color}]{item.severity}[/{color}]",
                item.path,
                b_val,
                c_val,
                f"[yellow]{item.drift_distance:.2f}[/yellow]",
                mitre_str,
            )
        c.print(detail_table)
        c.print()

        # Detailed Remediation Action Items for Critical & High
        c.print("[bold red]🚨 高危險飄移資安處置建議 (Remediation & Incident Response):[/bold red]")
        for i, item in enumerate(result.items, 1):
            if item.severity in ["CRITICAL", "HIGH"]:
                color = SEVERITY_COLORS.get(item.severity, "white")
                c.print(f"[{color}]▶ [{item.severity}] {item.path}[/{color}] (MITRE: {item.mitre_technique_id} - {item.mitre_technique_name})")
                c.print(f"   [bold yellow]威脅說明：[/bold yellow]{item.threat_description}")
                rem_lines = item.remediation.split("\n")
                c.print("   [bold green]建議處置：[/bold green]")
                for line in rem_lines:
                    c.print(f"      {line}")
                c.print()
