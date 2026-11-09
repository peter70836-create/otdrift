"""
Markdown reporter producing audit documents suitable for Wiki, Git, and archival.
"""

from __future__ import annotations

from otdrift.core.comparator import DriftResult
from otdrift.reporters.base import BaseReporter


class MarkdownReporter(BaseReporter):
    """Renders comprehensive Markdown audit report."""

    def generate(self, result: DriftResult) -> str:
        lines: list[str] = []

        lines.append("# OT/ICS 工控設定飄移與 MITRE ATT&CK 安全稽核報告\n")
        lines.append(f"> **產出時間**：`{result.compared_at}`  ")
        lines.append(f"> **整體安全等級**：**`{result.max_severity}`**  ")
        lines.append(f"> **飄移參數總數**：`{result.total_drifts}` 項\n")

        lines.append("## 1. 檔案與環境驗證元資料\n")
        lines.append("| 項目 | 檔案名稱 | SHA-256 Checksum | 格式 |")
        lines.append("| :--- | :--- | :--- | :--- |")
        b = result.baseline_metadata
        c = result.current_metadata
        lines.append(f"| **黃金標準 (Baseline)** | `{b.get('file_name', 'N/A')}` | `{b.get('sha256', 'N/A')}` | {b.get('format', 'N/A')} |")
        lines.append(f"| **現場現況 (Current)** | `{c.get('file_name', 'N/A')}` | `{c.get('sha256', 'N/A')}` | {c.get('format', 'N/A')} |\n")

        lines.append("## 2. 飄移嚴重度統計\n")
        lines.append("| 嚴重度 (Severity) | 數量 | 說明 |")
        lines.append("| :--- | :---: | :--- |")
        lines.append(f"| 🔴 **CRITICAL** | {result.severity_counts.get('CRITICAL', 0)} | 核心安全機制、身分驗證或韌體/程式邏輯遭更動 |")
        lines.append(f"| 🟠 **HIGH** | {result.severity_counts.get('HIGH', 0)} | 遠端管理埠、通訊白名單或作業狀態偏離基準 |")
        lines.append(f"| 🟡 **MEDIUM** | {result.severity_counts.get('MEDIUM', 0)} | 次要安全原則或維護配置變更 |")
        lines.append(f"| 🔵 **LOW** | {result.severity_counts.get('LOW', 0)} | 一般運作設定微調 |")
        lines.append(f"| ⚪ **INFO** | {result.severity_counts.get('INFO', 0)} | 資訊型微小差異 |\n")

        if not result.has_drift:
            lines.append("## 3. 比對結果\n")
            lines.append("✅ **系統狀態良好**：未偵測到任何設定飄移，目前運作參數與黃金標準完全相符。\n")
            return "\n".join(lines)

        lines.append("## 3. 設定飄移清單與 MITRE ATT&CK for ICS 威脅對應\n")
        lines.append("| 嚴重度 | 參數路徑 | 基準值 (Baseline) | 現況值 (Current) | MITRE ICS 技術 | 戰術分類 (Tactic) |")
        lines.append("| :---: | :--- | :---: | :---: | :---: | :--- |")

        for item in result.items:
            b_val = f"`{item.baseline_value}`" if item.baseline_value is not None else "*無*"
            c_val = f"`{item.current_value}`" if item.current_value is not None else "*無*"
            mitre_link = f"[{item.mitre_technique_id}](https://attack.mitre.org/techniques/{item.mitre_technique_id}/)" if item.mitre_technique_id.startswith("T") else item.mitre_technique_id
            lines.append(
                f"| **{item.severity}** | `{item.path}` | {b_val} | {c_val} | {mitre_link} ({item.mitre_technique_name}) | {item.mitre_tactic} |"
            )

        lines.append("\n## 4. 深度資安衝擊與應變處置手冊 (Incident Playbook)\n")
        for i, item in enumerate(result.items, 1):
            lines.append(f"### {i}. [{item.severity}] `{item.path}`")
            lines.append(f"- **變更類型**：`{item.change_type.value}`")
            lines.append(f"- **風險評分**：`{item.risk_score} / 100`")
            lines.append(f"- **對應 MITRE 框架**：{item.mitre_technique_id} - *{item.mitre_technique_name}* ({item.mitre_tactic})")
            lines.append(f"- **威脅場景說明**：\n  > {item.threat_description}\n")
            lines.append("- **建議處置作為 (Remediation Actions)**：")
            for step in item.remediation.split("\n"):
                if step.strip():
                    lines.append(f"  - [ ] {step.strip()}")
            lines.append("")

        lines.append("---\n*本報告由 `otdrift` 工控自動化飄移比對引擎自動產出，資料具不可否認性雜湊溯源保護。*")
        return "\n".join(lines)
