"""
HTML reporter generating an executive & engineering dashboard report.
"""

from __future__ import annotations

import html
from otdrift.core.comparator import DriftResult
from otdrift.reporters.base import BaseReporter


class HtmlReporter(BaseReporter):
    """Renders standalone responsive HTML security audit report."""

    def generate(self, result: DriftResult) -> str:
        b = result.baseline_metadata
        c = result.current_metadata

        sev_colors = {
            "CRITICAL": "#ef4444",
            "HIGH": "#f97316",
            "MEDIUM": "#eab308",
            "LOW": "#06b6d4",
            "INFO": "#64748b",
            "CLEAN": "#10b981",
        }

        max_color = sev_colors.get(result.max_severity, "#64748b")

        # Build rows for the drift table
        drift_rows = []
        for i, item in enumerate(result.items, 1):
            sev_color = sev_colors.get(item.severity, "#64748b")
            b_val = html.escape(str(item.baseline_value)) if item.baseline_value is not None else "<span class='text-muted'>--</span>"
            c_val = html.escape(str(item.current_value)) if item.current_value is not None else "<span class='text-muted'>--</span>"
            mitre_id = html.escape(item.mitre_technique_id)
            mitre_name = html.escape(item.mitre_technique_name)
            mitre_link = f"<a href='https://attack.mitre.org/techniques/{mitre_id}/' target='_blank' class='mitre-badge'>{mitre_id}</a>" if mitre_id.startswith("T") else mitre_id

            drift_rows.append(f"""
            <tr class="drift-row" data-severity="{item.severity}">
                <td style="text-align:center;"><span class="badge" style="background-color: {sev_color};">{item.severity}</span></td>
                <td><code>{html.escape(item.path)}</code></td>
                <td class="code-val">{b_val}</td>
                <td class="code-val highlight">{c_val}</td>
                <td>{mitre_link} <small class="text-muted d-block">{mitre_name}</small></td>
                <td><span class="badge bg-secondary">{html.escape(item.mitre_tactic)}</span></td>
                <td style="text-align:center;"><span class="risk-pill">{item.risk_score}</span></td>
            </tr>
            """)

        # Build cards for remediation playbook
        action_cards = []
        for i, item in enumerate(result.items, 1):
            sev_color = sev_colors.get(item.severity, "#64748b")
            remediation_steps = [f"<li><label><input type='checkbox'> {html.escape(s.strip().lstrip('1234567890. '))}</label></li>"
                                 for s in item.remediation.split("\n") if s.strip()]
            remediation_html = "".join(remediation_steps)

            action_cards.append(f"""
            <div class="card mb-3 border-left" style="border-left: 5px solid {sev_color};">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <div>
                        <span class="badge" style="background-color: {sev_color};">{item.severity}</span>
                        <strong class="ml-2 font-mono">{html.escape(item.path)}</strong>
                    </div>
                    <div>
                        <span class="badge bg-dark">MITRE: {html.escape(item.mitre_technique_id)}</span>
                        <span class="badge bg-info">Score: {item.risk_score}/100</span>
                    </div>
                </div>
                <div class="card-body">
                    <div class="threat-box">
                        <strong style="color: #dc2626;">⚠ 威脅衝擊分析：</strong>
                        <p class="mb-2 mt-1">{html.escape(item.threat_description)}</p>
                    </div>
                    <div class="remediation-box mt-3">
                        <strong style="color: #16a34a;">🛡 建議應變作為 (Remediation Actions)：</strong>
                        <ul class="task-list mt-2">
                            {remediation_html}
                        </ul>
                    </div>
                </div>
            </div>
            """)

        html_template = f"""<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OT/ICS 工控設定飄移與 MITRE ATT&CK 稽核報告</title>
    <style>
        :root {{
            --bg-color: #0f172a;
            --card-bg: #1e293b;
            --card-border: #334155;
            --text-color: #f1f5f9;
            --text-muted: #94a3b8;
            --accent: #38bdf8;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #06b6d4;
            --clean: #10b981;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            line-height: 1.6;
            padding: 24px;
        }}
        .container {{ max-width: 1300px; margin: 0 auto; }}
        .header {{
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            border: 1px solid var(--card-border);
            border-radius: 12px;
            padding: 28px;
            margin-bottom: 24px;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.4);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 20px;
        }}
        .header h1 {{ font-size: 24px; font-weight: 700; color: #fff; display: flex; align-items: center; gap: 10px; }}
        .header-sub {{ color: var(--text-muted); font-size: 13px; margin-top: 6px; }}
        .kpi-row {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .kpi-card {{
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 10px;
            padding: 20px;
            text-align: center;
            transition: transform 0.2s;
        }}
        .kpi-card:hover {{ transform: translateY(-2px); }}
        .kpi-value {{ font-size: 32px; font-weight: 800; margin: 8px 0; }}
        .kpi-label {{ font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-muted); }}

        .meta-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
            margin-bottom: 24px;
        }}
        @media (max-width: 768px) {{ .meta-grid {{ grid-template-columns: 1fr; }} }}
        .meta-card {{
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 10px;
            padding: 16px 20px;
            font-size: 13px;
        }}
        .meta-card strong {{ color: var(--accent); }}

        .section-title {{
            font-size: 18px;
            font-weight: 600;
            margin: 28px 0 14px 0;
            display: flex;
            align-items: center;
            justify-content: space-between;
            border-bottom: 1px solid var(--card-border);
            padding-bottom: 8px;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 10px;
            overflow: hidden;
            font-size: 13px;
        }}
        th, td {{
            padding: 12px 16px;
            text-align: left;
            border-bottom: 1px solid var(--card-border);
        }}
        th {{
            background: #111827;
            color: #94a3b8;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 11px;
            letter-spacing: 0.6px;
        }}
        tr:hover td {{ background: rgba(255, 255, 255, 0.02); }}
        code {{
            background: rgba(0, 0, 0, 0.3);
            color: #38bdf8;
            padding: 3px 6px;
            border-radius: 4px;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 12px;
        }}
        .code-val {{ font-family: monospace; font-size: 12px; }}
        .code-val.highlight {{ color: #fb923c; font-weight: bold; }}

        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 9999px;
            font-size: 11px;
            font-weight: 700;
            color: #fff;
            text-align: center;
        }}
        .bg-secondary {{ background-color: #475569; }}
        .bg-dark {{ background-color: #0f172a; border: 1px solid #334155; }}
        .bg-info {{ background-color: #0284c7; }}

        .mitre-badge {{
            color: #38bdf8;
            text-decoration: none;
            font-weight: bold;
        }}
        .mitre-badge:hover {{ text-decoration: underline; }}
        .risk-pill {{
            background: #334155;
            color: #f8fafc;
            padding: 2px 8px;
            border-radius: 6px;
            font-weight: bold;
            font-size: 12px;
        }}

        .card {{
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 8px;
            margin-bottom: 16px;
            overflow: hidden;
        }}
        .card-header {{
            background: rgba(0, 0, 0, 0.2);
            padding: 12px 18px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--card-border);
        }}
        .card-body {{ padding: 18px; }}
        .threat-box {{
            background: rgba(239, 68, 68, 0.08);
            border: 1px solid rgba(239, 68, 68, 0.2);
            padding: 12px 16px;
            border-radius: 6px;
            font-size: 13px;
        }}
        .remediation-box {{
            background: rgba(16, 185, 129, 0.08);
            border: 1px solid rgba(16, 185, 129, 0.2);
            padding: 12px 16px;
            border-radius: 6px;
            font-size: 13px;
        }}
        .task-list {{ list-style: none; }}
        .task-list li {{ margin-bottom: 6px; }}
        .task-list label {{ cursor: pointer; display: flex; align-items: center; gap: 8px; }}

        .filter-btn {{
            background: var(--card-bg);
            color: var(--text-muted);
            border: 1px solid var(--card-border);
            padding: 5px 12px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 12px;
            margin-left: 6px;
        }}
        .filter-btn.active {{
            background: var(--accent);
            color: #0f172a;
            font-weight: bold;
        }}

        .footer {{
            text-align: center;
            margin-top: 40px;
            color: var(--text-muted);
            font-size: 12px;
            border-top: 1px solid var(--card-border);
            padding-top: 20px;
        }}

        @media print {{
            body {{ background: #fff; color: #000; padding: 0; }}
            .header, .kpi-card, table, .card, .meta-card {{ background: #fff !important; color: #000 !important; border: 1px solid #ddd !important; }}
            .badge {{ color: #000 !important; border: 1px solid #000; }}
            .filter-btn {{ display: none; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <header class="header">
            <div>
                <h1>🛡 OT/ICS 設定飄移與 MITRE ATT&CK 資安稽核報告</h1>
                <div class="header-sub">
                    <span>比對時間：<strong>{result.compared_at}</strong></span> |
                    <span>稽核引擎：<strong>otdrift v1.0</strong></span> |
                    <span>底層載體：<strong>OpenPLC Runtime (Portainer Managed)</strong></span>
                </div>
            </div>
            <div>
                <span class="badge" style="font-size: 16px; padding: 10px 22px; background-color: {max_color};">
                    狀態評級：{result.max_severity}
                </span>
            </div>
        </header>

        <!-- KPI Metrics -->
        <div class="kpi-row">
            <div class="kpi-card">
                <div class="kpi-label">飄移參數總計</div>
                <div class="kpi-value" style="color: var(--accent);">{result.total_drifts}</div>
                <small class="text-muted">項受檢參數異動</small>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">嚴重風險 (CRITICAL)</div>
                <div class="kpi-value" style="color: var(--critical);">{result.severity_counts.get('CRITICAL', 0)}</div>
                <small class="text-muted">需立即緊急應變處置</small>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">高風險 (HIGH)</div>
                <div class="kpi-value" style="color: var(--high);">{result.severity_counts.get('HIGH', 0)}</div>
                <small class="text-muted">攻擊面顯著擴大</small>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">中/低風險 (MED/LOW)</div>
                <div class="kpi-value" style="color: var(--medium);">{result.severity_counts.get('MEDIUM', 0) + result.severity_counts.get('LOW', 0)}</div>
                <small class="text-muted">組態管理偏離基準</small>
            </div>
        </div>

        <!-- Meta Grid -->
        <div class="meta-grid">
            <div class="meta-card">
                <strong>📌 黃金標準 (Baseline):</strong> {html.escape(b.get('file_name', 'N/A'))}<br>
                <strong>路徑:</strong> {html.escape(b.get('absolute_path', 'N/A'))}<br>
                <strong>SHA-256:</strong> <code>{html.escape(b.get('sha256', 'N/A'))}</code>
            </div>
            <div class="meta-card">
                <strong>🔍 現場現況 (Current):</strong> {html.escape(c.get('file_name', 'N/A'))}<br>
                <strong>路徑:</strong> {html.escape(c.get('absolute_path', 'N/A'))}<br>
                <strong>SHA-256:</strong> <code>{html.escape(c.get('sha256', 'N/A'))}</code>
            </div>
        </div>

        <!-- Drift Details Table -->
        <div class="section-title">
            <span>📊 參數飄移矩陣與工控框架對應</span>
            <div>
                <button class="filter-btn active" onclick="filterDrifts('ALL')">全部 ({result.total_drifts})</button>
                <button class="filter-btn" onclick="filterDrifts('CRITICAL')">Critical</button>
                <button class="filter-btn" onclick="filterDrifts('HIGH')">High</button>
                <button class="filter-btn" onclick="filterDrifts('MEDIUM')">Medium</button>
            </div>
        </div>

        <table>
            <thead>
                <tr>
                    <th style="width: 100px; text-align: center;">嚴重度</th>
                    <th>參數路徑 (Parameter Path)</th>
                    <th>黃金標準 (Baseline)</th>
                    <th>現場現況 (Current)</th>
                    <th>MITRE ICS 技術</th>
                    <th>戰術 (Tactic)</th>
                    <th style="text-align: center;">風險值</th>
                </tr>
            </thead>
            <tbody>
                {''.join(drift_rows) if drift_rows else '<tr><td colspan="7" style="text-align:center; padding:30px; color:#10b981;">✓ 現況組態完全符合黃金標準，未檢驗出任何設定飄移！</td></tr>'}
            </tbody>
        </table>

        <!-- Incident & Remediation Playbook -->
        <div class="section-title">
            <span>🚨 處置因應指南與事件調查指引 (Incident Playbook)</span>
        </div>

        <div>
            {''.join(action_cards) if action_cards else '<p style="color:#10b981;">無安全異常需要處置。</p>'}
        </div>

        <!-- Footer -->
        <div class="footer">
            <p>本報告由 <code>otdrift</code> 工控組態自動化飄移比對引擎自動生成 | 適用於 IEC 62443 / MITRE ATT&CK for ICS 規範</p>
        </div>
    </div>

    <script>
        function filterDrifts(level) {{
            document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
            document.querySelectorAll('.drift-row').forEach(row => {{
                if (level === 'ALL' || row.getAttribute('data-severity') === level) {{
                    row.style.display = '';
                }} else {{
                    row.style.display = 'none';
                }}
            }});
        }}
    </script>
</body>
</html>
"""
        return html_template
