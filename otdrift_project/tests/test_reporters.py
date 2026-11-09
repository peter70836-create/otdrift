"""
Unit tests for reporters (JSON, Markdown, HTML, Console).
"""

import json
from pathlib import Path
from otdrift.core.comparator import compare_configs
from otdrift.rules.engine import SecurityRuleEngine
from otdrift.reporters.json_reporter import JsonReporter
from otdrift.reporters.markdown_reporter import MarkdownReporter
from otdrift.reporters.html_reporter import HtmlReporter
from otdrift.reporters.console_reporter import ConsoleReporter


def get_sample_result():
    baseline = {"protocols": {"modbus_tcp": {"auth_required": True, "port": 502}}}
    current = {"protocols": {"modbus_tcp": {"auth_required": False, "port": 5020}}}
    b_meta = {"file_name": "base.json", "sha256": "abc12345", "format": "JSON"}
    c_meta = {"file_name": "curr.json", "sha256": "def67890", "format": "JSON"}

    diff = compare_configs(baseline, current, b_meta, c_meta)
    engine = SecurityRuleEngine()
    return engine.evaluate(diff)


def test_json_reporter():
    res = get_sample_result()
    reporter = JsonReporter()
    output_str = reporter.generate(res)

    data = json.loads(output_str)
    assert data["generator"] == "otdrift"
    assert data["audit_summary"]["has_drift"] is True
    assert data["audit_summary"]["max_severity"] == "CRITICAL"
    assert len(data["drifts"]) == 2


def test_markdown_reporter():
    res = get_sample_result()
    reporter = MarkdownReporter()
    md = reporter.generate(res)

    assert "# OT/ICS" in md
    assert "CRITICAL" in md
    assert "T0812" in md
    assert "Incident Playbook" in md


def test_html_reporter():
    res = get_sample_result()
    reporter = HtmlReporter()
    html_text = reporter.generate(res)

    assert "<!DOCTYPE html>" in html_text
    assert "CRITICAL" in html_text
    assert "protocols.modbus_tcp.auth_required" in html_text
    assert "filterDrifts" in html_text


def test_console_reporter():
    res = get_sample_result()
    reporter = ConsoleReporter()
    text = reporter.generate(res)
    assert len(text) > 0
