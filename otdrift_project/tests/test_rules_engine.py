"""
Unit tests for security rule engine and MITRE ATT&CK for ICS evaluation.
"""

from pathlib import Path
from otdrift.core.comparator import compare_configs
from otdrift.rules.engine import SecurityRuleEngine
from otdrift.rules.mitre_ics import get_mitre_technique


def test_modbus_auth_disabled_rule_trigger():
    baseline = {"protocols": {"modbus_tcp": {"auth_required": True}}}
    current = {"protocols": {"modbus_tcp": {"auth_required": False}}}

    diff_res = compare_configs(baseline, current)
    engine = SecurityRuleEngine()
    evaluated = engine.evaluate(diff_res)

    assert evaluated.has_drift
    assert evaluated.max_severity == "CRITICAL"
    item = evaluated.items[0]
    assert item.severity == "CRITICAL"
    assert item.mitre_technique_id == "T0812"
    assert item.risk_score >= 90
    assert "身分驗證" in item.threat_description


def test_remote_programming_enabled_rule_trigger():
    baseline = {"management": {"allow_remote_programming": False}}
    current = {"management": {"allow_remote_programming": True}}

    diff_res = compare_configs(baseline, current)
    engine = SecurityRuleEngine()
    evaluated = engine.evaluate(diff_res)

    assert evaluated.max_severity == "CRITICAL"
    item = evaluated.items[0]
    assert item.mitre_technique_id == "T0843"
    assert "程式下載" in item.threat_description or "階梯圖" in item.threat_description


def test_custom_rules_loading(tmp_path: Path):
    custom_yaml = """
    rules:
      - id: "TEST-001"
        path: "custom.security_flag"
        name: "測試自訂規則"
        severity: "HIGH"
        risk_score: 88
        mitre_technique_id: "T0855"
        threat_description: "自訂威脅觸發"
        remediation: "處置方式步驟"
    """
    rule_file = tmp_path / "custom_rules.yaml"
    rule_file.write_text(custom_yaml, encoding="utf-8")

    engine = SecurityRuleEngine(custom_rules_path=rule_file)
    assert any(r.rule_id == "TEST-001" for r in engine.rules)

    diff_res = compare_configs(
        {"custom": {"security_flag": 1}},
        {"custom": {"security_flag": 0}},
    )
    evaluated = engine.evaluate(diff_res)
    assert evaluated.items[0].severity == "HIGH"
    assert evaluated.items[0].risk_score == 88


def test_mitre_ics_knowledge_base():
    tech = get_mitre_technique("T0812")
    assert tech is not None
    assert tech.name == "Default Credentials"
    assert "attack.mitre.org" in tech.url

    tech_dos = get_mitre_technique("T0855")
    assert tech_dos is not None
    assert tech_dos.name == "Unauthorized Command Message"
