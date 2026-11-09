"""
Security rule evaluation engine for OT/ICS drift analysis.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml

from otdrift.core.comparator import DriftItem, DriftResult
from otdrift.core.distance import DriftDistanceCalculator
from otdrift.rules.default_rules import SecurityRule, get_default_rules
from otdrift.rules.mitre_ics import get_mitre_technique


class SecurityRuleEngine:
    """Evaluates configuration drifts against security policies and MITRE ATT&CK for ICS."""

    def __init__(self, custom_rules_path: Optional[str | Path] = None):
        self.rules: List[SecurityRule] = get_default_rules()
        if custom_rules_path:
            self.load_custom_rules(custom_rules_path)

    def load_custom_rules(self, rules_path: str | Path) -> None:
        """Load additional user-defined rules from a YAML file."""
        path = Path(rules_path)
        if not path.exists():
            return

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except Exception:
            return

        if not isinstance(data, list):
            data = data.get("rules", []) if isinstance(data, dict) else []

        for item in data:
            if not isinstance(item, dict):
                continue
            rule = SecurityRule(
                rule_id=item.get("id", f"CUSTOM-{len(self.rules)+1:03d}"),
                path_pattern=item.get("path", ""),
                name=item.get("name", "自訂安全規則"),
                severity=item.get("severity", "MEDIUM").upper(),
                risk_score=int(item.get("risk_score", 50)),
                mitre_technique_id=item.get("mitre_technique_id", "T0839"),
                threat_template=item.get("threat_description", "參數偏離黃金標準"),
                remediation_template=item.get("remediation", "審查並還原該參數設定"),
            )
            self.rules.append(rule)

    def evaluate_item(self, item: DriftItem) -> None:
        """Evaluate a single drift item and annotate it in-place."""
        matched_rule: Optional[SecurityRule] = None

        for rule in self.rules:
            if rule.matches(item.path, item.baseline_value, item.current_value, item.change_type.value):
                matched_rule = rule
                break

        if matched_rule:
            item.severity = matched_rule.severity
            item.risk_score = matched_rule.risk_score
            item.mitre_technique_id = matched_rule.mitre_technique_id

            # Format templates safely
            fmt_kwargs = {
                "baseline_val": item.baseline_value,
                "current_val": item.current_value,
                "path": item.path,
            }
            try:
                item.threat_description = matched_rule.threat_template.format(**fmt_kwargs)
            except Exception:
                item.threat_description = matched_rule.threat_template

            try:
                item.remediation = matched_rule.remediation_template.format(**fmt_kwargs)
            except Exception:
                item.remediation = matched_rule.remediation_template

            # Enrich with MITRE ATT&CK for ICS knowledge base
            mitre_info = get_mitre_technique(item.mitre_technique_id)
            if mitre_info:
                item.mitre_technique_name = mitre_info.name
                item.mitre_tactic = mitre_info.tactic
            else:
                item.mitre_technique_name = "Custom Technique"
                item.mitre_tactic = "General ICS Modification"
        else:
            # Default unmapped fallback
            item.severity = "LOW"
            item.risk_score = 20
            item.mitre_technique_id = "T0839"
            mitre_info = get_mitre_technique("T0839")
            if mitre_info:
                item.mitre_technique_name = mitre_info.name
                item.mitre_tactic = mitre_info.tactic
            item.threat_description = f"參數 '{item.path}' 與黃金標準設定不一致。"
            item.remediation = "審核此項變更是否經過工控變更管理程序 (MOC)，若未授權請予原樣復原。"

    def evaluate(self, drift_result: DriftResult) -> DriftResult:
        """Evaluate all drift items in a DriftResult and quantify drift distance."""
        dist_calc = DriftDistanceCalculator()

        for item in drift_result.items:
            self.evaluate_item(item)
            item.drift_distance = dist_calc.calculate_item_distance(item)

        # Quantify aggregate semantic distance and normalized risk score
        quant_summary = dist_calc.quantify_drifts(drift_result.items)
        drift_result.total_drift_distance = quant_summary["total_drift_distance"]
        drift_result.w_sted_distance = quant_summary["w_sted_distance"]
        drift_result.normalized_drift_index = quant_summary["normalized_drift_index"]
        drift_result.normalized_risk_score = quant_summary["normalized_risk_score"]

        # Sort: CRITICAL -> HIGH -> MEDIUM -> LOW -> INFO, then by risk_score desc
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        drift_result.items.sort(
            key=lambda x: (severity_order.get(x.severity, 5), -x.risk_score, x.path)
        )
        return drift_result
