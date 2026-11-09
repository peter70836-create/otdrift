"""
Unit tests for OpenWrtCarrierAgent and ModbusTCPProbe.
"""

import pytest
from pathlib import Path
from otdrift.edge.agent import OpenWrtCarrierAgent


def test_openwrt_agent_uci_audit():
    agent = OpenWrtCarrierAgent(uci_firewall_path="configs/openwrt/tampered_firewall.uci")
    report = agent.audit(
        baseline_file="configs/openwrt/baseline_firewall.uci",
        current_uci_file="configs/openwrt/tampered_firewall.uci",
    )

    assert report["has_drift"] is True
    assert report["total_drifts"] == 2
    assert report["max_severity"] == "CRITICAL"
    assert report["w_sted_distance"] > 0
    assert 0.0 < report["normalized_drift_index"] <= 1.0
    assert report["normalized_risk_score"] >= 80


def test_openwrt_agent_clean_audit():
    agent = OpenWrtCarrierAgent(uci_firewall_path="configs/openwrt/baseline_firewall.uci")
    report = agent.audit(
        baseline_file="configs/openwrt/baseline_firewall.uci",
        current_uci_file="configs/openwrt/baseline_firewall.uci",
    )

    assert report["has_drift"] is False
    assert report["total_drifts"] == 0
    assert report["max_severity"] == "CLEAN"
    assert report["w_sted_distance"] == 0.0
    assert report["normalized_drift_index"] == 0.0
    assert report["normalized_risk_score"] == 0
