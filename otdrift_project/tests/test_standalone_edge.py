"""
Unit tests for the self-contained OpenWrt Native Edge Engine (openwrt/otdrift_edge.py).
Verifies zero-dependency execution, UCI parsing, W-STED distance, and threat evaluation.
"""

import sys
from pathlib import Path
import pytest

# Add openwrt directory to sys.path for direct import
sys.path.insert(0, str(Path(__file__).parent.parent / "openwrt"))
from otdrift_edge import OpenWrtEdgeEngine, UCIParser, native_compare_dicts, EdgeRuleEngine


def test_standalone_edge_uci_drift():
    engine = OpenWrtEdgeEngine()
    rep = engine.audit(
        baseline_path="configs/openwrt/baseline_firewall.uci",
        current_path="configs/openwrt/tampered_firewall.uci",
    )

    assert rep["has_drift"] is True
    assert rep["total_drifts"] == 2
    assert rep["max_severity"] == "CRITICAL"
    assert abs(rep["w_sted_distance"] - 4.0) < 1e-4
    assert 0.7 < rep["normalized_drift_index"] < 0.9
    assert rep["normalized_risk_score"] >= 80

    paths = [d["path"] for d in rep["drifts"]]
    assert "firewall.rules.Allow-Modbus-TCP-Internal.src" in paths
    assert "firewall.defaults.defaults_0.forward" in paths


def test_standalone_edge_clean():
    engine = OpenWrtEdgeEngine()
    rep = engine.audit(
        baseline_path="configs/openwrt/baseline_firewall.uci",
        current_path="configs/openwrt/baseline_firewall.uci",
    )

    assert rep["has_drift"] is False
    assert rep["total_drifts"] == 0
    assert rep["max_severity"] == "CLEAN"
    assert rep["w_sted_distance"] == 0.0
    assert rep["normalized_drift_index"] == 0.0
    assert rep["normalized_risk_score"] == 0


def test_standalone_edge_process_register_drift(tmp_path):
    base_data = {
        "process_registers": {"pump_cutoff_pressure_psi": 85}
    }
    tampered_data = {
        "process_registers": {"pump_cutoff_pressure_psi": 140}
    }
    b_file = tmp_path / "base.json"
    t_file = tmp_path / "tamp.json"
    import json
    b_file.write_text(json.dumps(base_data), encoding="utf-8")
    t_file.write_text(json.dumps(tampered_data), encoding="utf-8")

    engine = OpenWrtEdgeEngine()
    rep = engine.audit(baseline_path=b_file, current_path=t_file)

    assert rep["has_drift"] is True
    assert rep["total_drifts"] == 1
    assert rep["max_severity"] == "CRITICAL"
    drift = rep["drifts"][0]
    assert drift["path"] == "process_registers.pump_cutoff_pressure_psi"
    assert drift["baseline_value"] == 85
    assert drift["current_value"] == 140
    assert drift["mitre"]["technique_id"] == "T0839"
