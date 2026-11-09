"""
Unit tests for the Semantic Drift Distance Calculator.
"""

import pytest
from otdrift.core.comparator import ChangeType, DriftItem
from otdrift.core.distance import DriftDistanceCalculator, LayerWeightRegistry


def test_layer_weight_registry():
    assert LayerWeightRegistry.get_weight("safety_interlocks.safety_door_bypass") == 3.0
    assert LayerWeightRegistry.get_weight("process_machining.spindle_max_rpm") == 2.5
    assert LayerWeightRegistry.get_weight("tool_offset.tool_01_wear_compensation_mm") == 2.5
    assert LayerWeightRegistry.get_weight("comm_policy.modbus_tcp.auth_required") == 2.0
    assert LayerWeightRegistry.get_weight("unknown_layer.some_param") == 1.0


def test_distance_calculator_numeric():
    calc = DriftDistanceCalculator()
    # Identical
    assert calc.calculate_delta(10000, 10000) == 0.0

    # 50% relative deviation
    delta = calc.calculate_delta(10000, 15000)
    assert abs(delta - 0.5) < 1e-4

    # Capped at 1.0 (200% deviation)
    assert calc.calculate_delta(1000, 3000) == 1.0


def test_distance_calculator_boolean():
    calc = DriftDistanceCalculator()
    assert calc.calculate_delta(True, False) == 1.0
    assert calc.calculate_delta(False, False) == 0.0


def test_distance_item_and_quantification():
    calc = DriftDistanceCalculator()
    item1 = DriftItem(
        path="process_machining.spindle_max_rpm",
        change_type=ChangeType.MODIFIED,
        baseline_value=10000,
        current_value=15000,
    )
    # Weight 2.5 * Delta 0.5 = 1.25
    item1_dist = calc.calculate_item_distance(item1)
    assert abs(item1_dist - 1.25) < 1e-4

    item2 = DriftItem(
        path="safety_interlocks.safety_door_bypass",
        change_type=ChangeType.MODIFIED,
        baseline_value=False,
        current_value=True,
    )
    # Weight 3.0 * Delta 1.0 = 3.0
    item2_dist = calc.calculate_item_distance(item2)
    assert abs(item2_dist - 3.0) < 1e-4

    summary = calc.quantify_drifts([item1, item2])
    assert summary["drift_count"] == 2
    assert abs(summary["total_drift_distance"] - 4.25) < 1e-4
    assert abs(summary["w_sted_distance"] - 4.25) < 1e-4
    assert 0.0 < summary["normalized_drift_index"] <= 1.0
    assert summary["normalized_risk_score"] > 80
