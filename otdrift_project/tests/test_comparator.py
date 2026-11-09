"""
Unit tests for configuration comparator and deep diff logic.
"""

from otdrift.core.comparator import compare_configs, ChangeType


def test_identical_configs_no_drift():
    baseline = {"network": {"ip": "192.168.1.10", "port": 502}, "enabled": True}
    current = {"network": {"ip": "192.168.1.10", "port": 502}, "enabled": True}

    res = compare_configs(baseline, current)
    assert not res.has_drift
    assert res.total_drifts == 0
    assert res.max_severity == "CLEAN"


def test_modified_value_detected():
    baseline = {"protocols": {"modbus_tcp": {"port": 502}}}
    current = {"protocols": {"modbus_tcp": {"port": 5020}}}

    res = compare_configs(baseline, current)
    assert res.has_drift
    assert res.total_drifts == 1
    item = res.items[0]
    assert item.path == "protocols.modbus_tcp.port"
    assert item.change_type == ChangeType.MODIFIED
    assert item.baseline_value == 502
    assert item.current_value == 5020


def test_added_and_removed_parameters():
    baseline = {"auth_required": True, "old_param": "deprecated"}
    current = {"auth_required": True, "new_param": "injected"}

    res = compare_configs(baseline, current)
    assert res.has_drift
    paths = {item.path: item.change_type for item in res.items}
    assert paths["new_param"] == ChangeType.ADDED
    assert paths["old_param"] == ChangeType.REMOVED


def test_list_items_drift():
    baseline = {"whitelist": ["10.0.0.1", "10.0.0.2"]}
    current = {"whitelist": ["10.0.0.1", "10.0.0.2", "0.0.0.0/0"]}

    res = compare_configs(baseline, current)
    assert res.has_drift
    assert any("0.0.0.0/0" in str(item.current_value) for item in res.items)
