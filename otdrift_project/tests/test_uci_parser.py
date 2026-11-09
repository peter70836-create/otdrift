"""
Unit tests for OpenWrt UCI Parser and Converter.
"""

import pytest
from otdrift.edge.uci_parser import UCIParser, parse_uci, dump_uci, UCIParseError
from otdrift.core.comparator import compare_configs


SAMPLE_FIREWALL_UCI = """
package firewall

config defaults
	option syn_flood '1'
	option input 'REJECT'
	option output 'ACCEPT'
	option forward 'REJECT'

config zone
	option name 'lan'
	list network 'lan'
	option input 'ACCEPT'
	option output 'ACCEPT'
	option forward 'ACCEPT'

config zone
	option name 'wan'
	list network 'wan'
	list network 'wan6'
	option input 'REJECT'
	option output 'ACCEPT'
	option forward 'REJECT'
	option masq '1'
	option mtu_fix '1'

config rule
	option name 'Allow-Modbus-TCP'
	option src 'lan'
	option dest_port '502'
	option proto 'tcp'
	option target 'ACCEPT'
"""

SAMPLE_TAMPERED_FIREWALL_UCI = """
package firewall

config defaults
	option syn_flood '1'
	option input 'REJECT'
	option output 'ACCEPT'
	option forward 'REJECT'

config zone
	option name 'lan'
	list network 'lan'
	option input 'ACCEPT'
	option output 'ACCEPT'
	option forward 'ACCEPT'

config zone
	option name 'wan'
	list network 'wan'
	list network 'wan6'
	option input 'REJECT'
	option output 'ACCEPT'
	option forward 'REJECT'
	option masq '1'
	option mtu_fix '1'

config rule
	option name 'Allow-Modbus-TCP'
	option src 'wan'
	option dest_port '502'
	option proto 'tcp'
	option target 'ACCEPT'
"""


def test_uci_parser_basic():
    parser = UCIParser(package_name="firewall")
    sections = parser.parse_string(SAMPLE_FIREWALL_UCI)
    assert len(sections) == 4

    data = parser.to_dict()
    assert "firewall" in data
    assert "rules" in data["firewall"]
    assert "Allow-Modbus-TCP" in data["firewall"]["rules"]

    modbus_rule = data["firewall"]["rules"]["Allow-Modbus-TCP"]
    assert modbus_rule["src"] == "lan"
    assert modbus_rule["dest_port"] == 502
    assert modbus_rule["proto"] == "tcp"
    assert modbus_rule["target"] == "ACCEPT"


def test_uci_diff_detection():
    base_dict = parse_uci(SAMPLE_FIREWALL_UCI, package_name="openwrt_gateway")
    tampered_dict = parse_uci(SAMPLE_TAMPERED_FIREWALL_UCI, package_name="openwrt_gateway")

    res = compare_configs(base_dict, tampered_dict)
    assert res.has_drift
    assert res.total_drifts == 1
    drift = res.items[0]
    assert drift.path == "firewall.rules.Allow-Modbus-TCP.src"
    assert drift.baseline_value == "lan"
    assert drift.current_value == "wan"


def test_uci_dump_roundtrip():
    parsed = parse_uci(SAMPLE_FIREWALL_UCI, package_name="firewall")
    dumped = dump_uci(parsed, package_name="firewall")
    assert "config rule 'Allow-Modbus-TCP'" in dumped
    assert "option dest_port '502'" in dumped
    assert "option src 'lan'" in dumped
