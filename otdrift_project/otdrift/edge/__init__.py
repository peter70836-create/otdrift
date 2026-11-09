"""
OpenWrt Edge Gateway Integration for otdrift.
Provides UCI configuration parsing, edge Modbus telemetry, and dual-track drift auditing.
"""

from otdrift.edge.uci_parser import UCIParser, parse_uci, dump_uci

__all__ = ["UCIParser", "parse_uci", "dump_uci"]
