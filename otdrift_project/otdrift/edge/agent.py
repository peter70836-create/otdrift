"""
OpenWrt Edge Carrier Agent for otdrift.
Runs on OpenWrt industrial routers / gateways to perform dual-track drift auditing:
1. Local Gateway Audit: UCI Firewall & Network integrity (/etc/config/firewall)
2. Southbound Bus Audit: Modbus TCP (Port 502) real-time register extraction
Uses standard Python 3 library only (no mandatory third-party pip dependencies required on OpenWrt).
"""

from __future__ import annotations

import argparse
import json
import math
import os
import socket
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from otdrift.edge.uci_parser import parse_uci


class ModbusTCPProbe:
    """Lightweight raw socket Modbus TCP client requiring zero external dependencies."""

    def __init__(self, host: str = "127.0.0.1", port: int = 502, timeout: float = 3.0):
        self.host = host
        self.port = port
        self.timeout = timeout

    def read_holding_registers(self, start_addr: int = 0, count: int = 1, unit_id: int = 1) -> List[int]:
        """Send Modbus FC 03 (Read Holding Registers) via raw socket."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            s.connect((self.host, self.port))
            # Modbus TCP Header: Transaction ID (0x0001), Protocol ID (0x0000), Length (0x0006), Unit ID (unit_id)
            # PDU: Function Code (0x03), Starting Address (2 bytes), Quantity of Registers (2 bytes)
            req = bytearray([
                0x00, 0x01,  # Transaction ID
                0x00, 0x00,  # Protocol ID
                0x00, 0x06,  # Length
                unit_id,     # Unit ID
                0x03,        # FC 03
                (start_addr >> 8) & 0xFF, start_addr & 0xFF,
                (count >> 8) & 0xFF, count & 0xFF,
            ])
            s.sendall(req)
            resp = s.recv(1024)
            if len(resp) < 9:
                raise ConnectionError(f"Modbus response too short ({len(resp)} bytes)")

            # Check for Modbus exception (FC | 0x80)
            fc = resp[7]
            if fc & 0x80:
                exc_code = resp[8] if len(resp) > 8 else 0
                raise RuntimeError(f"Modbus Exception from PLC: FC 0x{fc:02X}, Code {exc_code}")

            byte_count = resp[8]
            data_bytes = resp[9: 9 + byte_count]
            registers = []
            for i in range(0, len(data_bytes), 2):
                if i + 1 < len(data_bytes):
                    val = (data_bytes[i] << 8) | data_bytes[i + 1]
                    registers.append(val)
            return registers
        finally:
            s.close()


class OpenWrtCarrierAgent:
    """
    OpenWrt Edge Carrier Daemon & Auditor.
    Performs dual-track auditing across gateway firewall policy and southbound Modbus PLC state.
    """

    def __init__(
        self,
        uci_firewall_path: str = "/etc/config/firewall",
        modbus_host: str = "127.0.0.1",
        modbus_port: int = 502,
        register_map: Optional[Dict[str, int]] = None,
    ):
        self.uci_firewall_path = Path(uci_firewall_path)
        self.modbus_host = modbus_host
        self.modbus_port = modbus_port
        # Default register 0 is pump_cutoff_pressure_psi
        self.register_map = register_map or {"pump_cutoff_pressure_psi": 0}

    def collect_live_state(self) -> Dict[str, Any]:
        """Harvest combined live state from OpenWrt UCI firewall and Modbus TCP PLC."""
        state: Dict[str, Any] = {
            "agent_node": "OpenWrt-Industrial-Carrier-Gateway",
            "timestamp": time.time(),
        }

        # 1. Harvest UCI Firewall
        if self.uci_firewall_path.is_file():
            try:
                uci_data = parse_uci(self.uci_firewall_path, package_name="firewall")
                state.update(uci_data)
            except Exception as e:
                state["firewall_harvest_error"] = str(e)
        else:
            state["firewall_harvest_warning"] = f"UCI file not found: {self.uci_firewall_path}"

        # 2. Harvest Southbound Modbus TCP
        probe = ModbusTCPProbe(host=self.modbus_host, port=self.modbus_port)
        registers_state: Dict[str, Any] = {}
        for name, addr in self.register_map.items():
            try:
                vals = probe.read_holding_registers(start_addr=addr, count=1)
                registers_state[name] = vals[0] if vals else 0
            except Exception as e:
                registers_state[name] = f"MODBUS_CONN_ERROR: {e}"

        state["process_registers"] = registers_state
        return state

    def audit(
        self,
        baseline_file: Union[str, Path],
        current_uci_file: Optional[Union[str, Path]] = None,
        live_modbus: bool = False,
    ) -> Dict[str, Any]:
        """
        Audit live state or provided files against a baseline.
        Returns evaluation metrics including W-STED distance and NDI.
        """
        from otdrift.core.comparator import compare_configs
        from otdrift.core.loader import load_config
        from otdrift.rules.engine import SecurityRuleEngine

        # Load baseline
        baseline_data, baseline_meta = load_config(baseline_file)

        # Harvest or load current
        if current_uci_file:
            current_data, current_meta = load_config(current_uci_file)
        elif live_modbus:
            current_data = self.collect_live_state()
            current_meta = {"file_name": "live_openwrt_harvest", "format": "LIVE"}
        else:
            current_data = self.collect_live_state()
            current_meta = {"file_name": "openwrt_edge_state", "format": "EDGE"}

        # Compare
        result = compare_configs(baseline_data, current_data, baseline_meta, current_meta)

        # Rule evaluation & W-STED distance quantification
        engine = SecurityRuleEngine()
        result = engine.evaluate(result)

        return {
            "has_drift": result.has_drift,
            "total_drifts": result.total_drifts,
            "max_severity": result.max_severity,
            "w_sted_distance": result.w_sted_distance,
            "normalized_drift_index": result.normalized_drift_index,
            "normalized_risk_score": result.normalized_risk_score,
            "drifts": [item.to_dict() for item in result.items],
        }


def main():
    parser = argparse.ArgumentParser(description="otdrift OpenWrt Edge Carrier Agent")
    parser.add_argument("-b", "--baseline", required=True, help="Path to golden baseline (JSON or UCI)")
    parser.add_argument("-c", "--current", default=None, help="Path to current UCI or snapshot (optional)")
    parser.add_argument("--modbus-host", default="127.0.0.1", help="Target PLC Modbus IP")
    parser.add_argument("--modbus-port", type=int, default=502, help="Target PLC Modbus Port")
    parser.add_argument("--live", action="store_true", help="Harvest live state from OpenWrt & Modbus")
    parser.add_argument("--auto-block", action="store_true", help="Automatically trigger iptables drop on CRITICAL drift")
    args = parser.parse_args()

    agent = OpenWrtCarrierAgent(
        uci_firewall_path=args.current or "/etc/config/firewall",
        modbus_host=args.modbus_host,
        modbus_port=args.modbus_port,
    )

    print(f"[*] Starting otdrift OpenWrt Edge Audit...")
    report = agent.audit(
        baseline_file=args.baseline,
        current_uci_file=args.current if not args.live else None,
        live_modbus=args.live,
    )

    print(f"\n[+] Audit Complete:")
    print(f"    - Maximum Severity: {report['max_severity']}")
    print(f"    - Total Drifts:     {report['total_drifts']}")
    print(f"    - W-STED Distance:  {report['w_sted_distance']:.2f}")
    print(f"    - Normalized Index: {report['normalized_drift_index']:.4f}")
    print(f"    - Risk Score:       {report['normalized_risk_score']}/100")

    if report["has_drift"]:
        print(f"\n[!] Detected Drifts:")
        for d in report["drifts"]:
            print(f"    [{d['severity']}] {d['path']}: {d['baseline_value']} -> {d['current_value']} (D={d['drift_distance']:.2f})")

        if args.auto_block and report["max_severity"] == "CRITICAL":
            print("[!] CRITICAL drift detected! Executing OpenWrt edge containment...")
            if os.name != "nt":
                os.system("iptables -I FORWARD -p tcp --dport 502 -j DROP")
                print("[+] Injected iptables drop rule for Modbus Port 502")
    else:
        print("\n[+] System is CLEAN: Fully aligned with baseline.")


if __name__ == "__main__":
    main()
