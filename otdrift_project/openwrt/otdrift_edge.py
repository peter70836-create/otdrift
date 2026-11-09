#!/usr/bin/env python3
"""
otdrift-edge: Self-Contained Industrial OT/ICS Drift Auditor for OpenWrt Gateways.
Requires ZERO external Python dependencies (Runs out-of-the-box on OpenWrt with standard python3 / python3-light).
Dual-Track Auditing:
1. Local OpenWrt Gateway UCI Firewall & Network Integrity (/etc/config/firewall)
2. Southbound Industrial Modbus TCP (Port 502) Holding Register Extraction & Invariant Checking
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import socket
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ==============================================================================
# 1. OpenWrt UCI Parser & Serializer (Zero-Dependency)
# ==============================================================================

class UCISection:
    def __init__(self, section_type: str, section_name: Optional[str] = None):
        self.section_type = section_type
        self.section_name = section_name
        self.options: Dict[str, Any] = {}
        self.lists: Dict[str, List[Any]] = {}

    def get_name(self, idx: int) -> str:
        if self.section_name:
            return self.section_name
        if "name" in self.options:
            return str(self.options["name"])
        return f"{self.section_type}_{idx}"

    def to_dict(self) -> Dict[str, Any]:
        res = dict(self.options)
        res.update(self.lists)
        return res


class UCIParser:
    @staticmethod
    def parse_value(raw: str) -> Any:
        raw = raw.strip()
        if (raw.startswith("'") and raw.endswith("'")) or (raw.startswith('"') and raw.endswith('"')):
            raw = raw[1:-1].strip()
        lower = raw.lower()
        if lower in ["true", "yes"]:
            return True
        if lower in ["false", "no"]:
            return False
        if re.fullmatch(r"[-+]?\d+", raw):
            try:
                return int(raw)
            except ValueError:
                pass
        if re.fullmatch(r"[-+]?\d+\.\d+", raw):
            try:
                return float(raw)
            except ValueError:
                pass
        return raw

    @classmethod
    def parse_string(cls, text: str, default_pkg: str = "firewall") -> Dict[str, Any]:
        pkg_name = default_pkg
        sections: List[UCISection] = []
        curr: Optional[UCISection] = None

        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue
            if line.startswith("package "):
                parts = line.split(maxsplit=1)
                if len(parts) > 1:
                    p = parts[1].strip("'\"")
                    if p:
                        pkg_name = p
                continue
            if line.startswith("config "):
                parts = line.split()
                sec_type = parts[1].strip("'\"")
                sec_name = parts[2].strip("'\"") if len(parts) >= 3 else None
                curr = UCISection(sec_type, sec_name)
                sections.append(curr)
                continue
            if line.startswith("option ") and curr:
                parts = line.split(maxsplit=2)
                k = parts[1].strip("'\"")
                v = cls.parse_value(parts[2]) if len(parts) >= 3 else ""
                curr.options[k] = v
                continue
            if line.startswith("list ") and curr:
                parts = line.split(maxsplit=2)
                if len(parts) >= 3:
                    k = parts[1].strip("'\"")
                    v = cls.parse_value(parts[2])
                    curr.lists.setdefault(k, []).append(v)
                continue

        # Group into hierarchical dictionary
        grouped: Dict[str, Any] = {}
        counters: Dict[str, int] = {}
        for s in sections:
            cnt = counters.get(s.section_type, 0)
            name = s.get_name(cnt)
            counters[s.section_type] = cnt + 1
            cat = f"{s.section_type}s" if not s.section_type.endswith("s") else s.section_type
            grouped.setdefault(cat, {})[name] = s.to_dict()

        return {pkg_name: grouped}

    @classmethod
    def parse_file(cls, path: Union[str, Path], default_pkg: str = "firewall") -> Dict[str, Any]:
        p = Path(path)
        if not p.is_file():
            raise FileNotFoundError(f"UCI file not found: {p}")
        return cls.parse_string(p.read_text(encoding="utf-8", errors="replace"), default_pkg=default_pkg)


# ==============================================================================
# 2. Native Semantic Drift Comparator (Zero-DeepDiff Dependency)
# ==============================================================================

class ChangeType:
    MODIFIED = "MODIFIED"
    ADDED = "ADDED"
    REMOVED = "REMOVED"
    TYPE_CHANGED = "TYPE_CHANGED"
    LIST_CHANGED = "LIST_CHANGED"


class DriftItem:
    def __init__(self, path: str, change_type: str, baseline_val: Any, current_val: Any, desc: str = ""):
        self.path = path
        self.change_type = change_type
        self.baseline_value = baseline_val
        self.current_value = current_val
        self.description = desc
        self.severity = "INFO"
        self.risk_score = 10
        self.drift_distance = 0.0
        self.mitre_id = "T0839"
        self.mitre_name = "Modify Parameter"
        self.threat_desc = ""
        self.remediation = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "change_type": self.change_type,
            "baseline_value": self.baseline_value,
            "current_value": self.current_value,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "drift_distance": round(self.drift_distance, 2),
            "mitre": {"technique_id": self.mitre_id, "technique_name": self.mitre_name},
            "threat_description": self.threat_desc,
            "remediation": self.remediation,
        }


def native_compare_dicts(base: dict, curr: dict, prefix: str = "", ignore_order: bool = True) -> List[DriftItem]:
    """Recursively compares two dictionaries with order-invariant list matching."""
    items: List[DriftItem] = []

    # 1. Removed or Modified keys
    for k, b_val in base.items():
        curr_path = f"{prefix}.{k}" if prefix else str(k)
        if k not in curr:
            items.append(DriftItem(curr_path, ChangeType.REMOVED, b_val, None, "Parameter removed from baseline"))
            continue

        c_val = curr[k]
        if isinstance(b_val, dict) and isinstance(c_val, dict):
            items.extend(native_compare_dicts(b_val, c_val, prefix=curr_path, ignore_order=ignore_order))
        elif type(b_val) != type(c_val) and not (
            isinstance(b_val, (int, float)) and isinstance(c_val, (int, float)) and not isinstance(b_val, bool) and not isinstance(c_val, bool)
        ):
            items.append(DriftItem(curr_path, ChangeType.TYPE_CHANGED, b_val, c_val, f"Type changed from {type(b_val).__name__} to {type(c_val).__name__}"))
        elif isinstance(b_val, list) and isinstance(c_val, list):
            if ignore_order:
                b_set = set(str(x) for x in b_val)
                c_set = set(str(x) for x in c_val)
                if b_set != c_set:
                    items.append(DriftItem(curr_path, ChangeType.LIST_CHANGED, b_val, c_val, "List items modified (order-independent)"))
            else:
                if b_val != c_val:
                    items.append(DriftItem(curr_path, ChangeType.LIST_CHANGED, b_val, c_val, "List items modified"))
        elif b_val != c_val:
            items.append(DriftItem(curr_path, ChangeType.MODIFIED, b_val, c_val, f"Value changed from '{b_val}' to '{c_val}'"))

    # 2. Added keys
    for k, c_val in curr.items():
        curr_path = f"{prefix}.{k}" if prefix else str(k)
        if k not in base:
            items.append(DriftItem(curr_path, ChangeType.ADDED, None, c_val, "New parameter added in current snapshot"))

    return items


# ==============================================================================
# 3. W-STED Distance & NDI Mathematical Model
# ==============================================================================

class LayerWeightRegistry:
    PREFIX_WEIGHTS = {
        "safety": 3.0,
        "safety_and_integrity": 3.0,
        "process_registers": 3.0,
        "firewall": 2.0,
        "openwrt": 2.0,
        "protocols": 2.0,
        "management": 1.5,
        "network": 1.0,
        "device_info": 0.5,
    }

    @classmethod
    def get_weight(cls, path: str) -> float:
        lp = path.lower()
        for prefix, w in cls.PREFIX_WEIGHTS.items():
            if lp.startswith(prefix):
                return w
        return 1.0


def calculate_delta(b_val: Any, c_val: Any) -> float:
    if b_val == c_val:
        return 0.0
    if isinstance(b_val, (int, float)) and isinstance(c_val, (int, float)) and not isinstance(b_val, bool) and not isinstance(c_val, bool):
        denom = abs(b_val)
        if denom == 0:
            return min(1.0, abs(c_val))
        return min(1.0, abs(c_val - b_val) / denom)
    if isinstance(b_val, list) and isinstance(c_val, list):
        b_s = set(str(x) for x in b_val)
        c_s = set(str(x) for x in c_val)
        u = len(b_s | c_s)
        return 1.0 - (len(b_s & c_s) / u) if u > 0 else 0.0
    return 1.0


# ==============================================================================
# 4. OpenWrt Edge Security Rules & Threat Inference
# ==============================================================================

class EdgeRuleEngine:
    @staticmethod
    def evaluate(items: List[DriftItem]) -> Tuple[List[DriftItem], float, float, int]:
        total_dist = 0.0

        for item in items:
            w = LayerWeightRegistry.get_weight(item.path)
            delta = calculate_delta(item.baseline_value, item.current_value)
            dist = round(w * delta, 2)
            item.drift_distance = dist
            total_dist += dist

            p_lower = item.path.lower()
            c_str = str(item.current_value).lower()

            # Rule 1: Modbus Port 502 WAN exposure or Injected Backdoor Rule
            if "firewall.rules" in p_lower and (
                ("src" in p_lower or "target" in p_lower) and c_str in ["wan", "internet", "0.0.0.0/0", "any"]
                or ("502" in c_str and "wan" in c_str)
            ):
                item.severity = "CRITICAL"
                item.risk_score = 98
                item.mitre_id = "T0855"
                item.mitre_name = "Unauthorized Command Message"
                item.threat_desc = f"OpenWrt 工控防火牆規則外曝：Modbus TCP 502 來源被竄改為 '{item.current_value}' (原為 '{item.baseline_value}')！外網可直接注入工控指令。"
                item.remediation = "立即執行 '/etc/init.d/firewall restart' 還原標準規則，並檢查 /etc/config/firewall 確保 Modbus 規則 src 限縮為 lan。"

            # Rule 2: OpenWrt Firewall Zone or Default policy weakened to ACCEPT
            elif ("firewall.defaults" in p_lower or "firewall.zones" in p_lower) and ("forward" in p_lower or "input" in p_lower) and c_str in ["accept", "allow"]:
                item.severity = "CRITICAL"
                item.risk_score = 95
                item.mitre_id = "T0855"
                item.mitre_name = "Unauthorized Command Message"
                item.threat_desc = f"OpenWrt 防火牆邊界安全政策弱化 ({item.path} 變更為 '{item.current_value}')！外部未授權流量可長驅直入或跨網段轉發。"
                item.remediation = f"執行 'uci set firewall.@defaults[0].forward=REJECT && uci commit firewall && /etc/init.d/firewall restart' 還原嚴格隔離政策。"

            # Rule 3: Southbound Modbus Critical Setpoint Tampered
            elif "process_registers" in p_lower:
                item.severity = "CRITICAL"
                item.risk_score = 95
                item.mitre_id = "T0839"
                item.mitre_name = "Modify Parameter"
                item.threat_desc = f"現場 PLC 保持暫存器遭竄改 ({item.path}: {item.baseline_value} -> {item.current_value})。實體設備面臨超壓、爆管或停機危險。"
                item.remediation = f"派員現場核實壓力閥門讀數，並透過 Modbus FC 06 將 {item.path} 數值還原為基準值 {item.baseline_value}。"

            # Rule 4: Modbus TCP Auth Disabled
            elif "modbus_tcp.auth_required" in p_lower and c_str in ["false", "0", "no"]:
                item.severity = "CRITICAL"
                item.risk_score = 95
                item.mitre_id = "T0812"
                item.mitre_name = "Default Credentials"
                item.threat_desc = "Modbus TCP 通訊身分認證遭關閉，任何內網裝置皆可任意下達工控功能碼。"
                item.remediation = "將 auth_required 復原為 true，阻斷非授權主站連線。"

            # Fallback
            else:
                item.severity = "LOW"
                item.risk_score = 20
                item.mitre_id = "T0839"
                item.mitre_name = "Modify Parameter"
                item.threat_desc = f"組態參數 '{item.path}' 與黃金標準設定不一致。"
                item.remediation = "審核此變更是否符合工控 MOC 流程，若未授權請予原樣還原。"

        total_dist = round(total_dist, 2)
        if total_dist == 0.0:
            ndi = 0.0
            risk_score = 0
        else:
            ndi = round(min(1.0, 1.0 - math.exp(-total_dist / 2.5)), 4)
            risk_score = min(100, int(round((1.0 - math.exp(-total_dist / 2.5)) * 100)))

        # Sort: CRITICAL -> HIGH -> MEDIUM -> LOW -> INFO
        sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        items.sort(key=lambda x: (sev_rank.get(x.severity, 5), -x.risk_score, x.path))

        return items, total_dist, ndi, risk_score


# ==============================================================================
# 5. Raw Socket Modbus TCP Probe (Zero-Pymodbus Dependency)
# ==============================================================================

class ModbusTCPProbe:
    def __init__(self, host: str = "127.0.0.1", port: int = 502, timeout: float = 2.0):
        self.host = host
        self.port = port
        self.timeout = timeout

    def read_holding_registers(self, start_addr: int = 0, count: int = 1, unit_id: int = 1) -> List[int]:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            s.connect((self.host, self.port))
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
            if len(resp) < 9 or (resp[7] & 0x80):
                return []
            byte_count = resp[8]
            data_bytes = resp[9: 9 + byte_count]
            return [(data_bytes[i] << 8) | data_bytes[i + 1] for i in range(0, len(data_bytes) - 1, 2)]
        except Exception:
            return []
        finally:
            s.close()


# ==============================================================================
# 6. OpenWrt Native Edge Auditor & Runner
# ==============================================================================

class OpenWrtEdgeEngine:
    def __init__(self, uci_path: str = "/etc/config/firewall", modbus_host: str = "127.0.0.1", modbus_port: int = 502):
        self.uci_path = Path(uci_path)
        self.modbus_host = modbus_host
        self.modbus_port = modbus_port

    def load_config(self, filepath: Union[str, Path]) -> Dict[str, Any]:
        p = Path(filepath)
        text = p.read_text(encoding="utf-8", errors="replace")
        if not text.strip():
            raise ValueError(f"設定檔 {p.resolve()} 為空檔案 (0 bytes)！請確認內容。")
        if p.suffix.lower() == ".uci" or "config " in text:
            return UCIParser.parse_string(text, default_pkg="firewall")
        return json.loads(text)

    def collect_live_state(self) -> Dict[str, Any]:
        state: Dict[str, Any] = {}
        # 1. Harvest local UCI
        if self.uci_path.is_file():
            try:
                state.update(UCIParser.parse_file(self.uci_path, default_pkg="firewall"))
            except Exception as e:
                state["firewall_error"] = str(e)
        # 2. Harvest Southbound Modbus
        probe = ModbusTCPProbe(self.modbus_host, self.modbus_port)
        regs = probe.read_holding_registers(0, 1)
        state["process_registers"] = {
            "pump_cutoff_pressure_psi": regs[0] if regs else 0
        }
        return state

    def audit(self, baseline_path: Union[str, Path], current_path: Optional[Union[str, Path]] = None, live: bool = False) -> Dict[str, Any]:
        base = self.load_config(baseline_path)
        if live:
            curr = self.collect_live_state()
        elif current_path:
            curr = self.load_config(current_path)
        else:
            curr = self.collect_live_state()

        # Run native comparator
        raw_drifts = native_compare_dicts(base, curr)

        # Run rule & distance engine
        items, w_sted, ndi, risk_score = EdgeRuleEngine.evaluate(raw_drifts)

        max_sev = "CLEAN"
        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if any(it.severity == s for it in items):
                max_sev = s
                break

        return {
            "audited_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "has_drift": len(items) > 0,
            "total_drifts": len(items),
            "max_severity": max_sev,
            "w_sted_distance": w_sted,
            "normalized_drift_index": ndi,
            "normalized_risk_score": risk_score,
            "drifts": [it.to_dict() for it in items],
        }


# ==============================================================================
# 7. ANSI Terminal Visual Formatter (Zero-Rich Dependency)
# ==============================================================================

C_RED = "\033[1;31m"
C_GRN = "\033[1;32m"
C_YEL = "\033[1;33m"
C_BLU = "\033[1;34m"
C_MAG = "\033[1;35m"
C_CYA = "\033[1;36m"
C_WHT = "\033[1;37m"
C_RST = "\033[0m"


def print_ansi_report(rep: Dict[str, Any]):
    sev = rep["max_severity"]
    sev_color = C_RED if sev == "CRITICAL" else (C_GRN if sev == "CLEAN" else C_YEL)

    print(f"\n{C_CYA}╔════════════════════════════════════════════════════════════════════════════╗{C_RST}")
    print(f"{C_CYA}║          🛡️  otdrift-edge : OpenWrt 工控閘道器邊緣安全審計報告            ║{C_RST}")
    print(f"{C_CYA}╚════════════════════════════════════════════════════════════════════════════╝{C_RST}")
    print(f" • 審計評定 (Severity)     : {sev_color}{sev}{C_RST}")
    print(f" • 飄移總數 (Total Drifts) : {C_WHT}{rep['total_drifts']}{C_RST}")
    print(f" • W-STED 語意距離 (D)     : {C_YEL}{rep['w_sted_distance']:.2f}{C_RST}")
    print(f" • 歸一化飄移指數 (NDI)    : {C_MAG}{rep['normalized_drift_index']:.4f}{C_RST}")
    print(f" • 整體工控風險分值        : {sev_color}{rep['normalized_risk_score']} / 100{C_RST}")

    if not rep["has_drift"]:
        print(f"\n{C_GRN}✓ 完美吻合：OpenWrt 網關與下向 PLC 完全符合黃金標準，未發現任何組態飄移！{C_RST}\n")
        return

    print(f"\n{C_BLU}┌───┬───────────────────────────────────────────┬────────┬────────┬──────┬─────────┐{C_RST}")
    print(f"{C_BLU}│等 │ 參數路徑 (Parameter Path)                 │ 基準   │ 現況   │ 距離 │ MITRE   │{C_RST}")
    print(f"{C_BLU}├───┼───────────────────────────────────────────┼────────┼────────┼──────┼─────────┤{C_RST}")
    for d in rep["drifts"]:
        col = C_RED if d["severity"] == "CRITICAL" else C_YEL
        path_str = (d["path"][:41] + "..") if len(d["path"]) > 43 else d["path"].ljust(43)
        b_str = str(d["baseline_value"])[:6].center(6)
        c_str = str(d["current_value"])[:6].center(6)
        print(f"│{col}{d['severity'][:3]}{C_RST}│ {path_str} │ {b_str} │ {c_str} │ {d['drift_distance']:4.2f} │ {d['mitre']['technique_id']}   │")
    print(f"{C_BLU}└───┴───────────────────────────────────────────┴────────┴────────┴──────┴─────────┘{C_RST}")

    print(f"\n{C_RED}🚨 高危險飄移現場處置手冊 (Incident Playbook):{C_RST}")
    for d in rep["drifts"]:
        if d["severity"] in ["CRITICAL", "HIGH"]:
            print(f"{C_YEL}▶ [{d['severity']}] {d['path']} ({d['mitre']['technique_id']} - {d['mitre']['technique_name']}){C_RST}")
            print(f"   威脅說明：{d['threat_description']}")
            print(f"   {C_GRN}建議處置：{d['remediation']}{C_RST}\n")


def main():
    parser = argparse.ArgumentParser(description="otdrift-edge: OpenWrt Native ICS Drift Auditor")
    parser.add_argument("-b", "--baseline", default=None, help="Golden baseline file (.json or .uci)")
    parser.add_argument("-c", "--current", default=None, help="Current snapshot file (.json or .uci)")
    parser.add_argument("--export-baseline", default=None, help="Export live state as golden baseline to specified path")
    parser.add_argument("--uci-path", default="/etc/config/firewall", help="Local UCI firewall path")
    parser.add_argument("--modbus-host", default="127.0.0.1", help="Target PLC Modbus Host")
    parser.add_argument("--modbus-port", type=int, default=502, help="Target PLC Modbus Port")
    parser.add_argument("--live", action="store_true", help="Harvest live state from OpenWrt UCI & Modbus")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON only")
    parser.add_argument("--auto-block", action="store_true", help="Auto-inject iptables drop rule on CRITICAL drift")
    args = parser.parse_args()

    engine = OpenWrtEdgeEngine(
        uci_path=args.uci_path,
        modbus_host=args.modbus_host,
        modbus_port=args.modbus_port,
    )

    if args.export_baseline:
        state = engine.collect_live_state()
        out_p = Path(args.export_baseline)
        out_p.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"{C_GRN}✓ 成功將現場真實組態匯出為黃金標準至：{out_p}{C_RST}")
        sys.exit(0)

    if not args.baseline:
        parser.error("請提供黃金標準路徑 (-b / --baseline) 或指定匯出目標 (--export-baseline)")

    report = engine.audit(
        baseline_path=args.baseline,
        current_path=args.current,
        live=args.live,
    )

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print_ansi_report(report)

    if args.auto_block and report["max_severity"] == "CRITICAL":
        print(f"{C_RED}[!] CRITICAL 威脅觸發！執行 OpenWrt 邊緣主動阻斷...{C_RST}")
        if os.name != "nt":
            os.system("iptables -I FORWARD -p tcp --dport 502 -j DROP")
            print(f"{C_GRN}[+] 已動態注入 iptables 阻斷 Modbus Port 502 轉發規則{C_RST}")

    sys.exit(1 if report["max_severity"] in ["CRITICAL", "HIGH"] else 0)


if __name__ == "__main__":
    main()
