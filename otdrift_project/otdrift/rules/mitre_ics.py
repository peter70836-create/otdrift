"""
MITRE ATT&CK for ICS (Industrial Control Systems) Knowledge Base.
Contains tactic/technique metadata, impact vectors, and mitigation guidance.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional


@dataclass(frozen=True)
class MitreTechnique:
    technique_id: str
    name: str
    tactic: str
    description: str
    impact: str
    url: str


# Pre-mapped MITRE ATT&CK for ICS knowledge base
MITRE_ICS_TECHNIQUES: Dict[str, MitreTechnique] = {
    "T0812": MitreTechnique(
        technique_id="T0812",
        name="Default Credentials",
        tactic="Initial Access / Lateral Movement",
        description="Adversaries may use default or disabled credentials to gain unauthorized access to OT devices or interfaces.",
        impact="Allows unauthenticated actors to execute privileged management functions on PLC/RTU.",
        url="https://attack.mitre.org/techniques/T0812/",
    ),
    "T0855": MitreTechnique(
        technique_id="T0855",
        name="Unauthorized Command Message",
        tactic="Impair Process Control",
        description="Adversaries may send unauthorized command messages over OT protocols (such as Modbus TCP) to instruct a device to act in an unexpected manner.",
        impact="Unauthorized alteration of coil/register outputs, manipulation of physical valves, motors, or safety limits.",
        url="https://attack.mitre.org/techniques/T0855/",
    ),
    "T0886": MitreTechnique(
        technique_id="T0886",
        name="Remote Services",
        tactic="Lateral Movement / Initial Access",
        description="Adversaries may leverage remote access services (such as SSH, RDP, Web Management, or VNC) to access network devices or control systems.",
        impact="Uncontrolled remote ingress into plant floor network without jumpbox or multi-factor authentication.",
        url="https://attack.mitre.org/techniques/T0886/",
    ),
    "T0807": MitreTechnique(
        technique_id="T0807",
        name="Command-Line Interface",
        tactic="Execution",
        description="Adversaries may leverage command-line interfaces on OT gateways or PLC web runtimes to execute commands.",
        impact="Direct operating system execution under the PLC daemon process context.",
        url="https://attack.mitre.org/techniques/T0807/",
    ),
    "T0843": MitreTechnique(
        technique_id="T0843",
        name="Program Download",
        tactic="Impair Process Control / Persistence",
        description="Adversaries may download new or modified control logic programs to controllers (PLCs/RTUs) to alter physical processes.",
        impact="Overwriting verified ladder logic or structured text with malicious payload that causes equipment damage.",
        url="https://attack.mitre.org/techniques/T0843/",
    ),
    "T0839": MitreTechnique(
        technique_id="T0839",
        name="Modify Parameter",
        tactic="Impair Process Control",
        description="Adversaries may alter device configuration parameters, setpoints, threshold limits, or communication parameters.",
        impact="Disrupts normal control loop dynamics, overrides critical operating alarms, and masks abnormal physical events.",
        url="https://attack.mitre.org/techniques/T0839/",
    ),
    "T0857": MitreTechnique(
        technique_id="T0857",
        name="System Firmware",
        tactic="Persistence / Defense Evasion",
        description="Adversaries may flash, downgrade, or modify system firmware on embedded control systems to introduce backdoors or exploit known vulnerabilities.",
        impact="Firmware downgrade bypasses newer security controls and allows persistent rootkit installation.",
        url="https://attack.mitre.org/techniques/T0857/",
    ),
    "T0836": MitreTechnique(
        technique_id="T0836",
        name="Modify Parameter (Safety/Protection)",
        tactic="Inhibit Response Function",
        description="Adversaries may modify safety-instrumented system (SIS) thresholds or disable write-protection on critical registers.",
        impact="Neutralizes emergency shutdown or safety interlocks when physical pressure/temperature exceeds thresholds.",
        url="https://attack.mitre.org/techniques/T0836/",
    ),
    "T0831": MitreTechnique(
        technique_id="T0831",
        name="Manipulation of Control",
        tactic="Impair Process Control",
        description="Adversaries may manipulate physical process states through altered controller operating modes (e.g. forcing RUN to STOP).",
        impact="Halts physical industrial production line or causes desynchronization of assembly lines.",
        url="https://attack.mitre.org/techniques/T0831/",
    ),
    "T0883": MitreTechnique(
        technique_id="T0883",
        name="Internet Accessible Device",
        tactic="Initial Access",
        description="Adversaries may target OT controllers exposed directly to public or untrusted IP segments.",
        impact="Direct internet discovery via Shodan/Censys, allowing opportunistic brute force or unauthenticated exploitation.",
        url="https://attack.mitre.org/techniques/T0883/",
    ),
    "T0885": MitreTechnique(
        technique_id="T0885",
        name="Commonly Used Port",
        tactic="Command and Control / Lateral Movement",
        description="Adversaries may communicate using standard or non-standard ports to blend in with legitimate OT traffic or bypass network firewall rules.",
        impact="Unauthorized communication bypassing industrial firewall inspection.",
        url="https://attack.mitre.org/techniques/T0885/",
    ),
    "T0859": MitreTechnique(
        technique_id="T0859",
        name="Valid Accounts",
        tactic="Initial Access / Defense Evasion",
        description="Adversaries may obtain and abuse credentials of existing accounts, or weaken authentication complexity.",
        impact="Undetected lateral movement using valid administrative privileges.",
        url="https://attack.mitre.org/techniques/T0859/",
    ),
}


def get_mitre_technique(technique_id: str) -> Optional[MitreTechnique]:
    """Retrieve MITRE technique details by ID."""
    return MITRE_ICS_TECHNIQUES.get(technique_id)
