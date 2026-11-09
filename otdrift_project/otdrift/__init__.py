# otdrift package
"""
otdrift - OT/ICS Golden Baseline Configuration Drift Detection & MITRE ATT&CK for ICS Analyzer
"""

__version__ = "1.0.0"
__author__ = "OT Security Team"

from otdrift.core.comparator import compare_configs, DriftComparator
from otdrift.core.loader import load_config
from otdrift.rules.engine import SecurityRuleEngine
from otdrift.reporters.base import BaseReporter

__all__ = [
    "compare_configs",
    "DriftComparator",
    "load_config",
    "SecurityRuleEngine",
    "BaseReporter",
]
