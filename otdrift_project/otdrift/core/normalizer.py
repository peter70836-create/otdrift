"""
Configuration normalizer and path standardizer.
"""

from __future__ import annotations

import re
from typing import Any, Dict


def parse_deepdiff_path(path_str: str) -> str:
    """
    Convert DeepDiff root path syntax into standardized dot notation.
    Example:
        root['protocols']['modbus_tcp']['auth_required'] -> protocols.modbus_tcp.auth_required
        root['network']['dns_servers'][0] -> network.dns_servers[0]
    """
    if not path_str:
        return ""

    # Remove leading 'root'
    s = re.sub(r"^root", "", path_str)

    # Convert ['key'] to .key
    s = re.sub(r"\['([^']+)'\]", r".\1", s)
    # Convert ["key"] to .key
    s = re.sub(r'\["([^"]+)"\]', r".\1", s)

    # Clean leading dots
    s = s.lstrip(".")
    return s


def flatten_dict(d: Dict[str, Any], parent_key: str = "", sep: str = ".") -> Dict[str, Any]:
    """
    Flatten a nested dictionary into dot-delimited key-value pairs.
    """
    items: list[tuple[str, Any]] = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else str(k)
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


def get_nested_value(data: Dict[str, Any], path: str, default: Any = None) -> Any:
    """
    Retrieve nested value using dot notation (e.g. 'protocols.modbus_tcp.port').
    """
    parts = path.split(".")
    curr: Any = data
    for part in parts:
        if not isinstance(curr, dict):
            return default
        if part not in curr:
            return default
        curr = curr[part]
    return curr
