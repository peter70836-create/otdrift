"""
OpenWrt UCI (Unified Configuration Interface) Parser and Converter for otdrift.
Enables parsing and auditing of OpenWrt firewall, network, and system configurations.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


class UCIParseError(Exception):
    """Raised when UCI configuration syntax is invalid."""
    pass


class UCISection:
    """Represents a section in an OpenWrt UCI configuration file."""

    def __init__(self, section_type: str, section_name: Optional[str] = None):
        self.section_type = section_type
        self.section_name = section_name
        self.options: Dict[str, Any] = {}
        self.lists: Dict[str, List[Any]] = {}

    def get_effective_name(self, fallback_index: int) -> str:
        """Return designated section name or 'name' option or fallback."""
        if self.section_name:
            return self.section_name
        if "name" in self.options:
            return str(self.options["name"])
        return f"{self.section_type}_{fallback_index}"

    def to_dict(self) -> Dict[str, Any]:
        """Convert section options and lists into a Python dictionary."""
        d: Dict[str, Any] = {}
        for k, v in self.options.items():
            d[k] = v
        for k, v in self.lists.items():
            d[k] = v
        return d


class UCIParser:
    """
    Parser for OpenWrt UCI syntax files (e.g. /etc/config/firewall).
    Transforms flat UCI blocks into structured hierarchical representations.
    """

    def __init__(self, package_name: str = "openwrt_gateway"):
        self.package_name = package_name
        self.sections: List[UCISection] = []

    @staticmethod
    def _parse_value(raw: str) -> Any:
        """Parse raw string token into boolean, integer, float, or unquoted string."""
        raw = raw.strip()
        # Strip surrounding single or double quotes
        if (raw.startswith("'") and raw.endswith("'")) or (raw.startswith('"') and raw.endswith('"')):
            raw = raw[1:-1].strip()

        # Booleans in OpenWrt ('1'/'0', 'true'/'false', 'yes'/'no')
        lower = raw.lower()
        if lower in ["true", "yes"]:
            return True
        if lower in ["false", "no"]:
            return False

        # Integers
        if re.fullmatch(r"[-+]?\d+", raw):
            try:
                return int(raw)
            except ValueError:
                pass

        # Floats
        if re.fullmatch(r"[-+]?\d+\.\d+", raw):
            try:
                return float(raw)
            except ValueError:
                pass

        return raw

    def parse_string(self, content: str) -> List[UCISection]:
        """Parse raw text content of a UCI file."""
        self.sections = []
        current_section: Optional[UCISection] = None

        lines = content.splitlines()
        for line_no, raw_line in enumerate(lines, 1):
            line = raw_line.strip()
            # Ignore empty lines and comments
            if not line or line.startswith("#") or line.startswith("//"):
                continue

            # package declaration
            if line.startswith("package "):
                parts = line.split(maxsplit=1)
                if len(parts) > 1:
                    pkg = parts[1].strip().strip("'\"")
                    if pkg:
                        self.package_name = pkg
                continue

            # config <type> [<name>]
            if line.startswith("config "):
                parts = line.split()
                if len(parts) < 2:
                    raise UCIParseError(f"Line {line_no}: Invalid config statement: '{line}'")
                sec_type = parts[1].strip("'\"")
                sec_name = parts[2].strip("'\"") if len(parts) >= 3 else None
                current_section = UCISection(section_type=sec_type, section_name=sec_name)
                self.sections.append(current_section)
                continue

            # option <key> <value>
            if line.startswith("option "):
                if current_section is None:
                    raise UCIParseError(f"Line {line_no}: 'option' statement outside of any 'config' block: '{line}'")
                # Split on whitespace, max 3 items: 'option', key, value
                parts = line.split(maxsplit=2)
                if len(parts) < 3:
                    # Empty option value e.g. "option src ''"
                    key = parts[1].strip("'\"")
                    val = ""
                else:
                    key = parts[1].strip("'\"")
                    val = self._parse_value(parts[2])
                current_section.options[key] = val
                continue

            # list <key> <value>
            if line.startswith("list "):
                if current_section is None:
                    raise UCIParseError(f"Line {line_no}: 'list' statement outside of any 'config' block: '{line}'")
                parts = line.split(maxsplit=2)
                if len(parts) < 3:
                    continue
                key = parts[1].strip("'\"")
                val = self._parse_value(parts[2])
                if key not in current_section.lists:
                    current_section.lists[key] = []
                current_section.lists[key].append(val)
                continue

        return self.sections

    def parse_file(self, file_path: Union[str, Path]) -> List[UCISection]:
        """Read and parse a UCI configuration file from disk."""
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"UCI file not found: {path}")
        text = path.read_text(encoding="utf-8", errors="replace")
        return self.parse_string(text)

    def to_dict(self, root_prefix: Optional[str] = None) -> Dict[str, Any]:
        """
        Convert parsed UCI sections into structured nested dictionary compatible with otdrift.
        Grouped by section_type, then by section_name.
        """
        prefix = root_prefix if root_prefix is not None else self.package_name
        grouped: Dict[str, Any] = {}

        type_indices: Dict[str, int] = {}
        for sec in self.sections:
            idx = type_indices.get(sec.section_type, 0)
            sec_name = sec.get_effective_name(fallback_index=idx)
            type_indices[sec.section_type] = idx + 1

            plural_type = f"{sec.section_type}s" if not sec.section_type.endswith("s") else sec.section_type
            if plural_type not in grouped:
                grouped[plural_type] = {}

            grouped[plural_type][sec_name] = sec.to_dict()

        return {prefix: grouped}

    @staticmethod
    def dump_uci(data: Dict[str, Any], package_name: Optional[str] = None) -> str:
        """
        Serialize structured dictionary back into standard OpenWrt UCI format string.
        """
        lines: List[str] = []
        if package_name:
            lines.append(f"package {package_name}\n")

        # Unwrap top-level prefix if present
        if len(data) == 1 and isinstance(next(iter(data.values())), dict):
            top_key = next(iter(data.keys()))
            inner = data[top_key]
        else:
            inner = data

        for group_type, sections in inner.items():
            if not isinstance(sections, dict):
                continue
            # Singularity (e.g. 'rules' -> 'rule', 'zones' -> 'zone')
            singular_type = group_type[:-1] if group_type.endswith("s") and not group_type.endswith("ss") else group_type

            for sec_name, sec_body in sections.items():
                if not isinstance(sec_body, dict):
                    continue
                lines.append(f"config {singular_type} '{sec_name}'")
                for k, v in sec_body.items():
                    if isinstance(v, list):
                        for item in v:
                            lines.append(f"\tlist {k} '{item}'")
                    elif isinstance(v, bool):
                        val_str = "1" if v else "0"
                        lines.append(f"\toption {k} '{val_str}'")
                    else:
                        lines.append(f"\toption {k} '{v}'")
                lines.append("")

        return "\n".join(lines).strip() + "\n"


def parse_uci(content_or_path: Union[str, Path], package_name: str = "openwrt_gateway") -> Dict[str, Any]:
    """Convenience helper to parse UCI content or file path into an otdrift dictionary."""
    parser = UCIParser(package_name=package_name)
    path = Path(content_or_path)
    if path.is_file():
        parser.parse_file(path)
    else:
        parser.parse_string(str(content_or_path))
    return parser.to_dict()


def dump_uci(data: Dict[str, Any], package_name: Optional[str] = None) -> str:
    """Convenience helper to dump dictionary back into UCI format string."""
    return UCIParser.dump_uci(data, package_name=package_name)
