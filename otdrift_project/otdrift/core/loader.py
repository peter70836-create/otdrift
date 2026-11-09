"""
Config file loader supporting JSON, YAML, and offline snapshot parsing.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Tuple
import yaml


class ConfigLoadError(Exception):
    """Raised when configuration fails to load or parse."""
    pass


def compute_file_sha256(filepath: str | Path) -> str:
    """Compute SHA-256 checksum of a file for integrity tracking."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
    return sha256.hexdigest()


def load_config(filepath: str | Path) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Safely load a configuration file (JSON or YAML).

    Returns:
        Tuple of (parsed_config_dict, metadata_dict)
    """
    path = Path(filepath)
    if not path.exists():
        raise ConfigLoadError(f"Configuration file not found: {path.resolve()}")

    if not path.is_file():
        raise ConfigLoadError(f"Path is not a regular file: {path.resolve()}")

    try:
        content_bytes = path.read_bytes()
        file_hash = hashlib.sha256(content_bytes).hexdigest()
        content_text = content_bytes.decode("utf-8")
    except UnicodeDecodeError:
        try:
            content_text = content_bytes.decode("gbk")
        except Exception as e:
            raise ConfigLoadError(f"Failed to decode file {path.name}: {e}")
    except Exception as e:
        raise ConfigLoadError(f"Failed to read file {path.name}: {e}")

    suffix = path.suffix.lower()
    data: Any = None

    if suffix in [".json"]:
        try:
            data = json.loads(content_text)
        except json.JSONDecodeError as e:
            raise ConfigLoadError(f"Invalid JSON syntax in {path.name}: {e}")
    elif suffix in [".yaml", ".yml"]:
        try:
            data = yaml.safe_load(content_text)
        except yaml.YAMLError as e:
            raise ConfigLoadError(f"Invalid YAML syntax in {path.name}: {e}")
    elif suffix in [".uci"]:
        try:
            from otdrift.edge.uci_parser import parse_uci
            data = parse_uci(content_text, package_name="openwrt_gateway")
        except Exception as e:
            raise ConfigLoadError(f"Invalid UCI syntax in {path.name}: {e}")
    else:
        # Fallback: attempt JSON first, then YAML, then UCI
        try:
            data = json.loads(content_text)
        except Exception:
            try:
                data = yaml.safe_load(content_text)
            except Exception:
                try:
                    from otdrift.edge.uci_parser import parse_uci
                    data = parse_uci(content_text, package_name="openwrt_gateway")
                except Exception as e:
                    raise ConfigLoadError(
                        f"Unsupported or unparseable format for {path.name}. "
                        f"Expected JSON, YAML, or UCI. Error: {e}"
                    )

    if not isinstance(data, dict):
        raise ConfigLoadError(
            f"Config root must be a key-value mapping (dict), got {type(data).__name__}"
        )

    metadata = {
        "file_name": path.name,
        "absolute_path": str(path.resolve()),
        "file_size_bytes": len(content_bytes),
        "sha256": file_hash,
        "format": suffix.replace(".", "").upper() or "UNKNOWN",
    }

    return data, metadata
