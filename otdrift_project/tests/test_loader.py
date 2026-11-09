"""
Unit tests for otdrift configuration loader.
"""

import json
from pathlib import Path
import pytest
from otdrift.core.loader import load_config, ConfigLoadError, compute_file_sha256


def test_load_valid_json(tmp_path: Path):
    sample = {"device": "OpenPLC", "port": 502, "auth": True}
    file = tmp_path / "test.json"
    file.write_text(json.dumps(sample), encoding="utf-8")

    data, meta = load_config(file)
    assert data == sample
    assert meta["file_name"] == "test.json"
    assert meta["format"] == "JSON"
    assert len(meta["sha256"]) == 64


def test_load_valid_yaml(tmp_path: Path):
    yaml_content = """
    device: OpenPLC
    port: 502
    auth: true
    """
    file = tmp_path / "test.yaml"
    file.write_text(yaml_content, encoding="utf-8")

    data, meta = load_config(file)
    assert data["device"] == "OpenPLC"
    assert data["port"] == 502
    assert data["auth"] is True
    assert meta["format"] in ["YAML", "YML"]


def test_load_nonexistent_file(tmp_path: Path):
    with pytest.raises(ConfigLoadError) as exc_info:
        load_config(tmp_path / "nonexistent.json")
    assert "not found" in str(exc_info.value).lower()


def test_load_malformed_json(tmp_path: Path):
    file = tmp_path / "bad.json"
    file.write_text("{ unquoted_bad_json: 123 ", encoding="utf-8")

    with pytest.raises(ConfigLoadError) as exc_info:
        load_config(file)
    assert "syntax" in str(exc_info.value).lower() or "json" in str(exc_info.value).lower()


def test_checksum_computation(tmp_path: Path):
    file = tmp_path / "sample.txt"
    file.write_text("hello world", encoding="utf-8")
    expected_hash = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    assert compute_file_sha256(file) == expected_hash
