"""
Integration tests for otdrift CLI commands.
"""

from click.testing import CliRunner
from otdrift.cli import cli


def test_cli_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "otdrift" in result.output


def test_cli_rules_list():
    runner = CliRunner()
    result = runner.invoke(cli, ["rules"])
    assert result.exit_code == 0
    assert "RULE-OT-001" in result.output


def test_cli_mitre_list():
    runner = CliRunner()
    result = runner.invoke(cli, ["mitre"])
    assert result.exit_code == 0
    assert "T0812" in result.output


def test_cli_check_clean():
    runner = CliRunner()
    result = runner.invoke(cli, [
        "check",
        "-b", "configs/baseline.json",
        "-c", "examples/scenarios/01_normal_running.json",
        "-f", "json",
    ])
    assert result.exit_code == 0
    assert '"has_drift": false' in result.output


def test_cli_check_drift_critical_fail():
    runner = CliRunner()
    result = runner.invoke(cli, [
        "check",
        "-b", "configs/baseline.json",
        "-c", "examples/scenarios/02_modbus_auth_disabled.json",
        "--fail-on", "HIGH",
    ])
    assert result.exit_code == 1
    assert "T0812" in result.output or "protocols.modbus_tcp.auth_required" in result.output


def test_cli_check_html_export(tmp_path):
    report_file = tmp_path / "report.html"
    runner = CliRunner()
    result = runner.invoke(cli, [
        "check",
        "-b", "configs/baseline.json",
        "-c", "examples/scenarios/03_unauthorized_port_and_remote_access.json",
        "-f", "html",
        "-o", str(report_file),
        "--fail-on", "NEVER",
    ])
    assert result.exit_code == 0
    assert report_file.exists()
    content = report_file.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in content
    assert "5020" in content
