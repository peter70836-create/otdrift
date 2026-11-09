"""
Zero-Disruption Offline Snapshot Ingestion and Drift Detection Scheduler.

In mission-critical OT environments, active scanning or aggressive polling
against live PLCs can disrupt scan cycles, induce jitter, or trigger fail-safe stops.
This script demonstrates the zero-disruption offline analysis architecture:
1. Non-intrusively monitors a staged config directory (e.g. read-only container mount).
2. Performs automated baseline drift audit using otdrift engine.
3. Emits structured evidence logs and alerts upon detecting security violations.
"""

from __future__ import annotations

import argparse
import logging
from datetime import datetime, timezone
from pathlib import Path
import sys
import time

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from otdrift.core.comparator import compare_configs
from otdrift.core.loader import load_config
from otdrift.reporters.console_reporter import ConsoleReporter
from otdrift.reporters.html_reporter import HtmlReporter
from otdrift.reporters.json_reporter import JsonReporter
from otdrift.reporters.markdown_reporter import MarkdownReporter
from otdrift.rules.engine import SecurityRuleEngine

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [OT-COLLECTOR] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ot_collector")


def perform_audit_cycle(
    baseline_path: Path,
    current_path: Path,
    reports_dir: Path,
    rules_path: Path | None = None,
    fail_on_critical: bool = True,
) -> bool:
    """Execute a single non-intrusive audit cycle."""
    logger.info("Starting zero-disruption offline configuration audit...")
    logger.info(f"Target Baseline: {baseline_path.name}")
    logger.info(f"Current Snapshot: {current_path.name}")

    if not current_path.exists():
        logger.warning(f"Snapshot file not yet present at {current_path}. Awaiting export...")
        return True

    # 1. Load configs
    try:
        baseline_data, b_meta = load_config(baseline_path)
        current_data, c_meta = load_config(current_path)
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        return False

    # 2. Compare
    result = compare_configs(baseline_data, current_data, b_meta, c_meta)

    # 3. Rule evaluation
    engine = SecurityRuleEngine(custom_rules_path=rules_path)
    result = engine.evaluate(result)

    # 4. Evidence archiving
    timestamp_slug = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    reports_dir.mkdir(parents=True, exist_ok=True)

    json_path = reports_dir / f"audit_{timestamp_slug}.json"
    html_path = reports_dir / f"audit_{timestamp_slug}.html"
    md_path = reports_dir / f"audit_{timestamp_slug}.md"

    JsonReporter().save(result, json_path)
    HtmlReporter().save(result, html_path)
    MarkdownReporter().save(result, md_path)

    # 5. Log and alert
    if result.has_drift:
        logger.warning(
            f"🚨 CONFIG DRIFT DETECTED! Max Severity: {result.max_severity} | "
            f"Total Drifts: {result.total_drifts} | Details: {json_path.name}"
        )
        for item in result.items:
            if item.severity in ["CRITICAL", "HIGH"]:
                logger.error(
                    f"[{item.severity}] Path: {item.path} | MITRE: {item.mitre_technique_id} | "
                    f"Threat: {item.threat_description}"
                )
        if fail_on_critical and result.max_severity in ["CRITICAL", "HIGH"]:
            return False
    else:
        logger.info("✓ Audit clean: Current configuration strictly complies with Golden Baseline.")

    return True


def main():
    parser = argparse.ArgumentParser(
        description="OT Zero-Disruption Offline Snapshot Ingestion and Drift Detector"
    )
    parser.add_argument("-b", "--baseline", default="configs/baseline.json", help="Path to golden baseline")
    parser.add_argument("-c", "--current", default="examples/scenarios/02_modbus_auth_disabled.json", help="Path to current snapshot")
    parser.add_argument("-r", "--rules", default="configs/rules.yaml", help="Path to custom rules")
    parser.add_argument("--reports-dir", default="reports", help="Directory to save audit reports")
    parser.add_argument("--loop", action="store_true", help="Run in continuous daemon monitoring mode")
    parser.add_argument("--interval", type=int, default=30, help="Monitoring interval seconds")

    args = parser.parse_args()

    baseline_path = Path(args.baseline)
    current_path = Path(args.current)
    reports_dir = Path(args.reports_dir)
    rules_path = Path(args.rules) if args.rules and Path(args.rules).exists() else None

    if args.loop:
        logger.info(f"Starting continuous daemon monitor (Interval: {args.interval}s)...")
        try:
            while True:
                perform_audit_cycle(baseline_path, current_path, reports_dir, rules_path, fail_on_critical=False)
                time.sleep(args.interval)
        except KeyboardInterrupt:
            logger.info("Monitoring daemon halted by user.")
    else:
        success = perform_audit_cycle(baseline_path, current_path, reports_dir, rules_path, fail_on_critical=True)
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
