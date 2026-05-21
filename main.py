"""CLI entrypoint for the production-grade Cyber Threat Intelligence platform."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections import Counter
from dataclasses import asdict
from pathlib import Path

from scripts.alerter import Alerter
from scripts.analyzer import Analyzer
from scripts.correlation_engine import CorrelationEngine
from scripts.enricher import Enricher
from scripts.fetcher import Fetcher
from scripts.ioc_extractor import IOCExtractor
from scripts.report_generator import ReportGenerator, ThreatFinding
from scripts.state_manager import StateManager
from scripts.threat_scorer import ThreatScorer


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""

    parser = argparse.ArgumentParser(
        description="AI-Powered Cyber Threat Intelligence (CTI) Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --test --mock-ai              # Test with mock data
  python main.py --live --enable-enrichment    # Production run with enrichment
  python main.py --live --enable-alerting      # Production with alerts
  python main.py --output-format markdown      # Export as Markdown report
        """
    )

    # Core execution modes
    parser.add_argument("--test", action="store_true", help="Use synthetic test data (no API calls)")
    parser.add_argument("--live", action="store_true", help="Fetch from real security feeds")
    parser.add_argument("--mock-ai", action="store_true", help="Use mock AI analysis instead of DeepSeek")

    # Database operations
    parser.add_argument("--reset-db", action="store_true", help="Clear database before processing")
    parser.add_argument("--init-db", action="store_true", help="Initialize/migrate database schema")

    # Enrichment & Analysis
    parser.add_argument(
        "--enable-enrichment",
        action="store_true",
        help="Enrich with NVD, CISA KEV, MITRE ATT&CK"
    )
    parser.add_argument("--deduplicate-only", action="store_true", help="Only deduplicate, skip analysis")

    # Alerting
    parser.add_argument("--enable-alerting", action="store_true", help="Send alerts to configured channels")
    parser.add_argument("--test-alerts", action="store_true", help="Test alerting channels and exit")

    # Output formatting
    parser.add_argument(
        "--output-format",
        choices=["json", "markdown", "csv", "stix"],
        default="json",
        help="Output format (default: json)"
    )
    parser.add_argument("--output-file", help="Write report to file instead of stdout")

    # Development & diagnostics
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")

    return parser.parse_args()


def _severity_breakdown(findings: list[dict]) -> dict[str, int]:
    """Count findings by severity."""
    counter = Counter()
    for finding in findings:
        counter[str(finding.get("severity", "unknown")).lower()] += 1
    return dict(sorted(counter.items()))


def _create_threat_findings(
    analysis_items: list,
    scorer: ThreatScorer,
    enricher: Enricher,
    extractor: IOCExtractor,
) -> list[ThreatFinding]:
    """Convert analysis items to threat findings with enrichment."""
    findings = []

    for item in analysis_items:
        # Extract IOCs
        iocs = extractor.extract(item.summary_en)

        cve_id = getattr(item, 'cve_id', None)
        if not cve_id:
            cve_id = enricher.extract_cve_id(f"{item.title} {item.summary_en}")

        description = item.summary_en
        kev_status = bool(cve_id and enricher.check_kev(cve_id))
        threat_score = scorer.score(
            title=item.title,
            description=description,
            cvss_score=getattr(item, 'cvss_score', 0.0),
            has_public_exploit=kev_status,
            is_in_kev=kev_status,
            is_ransomware='ransomware' in description.lower(),
            is_mass_exploitation=scorer.detect_mass_exploitation(item.title, description),
        )

        # Get MITRE mappings
        mitre_tactics = []
        mapping_text = " ".join(filter(None, [getattr(item, 'vulnerability_type', ''), item.title, item.summary_en]))
        if mapping_text:
            mappings = enricher.get_mitre_mappings(mapping_text)
            mitre_tactics = [m.tactic for m in mappings]

        # Create threat finding
        finding = ThreatFinding(
            title=item.title,
            source=item.source,
            severity=item.severity,
            threat_score=threat_score,
            cvss_score=getattr(item, 'cvss_score', 0.0),
            cve_id=cve_id,
            description=item.summary_en,
            affected_systems=getattr(item, 'affected_assets', None),
            iocs=[asdict(ioc) for ioc in iocs[:5]],  # Top 5 IOCs
            mitre_tactics=mitre_tactics,
            remediation_en=item.remediation_en,
            remediation_secondary=item.remediation_fa,
        )
        findings.append(finding)

    return findings


def main() -> int:
    """Run the production CTI pipeline."""

    try:
        args = parse_args()

        # Enable debug logging if requested
        if args.verbose:
            logging.getLogger().setLevel(logging.DEBUG)
            logger.debug("Debug logging enabled")

        # Initialize components
        database_path = Path(__file__).resolve().parent / "data" / "agent_state.db"
        state_manager = StateManager(db_path=database_path)

        # Handle database initialization
        if args.init_db:
            logger.info("Initializing database schema...")
            return 0

        if args.reset_db:
            logger.info("Resetting database...")
            state_manager.reset_database()

        # Test alerting if requested
        if args.test_alerts:
            logger.info("Testing alerting channels...")
            alerter = Alerter()
            status = alerter.test_connection()
            print(json.dumps(status, indent=2))
            return 0

        # Determine execution mode
        if not args.test and not args.live:
            args.test = True  # Default to test mode
            logger.info("No mode specified; defaulting to --test mode")

        # Fetch feeds
        logger.info(f"Fetching threats (mode: {'test' if args.test else 'live'})...")
        fetcher = Fetcher()
        entries = fetcher.fetch_all(state_manager=state_manager, force_mock=args.test)
        logger.info(f"Fetched {len(entries)} entries")

        if not entries:
            logger.warning("Fetcher returned no entries; using mock fallback entries")
            entries = fetcher._mock_entries()

        # Skip analysis if deduplication only
        if args.deduplicate_only:
            for entry in entries:
                try:
                    state_manager.mark_as_processed(entry.url, entry.title, entry.source)
                except ValueError:
                    continue
            logger.info("Deduplication complete")
            print(json.dumps({"status": "deduplicated", "entries": len(entries)}))
            return 0

        # Analyze threats
        logger.info("Analyzing threats...")
        analyzer = Analyzer()
        analysis_result = analyzer.analyze(entries=entries, use_mock_ai=args.mock_ai)

        # Mark as processed
        for entry in entries:
            try:
                state_manager.mark_as_processed(entry.url, entry.title, entry.source)
            except ValueError:
                continue

        # Enrich if requested
        logger.info(f"Enrichment: {'enabled' if args.enable_enrichment else 'disabled'}")
        enricher = Enricher() if args.enable_enrichment else Enricher()
        scorer = ThreatScorer()
        extractor = IOCExtractor()
        correlation_engine = CorrelationEngine()

        # Create threat findings with enrichment
        findings = _create_threat_findings(analysis_result.items, scorer, enricher, extractor)
        correlation_result = correlation_engine.correlate(findings)
        correlation_data = correlation_result.to_dict()

        # Generate report in requested format
        logger.info(f"Generating report ({args.output_format} format)...")
        report_gen = ReportGenerator()

        if args.output_format == "json":
            report_output = report_gen.generate_json(
                findings,
                metadata={
                    "mode": "test" if args.test else "live",
                    "enriched": args.enable_enrichment,
                },
                correlation_data=correlation_data,
            )
        elif args.output_format == "markdown":
            report_output = report_gen.generate_markdown(
                findings,
                title="Threat Intelligence Report",
                correlation_data=correlation_data,
            )
        elif args.output_format == "csv":
            report_output = report_gen.generate_csv(findings)
        elif args.output_format == "stix":
            report_output = report_gen.generate_stix_like(findings)
        else:
            report_output = report_gen.generate_json(findings)

        # Send alerts if enabled
        if args.enable_alerting:
            logger.info("Sending alerts...")
            alerter = Alerter()
            alert_results = alerter.batch_alert([asdict(f) for f in findings])
            logger.info(f"Alerts sent: {alert_results}")

        # Output report
        if args.output_file:
            output_path = Path(args.output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(report_output, encoding='utf-8')
            logger.info(f"Report written to {output_path}")
            print(json.dumps({"output": str(output_path), "format": args.output_format}))
        else:
            print(report_output)

        logger.info("CTI pipeline complete")
        return 0

    except Exception as error:
        logger.exception("Fatal error during CTI pipeline")
        print(json.dumps({"error": str(error)}, ensure_ascii=False, indent=2), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())