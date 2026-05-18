"""CLI entrypoint for the cybersecurity AI agent pipeline."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from scripts.analyzer import Analyzer
from scripts.fetcher import Fetcher
from scripts.state_manager import StateManager


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""

    parser = argparse.ArgumentParser(description="Cybersecurity AI Agent")
    parser.add_argument("--test", action="store_true", help="Force synthetic feed data for test execution")
    parser.add_argument("--mock-ai", action="store_true", help="Use mock AI analysis instead of DeepSeek API")
    parser.add_argument("--reset-db", action="store_true", help="Clear stored processed state before fetching")
    return parser.parse_args()


def main() -> int:
    """Run state -> fetch -> analyze pipeline and print structured JSON output."""

    try:
        args = parse_args()
        print("=== Cybersecurity AI Agent Initialized Successfully ===")

        database_path = Path(__file__).resolve().parent / "data" / "agent_state.db"
        state_manager = StateManager(db_path=database_path)

        if args.reset_db:
            state_manager.reset_database()

        fetcher = Fetcher()
        analyzer = Analyzer()

        entries = fetcher.fetch_all(state_manager=state_manager, force_mock=args.test)
        for entry in entries:
            try:
                state_manager.mark_as_processed(entry.url, entry.title)
            except ValueError:
                # Duplicates are expected in concurrent or repeated runs.
                continue

        analysis_result = analyzer.analyze(entries=entries, use_mock_ai=args.mock_ai)

        severity_map = {
            "critical": "Critical",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
        }
        severity_breakdown: dict[str, int] = {}
        for item in analysis_result.items:
            severity_label = severity_map.get(item.severity, item.severity.title())
            severity_breakdown[severity_label] = severity_breakdown.get(severity_label, 0) + 1

        stats = state_manager.get_stats()
        output_payload = {
            "generated_at": analysis_result.generated_at,
            "provider": "mock-ai" if analysis_result.used_mock_ai else "deepseek",
            "total_new_articles": len(entries),
            "total_analyses": analysis_result.total_items,
            "total_processed_items": stats.get("total_processed", 0),
            "severity_breakdown": severity_breakdown,
            "findings": [
                {
                    "title": item.title,
                    "source": item.source,
                    "vulnerability_type": item.vulnerability_type,
                    "severity": severity_map.get(item.severity, item.severity.title()),
                    "cvss_score": item.cvss_score,
                    "confidence": item.confidence,
                    "attack_vector": item.attack_vector,
                    "affected_assets": item.affected_assets,
                    "iocs": item.iocs,
                    "summary": item.summary,
                    "remediation": item.remediation,
                    "url": item.url,
                }
                for item in analysis_result.items
            ],
        }

        print(f"Fetched {len(entries)} new articles")
        print("Analysis Result:")
        print(json.dumps(output_payload, indent=2, ensure_ascii=False))
        return 0
    except Exception as error:
        print(f"[startup error] {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())