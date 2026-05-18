"""CLI entrypoint for the cybersecurity threat intelligence agent."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import asdict
from pathlib import Path

from scripts.analyzer import Analyzer
from scripts.fetcher import Fetcher
from scripts.state_manager import StateManager


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""

    parser = argparse.ArgumentParser(description="AI-Powered Cyber Threat Intelligence Agent")
    parser.add_argument("--test", action="store_true", help="Force synthetic feed data for deterministic runs")
    parser.add_argument("--mock-ai", action="store_true", help="Use mock AI analysis instead of DeepSeek API")
    parser.add_argument("--reset-db", action="store_true", help="Clear stored processed state before fetching")
    return parser.parse_args()


def _severity_breakdown(findings: list[dict[str, object]]) -> dict[str, int]:
    counter = Counter()
    for finding in findings:
        counter[str(finding.get("severity", "unknown")).lower()] += 1
    return dict(sorted(counter.items()))


def main() -> int:
    """Run the fetch -> analyze -> store pipeline and print JSON results."""

    try:
        args = parse_args()

        database_path = Path(__file__).resolve().parent / "data" / "agent_state.db"
        state_manager = StateManager(db_path=database_path)

        if args.reset_db:
            state_manager.reset_database()

        fetcher = Fetcher()
        analyzer = Analyzer()

        entries = fetcher.fetch_all(state_manager=state_manager, force_mock=args.test)
        analysis_result = analyzer.analyze(entries=entries, use_mock_ai=args.mock_ai)

        for entry in entries:
            try:
                state_manager.mark_as_processed(entry.url, entry.title, entry.source)
            except ValueError:
                continue

        findings = [asdict(item) for item in analysis_result.items]
        payload = {
            "generated_at": analysis_result.generated_at,
            "provider": analysis_result.provider,
            "mode": {
                "test": args.test,
                "mock_ai": args.mock_ai,
                "reset_db": args.reset_db,
            },
            "database": state_manager.get_stats(),
            "statistics": {
                "articles_fetched": len(entries),
                "articles_analyzed": analysis_result.total_items,
                "severity_breakdown": _severity_breakdown(findings),
            },
            "summary_en": analysis_result.summary_en,
            "summary_fa": analysis_result.summary_fa,
            "findings": findings,
        }

        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0
    except Exception as error:
        print(json.dumps({"error": str(error)}, ensure_ascii=False, indent=2), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())