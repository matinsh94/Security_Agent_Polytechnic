from scripts.fetcher import Fetcher, FeedEntry, _FeedSource
from scripts.state_manager import StateManager
import tempfile
from pathlib import Path


def test_fetcher_url_canonicalization():
    url1 = "https://example.com/advisories/cve-2024-1234/"
    url2 = "https://example.com/advisories/cve-2024-1234"
    assert Fetcher._canonical_url(url1) == Fetcher._canonical_url(url2)


def test_fetcher_extract_cve():
    assert Fetcher._extract_cve("Critical zero-day CVE-2024-9999 reported") == "CVE-2024-9999"
    assert Fetcher._extract_cve("Non cve alert") == ""
    assert Fetcher._extract_cve("Multiple CVEs: cve-2023-1111 and cve-2023-2222") == "CVE-2023-1111"


def test_fetcher_clean_html():
    raw_html = "<p>Critical advisory <b>urgent</b> <a href='https://example.com'>link</a></p>"
    cleaned = Fetcher._clean_html(raw_html)
    assert "<" not in cleaned
    assert ">" not in cleaned
    assert "Critical advisory urgent link" in cleaned


def test_fetcher_xml_fallback_parser():
    fetcher = Fetcher()
    source = _FeedSource("Test Feed", "https://example.local/feed.xml")
    xml_data = """<?xml version="1.0" encoding="UTF-8" ?>
    <rss version="2.0">
    <channel>
        <title>Security Feed</title>
        <item>
            <title>Zero-Day Exploit Observed (CVE-2024-5555)</title>
            <link>https://example.com/advisories/5555</link>
            <description>&lt;p&gt;Active in-the-wild exploitation.&lt;/p&gt;</description>
            <pubDate>2026-10-25T12:00:00Z</pubDate>
        </item>
    </channel>
    </rss>
    """
    entries = fetcher._parse_feed_xml(source, xml_data)
    assert len(entries) == 1
    assert entries[0].title == "Zero-Day Exploit Observed (CVE-2024-5555)"
    assert "Active in-the-wild exploitation." in entries[0].summary
    assert entries[0].source == "Test Feed"


def test_fetcher_deduplication():
    e1 = FeedEntry("Title A", "https://example.com/a", "Summary", "Source", "2026-01-01")
    e2 = FeedEntry("Title A", "https://example.com/a", "Summary", "Source", "2026-01-01")
    e3 = FeedEntry("Title B", "https://example.com/b", "Summary", "Source", "2026-01-01")

    deduped = Fetcher._dedupe([e1, e2, e3])
    assert len(deduped) == 2


def test_fetcher_mock_entries_and_state():
    with tempfile.TemporaryDirectory() as tmpdir:
        sm = StateManager(db_path=Path(tmpdir) / "state.db")
        fetcher = Fetcher()

        mock_entries = fetcher.fetch_all(state_manager=sm, force_mock=True)
        assert len(mock_entries) >= 5
        assert all(isinstance(e, FeedEntry) for e in mock_entries)
