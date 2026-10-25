from scripts.analyzer import Analyzer, AnalysisResult
from scripts.fetcher import FeedEntry


def test_analyzer_empty_entries():
    analyzer = Analyzer(api_key=None)
    result = analyzer.analyze([], use_mock_ai=True)
    assert isinstance(result, AnalysisResult)
    assert result.total_items == 0
    assert len(result.items) == 0


def test_analyzer_mock_mode_produces_structured_output():
    analyzer = Analyzer(api_key=None)
    entries = [
        FeedEntry(
            title="Critical Zero-Day in Windows Kernel (CVE-2026-1122)",
            url="https://example.com/advisory1",
            summary="An unauthenticated attacker can execute code via kernel RPC vulnerability.",
            source="Test Feed",
            published_at="2026-10-25T00:00:00Z",
        ),
        FeedEntry(
            title="Linux Ransomware Attack Wave",
            url="https://example.com/advisory2",
            summary="Ransomware encrypts database directories on Linux hosts.",
            source="Test Feed",
            published_at="2026-10-25T00:00:00Z",
        ),
    ]

    result = analyzer.analyze(entries, use_mock_ai=True)
    assert isinstance(result, AnalysisResult)
    assert result.total_items == 2
    assert result.used_mock_ai is True
    assert len(result.items) == 2

    first = result.items[0]
    assert first.title == entries[0].title
    assert first.severity in {"low", "medium", "high", "critical"}
    assert 0.0 <= first.cvss_score <= 10.0
    assert first.remediation_en != ""

    second = result.items[1]
    assert second.severity in {"low", "medium", "high", "critical"}
    assert "ransomware" in second.vulnerability_type.lower() or "intrusion" in second.summary_en.lower()


def test_analyzer_fallback_on_network_failure():
    # Provide a dummy key and invalid base URL to trigger request failure
    analyzer = Analyzer(api_key="fake-key", base_url="http://127.0.0.1:1/chat/completions", timeout=1)
    entry = FeedEntry(
        title="Web Server RCE Advisory",
        url="https://example.com/advisory3",
        summary="Remote code execution in public web gateway.",
        source="Test Feed",
        published_at="2026-10-25T00:00:00Z",
    )
    result = analyzer.analyze([entry], use_mock_ai=False)
    # Must gracefully fall back to mock analysis instead of raising uncaught exception
    assert result.total_items == 1
    assert result.used_mock_ai is True
