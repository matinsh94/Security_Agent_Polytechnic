import tempfile
from pathlib import Path
import pytest
from scripts.state_manager import StateManager


@pytest.fixture
def temp_state_manager():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_agent_state.db"
        manager = StateManager(db_path=db_path)
        yield manager


def test_state_manager_init_and_mark_processed(temp_state_manager):
    sm = temp_state_manager
    assert sm.is_processed("https://example.com/article1", "Article One", "CVE-2024-0001") is False

    article_id = sm.mark_as_processed("https://example.com/article1", "Article One", "FeedA", "CVE-2024-0001")
    assert article_id > 0
    assert sm.is_processed("https://example.com/article1", "Article One", "CVE-2024-0001") is True

    # Duplicate should raise ValueError
    with pytest.raises(ValueError, match="already exists"):
        sm.mark_as_processed("https://example.com/article1", "Article One", "FeedA", "CVE-2024-0001")


def test_state_manager_vulnerabilities(temp_state_manager):
    sm = temp_state_manager
    sm.store_vulnerability(
        cve_id="CVE-2024-1111",
        cvss_score=9.5,
        severity="CRITICAL",
        description="Remote code execution vulnerability.",
    )
    vulns = sm.get_vulnerabilities()
    assert len(vulns) == 1
    assert vulns[0]["cve_id"] == "CVE-2024-1111"
    assert vulns[0]["cvss_base_score"] == 9.5
    assert vulns[0]["nist_severity"] == "CRITICAL"


def test_state_manager_iocs(temp_state_manager):
    sm = temp_state_manager
    sm.store_ioc("ipv4", "198.51.100.1", source_article_id=1, confidence=0.95)
    sm.store_ioc("ipv4", "198.51.100.2", source_article_id=1, confidence=0.90)
    sm.store_ioc("cve", "CVE-2024-1111", source_article_id=1, confidence=0.99)

    ips = sm.get_iocs_by_type("ipv4")
    assert len(ips) == 2
    assert {ip["value"] for ip in ips} == {"198.51.100.1", "198.51.100.2"}

    cves = sm.get_iocs_by_type("cve")
    assert len(cves) == 1
    assert cves[0]["value"] == "CVE-2024-1111"


def test_state_manager_threat_analysis(temp_state_manager):
    sm = temp_state_manager
    sm.store_threat_analysis(
        article_id=1,
        cve_id="CVE-2024-2222",
        threat_score=85,
        severity="high",
        attack_vector="network",
        affected_assets=["web-server", "database"],
        remediation_en="Apply security patch immediately.",
    )

    analysis = sm.get_threat_analysis_by_cve("CVE-2024-2222")
    assert analysis is not None
    assert analysis["threat_score"] == 85
    assert analysis["severity"] == "high"
    assert "web-server" in analysis["affected_assets"]


def test_state_manager_correlation_clusters(temp_state_manager):
    sm = temp_state_manager
    sm.store_correlation_cluster(
        campaign_id="campaign-12345",
        related_cves=["CVE-2024-1111", "CVE-2024-2222"],
        risk_score=80,
        explanation="Shared C2 infrastructure",
        finding_titles=["Threat A", "Threat B"],
    )

    clusters = sm.get_correlation_clusters()
    assert len(clusters) == 1
    assert clusters[0]["campaign_id"] == "campaign-12345"
    assert clusters[0]["risk_score"] == 80
    assert clusters[0]["related_cves"] == ["CVE-2024-1111", "CVE-2024-2222"]
    assert clusters[0]["finding_titles"] == ["Threat A", "Threat B"]


def test_state_manager_historical_context(temp_state_manager):
    sm = temp_state_manager
    data = {"last_scan": "2026-10-25", "total_threats": 42}
    sm.store_historical_context("scan_metadata", data)

    loaded = sm.get_historical_context("scan_metadata")
    assert loaded == data
    assert sm.get_historical_context("non_existent_key") is None


def test_state_manager_reset(temp_state_manager):
    sm = temp_state_manager
    sm.mark_as_processed("https://example.com/item", "Item")
    sm.store_vulnerability("CVE-2024-9999", 8.0, "HIGH", "Test")
    sm.store_ioc("ipv4", "192.0.2.1")
    sm.store_historical_context("key1", "val1")

    sm.reset_database()
    assert sm.get_stats()["total_processed"] == 0
    assert len(sm.get_vulnerabilities()) == 0
    assert len(sm.get_iocs_by_type("ipv4")) == 0
    assert sm.get_historical_context("key1") is None
