from scripts.correlation_engine import CorrelationEngine
from scripts.report_generator import ThreatFinding


def test_correlate_shared_cve():
    engine = CorrelationEngine()
    findings = [
        ThreatFinding(
            title="Finding 1: Zero-day campaign",
            source="Source A",
            severity="critical",
            threat_score=90,
            cve_id="CVE-2024-1111",
        ),
        ThreatFinding(
            title="Finding 2: Exploit tool released",
            source="Source B",
            severity="high",
            threat_score=75,
            cve_id="CVE-2024-1111",
        ),
    ]

    result = engine.correlate(findings)
    assert result.total_clusters >= 1
    cluster = result.clusters[0]
    assert "CVE-2024-1111" in cluster.cves
    assert len(cluster.finding_titles) == 2


def test_correlate_shared_iocs():
    engine = CorrelationEngine()
    findings = [
        ThreatFinding(
            title="Intrusion Wave alpha",
            source="Source A",
            severity="high",
            threat_score=70,
            iocs=[{"ioc_type": "ipv4", "value": "198.51.100.25"}],
        ),
        ThreatFinding(
            title="Ransomware deployment beta",
            source="Source B",
            severity="critical",
            threat_score=92,
            iocs=[{"ioc_type": "ipv4", "value": "198.51.100.25"}],
        ),
    ]

    result = engine.correlate(findings)
    assert result.total_clusters >= 1
    cluster = result.clusters[0]
    assert "198.51.100.25" in cluster.iocs


def test_correlate_empty_findings():
    engine = CorrelationEngine()
    result = engine.correlate([])
    assert result.total_clusters == 0
    assert result.related_findings == 0
    assert len(result.clusters) == 0


def test_correlate_no_overlap_yields_independent_cluster():
    engine = CorrelationEngine()
    findings = [
        ThreatFinding(
            title="Database vulnerability report",
            source="Source A",
            severity="low",
            threat_score=20,
            cve_id="CVE-2020-0001",
        ),
        ThreatFinding(
            title="Router firmware warning",
            source="Source B",
            severity="low",
            threat_score=25,
            cve_id="CVE-2021-9999",
        ),
    ]

    result = engine.correlate(findings)
    assert result.total_clusters == 1
    assert "No direct cross-finding correlations detected" in result.clusters[0].reason
