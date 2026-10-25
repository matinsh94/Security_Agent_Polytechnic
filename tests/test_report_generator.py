import json
from scripts.report_generator import ReportGenerator, ThreatFinding


def _sample_findings():
    return [
        ThreatFinding(
            title="Critical Kernel Vulnerability",
            source="Feed A",
            severity="critical",
            threat_score=95,
            cvss_score=9.8,
            cve_id="CVE-2024-9999",
            description="Remote code execution in OS kernel.",
            affected_systems=["Linux", "Windows"],
            iocs=[{"ioc_type": "ipv4", "value": "198.51.100.1", "confidence": 0.95}],
            mitre_tactics=["Execution", "Initial Access"],
            remediation_en="Apply security patches immediately.",
        ),
        ThreatFinding(
            title="Credential Leak on Public Repo",
            source="Feed B",
            severity="medium",
            threat_score=50,
            cvss_score=5.5,
            cve_id=None,
            description="Leaked API credentials in repository.",
            affected_systems=["Cloud IAM"],
            iocs=[],
            mitre_tactics=["Credential Access"],
            remediation_en="Revoke leaked tokens.",
        ),
    ]


def test_generate_json_report():
    rg = ReportGenerator()
    findings = _sample_findings()
    output = rg.generate_json(findings, metadata={"mode": "test"})
    data = json.loads(output)

    assert data["format"] == "json"
    assert data["metadata"]["mode"] == "test"
    assert data["statistics"]["total_findings"] == 2
    assert data["statistics"]["critical_count"] == 1
    assert data["statistics"]["medium_count"] == 1
    assert "CVE-2024-9999" in data["cves"]
    assert "ipv4" in data["ioc_inventory"]


def test_generate_markdown_report():
    rg = ReportGenerator()
    findings = _sample_findings()
    md = rg.generate_markdown(findings, title="Weekly Threat Brief")

    assert "# Weekly Threat Brief" in md
    assert "## Executive Summary" in md
    assert "## Statistics" in md
    assert "CVE-2024-9999" in md
    assert "Apply security patches immediately." in md


def test_generate_csv_report():
    rg = ReportGenerator()
    findings = _sample_findings()
    csv_out = rg.generate_csv(findings)

    assert "title,severity,threat_score,cvss_score,cve_id" in csv_out
    assert "Critical Kernel Vulnerability" in csv_out
    assert "CVE-2024-9999" in csv_out


def test_generate_stix_like_report():
    rg = ReportGenerator()
    findings = _sample_findings()
    stix_json = rg.generate_stix_like(findings)
    data = json.loads(stix_json)

    assert data["type"] == "threat-report"
    assert len(data["findings"]) == 2
    assert data["findings"][0]["name"] == "Critical Kernel Vulnerability"


def test_empty_findings_handling():
    rg = ReportGenerator()
    json_out = rg.generate_json([])
    data = json.loads(json_out)
    assert data["statistics"]["total_findings"] == 0

    md_out = rg.generate_markdown([])
    assert "# Threat Intelligence Report" in md_out

    csv_out = rg.generate_csv([])
    assert "title,severity" in csv_out
