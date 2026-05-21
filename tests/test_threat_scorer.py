from scripts.threat_scorer import ThreatScorer


def test_scoring_escalates_kevs_and_ransomware():
    scorer = ThreatScorer()
    result = scorer.score_threat(
        title="Ransomware campaign targets public services",
        description="A public exploit is available and the vulnerability is listed in CISA KEV.",
        cvss_score=8.5,
        has_public_exploit=True,
        is_in_kev=True,
        is_ransomware=True,
        is_mass_exploitation=True,
    )

    assert result.score >= 90
    assert result.severity == "critical"
    assert "CISA KEV listed" in result.reasons


def test_scoring_classifies_low_risk_items():
    scorer = ThreatScorer()
    result = scorer.score_threat(
        title="Advisory with minimal impact",
        description="Limited exposure and no evidence of exploitation.",
        cvss_score=2.0,
    )

    assert result.score < 50
    assert result.severity == "low"