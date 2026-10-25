from scripts.alerter import Alerter


def test_alerter_severity_ranking():
    assert Alerter._severity_rank("critical") > Alerter._severity_rank("high")
    assert Alerter._severity_rank("high") > Alerter._severity_rank("medium")
    assert Alerter._severity_rank("medium") > Alerter._severity_rank("low")


def test_alerter_format_messages():
    crit_msg = Alerter._format_critical_message("Zero-day in hypervisor", 95, "CVE-2024-8888")
    assert "CRITICAL THREAT DETECTED" in crit_msg
    assert "CVE-2024-8888" in crit_msg
    assert "95/100" in crit_msg

    high_msg = Alerter._format_high_message("Privilege Escalation", 80, "CVE-2024-7777")
    assert "HIGH SEVERITY THREAT" in high_msg
    assert "CVE-2024-7777" in high_msg


def test_batch_alert_filtering_without_channels():
    # When no webhook or bot credentials exist in env, dispatch returns False and totals remain 0
    alerter = Alerter()
    findings = [
        {"title": "Low advisory", "severity": "low", "threat_score": 20},
        {"title": "Critical breach", "severity": "critical", "threat_score": 95},
    ]
    result = alerter.batch_alert(findings)
    assert isinstance(result, dict)
    assert result["total_sent"] == 0


def test_alerter_dispatch_mock():
    alerter = Alerter()
    # Mock dispatch method
    dispatched = []
    alerter._dispatch = lambda msg: dispatched.append(msg) or True

    findings = [
        {"title": "Ignored low", "severity": "low", "threat_score": 30},
        {"title": "High alert item", "severity": "high", "threat_score": 75},
        {"title": "Critical item", "severity": "critical", "threat_score": 95},
    ]

    result = alerter.batch_alert(findings)
    assert result["total_sent"] == 2
    assert result["critical"] == 1
    assert result["high"] == 1
    assert len(dispatched) == 2


def test_alerter_test_connection_unconfigured():
    alerter = Alerter()
    status = alerter.test_connection()
    assert status == {"telegram": False, "discord": False, "slack": False}
