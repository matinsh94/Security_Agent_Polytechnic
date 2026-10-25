from scripts.ioc_extractor import IOCExtractor


def test_ioc_filters_file_extensions_from_domains():
    extractor = IOCExtractor()
    text = (
        "The attack executed setup.py and payload.exe, then dropped run.sh and library.dll. "
        "It then communicated with c2-master.darkthreat.org."
    )
    iocs = extractor.extract(text)
    domains = [ioc.value for ioc in iocs if ioc.ioc_type == "domain"]

    assert "setup.py" not in domains
    assert "payload.exe" not in domains
    assert "run.sh" not in domains
    assert "library.dll" not in domains
    assert "c2-master.darkthreat.org" in domains


def test_ioc_extracts_real_domains_and_ips():
    extractor = IOCExtractor()
    text = "Indicators: 8.8.8.8, malicious-api.attacker.net, https://download.threat.org/stage2"
    iocs = extractor.extract(text)

    types = {ioc.ioc_type for ioc in iocs}
    values = {ioc.value for ioc in iocs}

    assert "ipv4" in types
    assert "domain" in types
    assert "url" in types
    assert "8.8.8.8" in values
    assert "malicious-api.attacker.net" in values
