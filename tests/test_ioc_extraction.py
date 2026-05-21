from scripts.ioc_extractor import IOCExtractor


def test_extracts_common_iocs_and_normalizes_them():
    text = (
        "CVE-2024-12345 was observed with https://Example.com/path/ and 8.8.8.8. "
        "The sample hash is aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa."
    )

    extractor = IOCExtractor()
    iocs = extractor.extract(text)

    assert any(ioc.ioc_type == "cve" and ioc.value == "CVE-2024-12345" for ioc in iocs)
    assert any(ioc.ioc_type == "url" and ioc.value == "https://example.com/path" for ioc in iocs)
    assert any(ioc.ioc_type == "ipv4" and ioc.value == "8.8.8.8" for ioc in iocs)
    assert any(ioc.ioc_type == "sha256" for ioc in iocs)


def test_deduplicates_repeated_iocs():
    text = "8.8.8.8 8.8.8.8 CVE-2024-12345 CVE-2024-12345"

    extractor = IOCExtractor()
    iocs = extractor.extract(text)

    assert len([ioc for ioc in iocs if ioc.ioc_type == "ipv4"]) == 1
    assert len([ioc for ioc in iocs if ioc.ioc_type == "cve"]) == 1