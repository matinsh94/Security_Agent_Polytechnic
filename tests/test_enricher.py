from scripts.enricher import Enricher


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class _FakeSession:
    def __init__(self):
        self.calls = []

    def get(self, url, params=None, timeout=None):
        self.calls.append((url, params, timeout))
        if "known_exploited_vulnerabilities" in url:
            return _FakeResponse({"vulnerabilities": [{"cveID": "CVE-2024-12345"}]})
        return _FakeResponse(
            {
                "vulnerabilities": [
                    {
                        "cve": {
                            "published": "2024-01-01T00:00:00.000",
                            "descriptions": [{"lang": "en", "value": "Remote code execution in a web service."}],
                            "metrics": {
                                "cvssMetricV31": [
                                    {"cvssData": {"baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}
                                ]
                            },
                        }
                    }
                ]
            }
        )


def test_enricher_uses_cache_and_parses_nvd_payload():
    enricher = Enricher(session=_FakeSession())

    info = enricher.enrich_cve("CVE-2024-12345")

    assert info is not None
    assert info.cve_id == "CVE-2024-12345"
    assert info.cvss_score == 9.8
    assert info.nist_severity == "CRITICAL"
    assert enricher.check_kev("CVE-2024-12345") is True


def test_enricher_returns_none_for_invalid_cve():
    enricher = Enricher(session=_FakeSession())

    assert enricher.enrich_cve("not-a-cve") is None