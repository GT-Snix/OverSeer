import httpx
import pytest

from overseer.collector.cisco import CiscoAdapter
from overseer.parser.normalize import normalize

# A static snapshot of Cisco PSIRT openVuln API v2 response shape
# (GET /security/advisories/v2/all). Used via httpx.MockTransport rather
# than hitting the live API or a live OAuth token endpoint -- same
# reasoning as step 3's RSS fixture: deterministic, offline, no flakiness
# from daily-changing advisory content, while still exercising the real
# request/response/parsing code paths (token fetch included).
SAMPLE_RESPONSE = {
    "advisories": [
        {
            "advisoryId": "cisco-sa-iosxe-webui-privesc-j22SaA4z",
            "advisoryTitle": "Cisco IOS XE Software Web UI Privilege Escalation Vulnerability",
            "publicationUrl": (
                "https://sec.cloudapps.cisco.com/security/center/content/"
                "CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z"
            ),
            "bugIDs": ["CSCwh87343"],
            "cves": ["CVE-2023-20198"],
            "cvrfUrl": (
                "https://sec.cloudapps.cisco.com/security/center/content/"
                "CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z/"
                "cvrf/cisco-sa-iosxe-webui-privesc-j22SaA4z_cvrf.xml"
            ),
            "cvssBaseScore": "10.0",
            "firstPublished": "2023-10-16T16:00:00",
            "lastUpdated": "2023-10-20T14:36:03",
            "productNames": ["Cisco IOS XE Software"],
            "securityImpactRating": "Critical",
            "sir": "Critical",
            "status": "Published",
            "summary": (
                "A vulnerability in the web UI feature of Cisco IOS XE Software "
                "could allow an unauthenticated, remote attacker to create an "
                "account on an affected system with privilege level 15 access."
            ),
            "version": "1.1",
        },
        {
            "advisoryId": "cisco-sa-sdwan-overlay-af7Qz9Kx",
            "advisoryTitle": "Cisco SD-WAN vManage Software Arbitrary File Overwrite Vulnerability",
            "publicationUrl": (
                "https://sec.cloudapps.cisco.com/security/center/content/"
                "CiscoSecurityAdvisory/cisco-sa-sdwan-overlay-af7Qz9Kx"
            ),
            "bugIDs": ["CSCwe12345"],
            "cves": ["CVE-2023-20252"],
            "cvrfUrl": (
                "https://sec.cloudapps.cisco.com/security/center/content/"
                "CiscoSecurityAdvisory/cisco-sa-sdwan-overlay-af7Qz9Kx/"
                "cvrf/cisco-sa-sdwan-overlay-af7Qz9Kx_cvrf.xml"
            ),
            "cvssBaseScore": "4.9",
            "firstPublished": "2023-08-16T16:00:00",
            "lastUpdated": "2023-08-16T16:00:00",
            "productNames": ["Cisco SD-WAN vManage Software"],
            "securityImpactRating": "Medium",
            "sir": "Medium",
            "status": "Published",
            "summary": (
                "A vulnerability in Cisco SD-WAN vManage Software could allow an "
                "authenticated, remote attacker to overwrite arbitrary files on "
                "the underlying operating system."
            ),
            "version": "1.0",
        },
    ]
}


def make_transport(expected_token="fake-access-token"):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "id.cisco.com":
            assert request.method == "POST"
            body = request.read().decode()
            assert "grant_type=client_credentials" in body
            assert "client_id=test-client-id" in body
            assert "client_secret=test-client-secret" in body
            return httpx.Response(200, json={"access_token": expected_token, "expires_in": 3600})

        if request.url.host == "api.cisco.com":
            assert request.headers.get("authorization") == f"Bearer {expected_token}"
            return httpx.Response(200, json=SAMPLE_RESPONSE)

        return httpx.Response(404)

    return httpx.MockTransport(handler)


def make_adapter():
    return CiscoAdapter(
        client_id="test-client-id",
        client_secret="test-client-secret",
        http_client=httpx.Client(transport=make_transport()),
    )


def test_fetch_maps_advisories_to_raw_advisory():
    adapter = make_adapter()

    results = adapter.fetch()

    assert len(results) == 2

    first = results[0]
    assert first.source_name == "Cisco PSIRT"
    assert first.raw_id == "cisco-sa-iosxe-webui-privesc-j22SaA4z"
    assert first.raw_title == "Cisco IOS XE Software Web UI Privilege Escalation Vulnerability"
    assert "web UI feature of Cisco IOS XE Software" in first.raw_summary
    assert first.raw_published == "2023-10-16T16:00:00"
    assert first.raw_link == (
        "https://sec.cloudapps.cisco.com/security/center/content/"
        "CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z"
    )

    # This is the key mapping: a clean numeric CVSS score straight from
    # the API, landing in extra["cvss_score"] -- the field normalize()
    # already checks first, before any prose parsing.
    assert first.extra["cvss_score"] == "10.0"
    assert first.extra["cves"] == ["CVE-2023-20198"]
    assert first.extra["bug_ids"] == ["CSCwh87343"]
    assert first.extra["security_impact_rating"] == "Critical"
    assert first.extra["product_names"] == ["Cisco IOS XE Software"]
    assert first.extra["status"] == "Published"
    assert first.extra["version"] == "1.1"

    second = results[1]
    assert second.raw_id == "cisco-sa-sdwan-overlay-af7Qz9Kx"
    assert second.extra["cvss_score"] == "4.9"


def test_normalize_needs_no_changes_for_cisco_mapped_advisories():
    # Proves extra["cvss_score"] alone is enough: normalize() takes the
    # clean numeric path (extra["cvss_score"]) and never touches its
    # prose-parsing fallbacks for this source.
    adapter = make_adapter()
    raw_advisories = adapter.fetch()

    critical_advisory = normalize(raw_advisories[0])
    assert critical_advisory is not None
    assert critical_advisory.severity == "Critical"
    assert critical_advisory.needs_review is False
    assert critical_advisory.unique_id == "cisco-sa-iosxe-webui-privesc-j22SaA4z"

    medium_advisory = normalize(raw_advisories[1])
    assert medium_advisory is None  # CVSS 4.9 < 7.0, filtered out


def test_fetch_missing_credentials_raises_clear_error(monkeypatch):
    monkeypatch.delenv("CISCO_CLIENT_ID", raising=False)
    monkeypatch.delenv("CISCO_CLIENT_SECRET", raising=False)

    adapter = CiscoAdapter(http_client=httpx.Client(transport=make_transport()))

    with pytest.raises(RuntimeError, match="CISCO_CLIENT_ID.*CISCO_CLIENT_SECRET"):
        adapter.fetch()


def test_credentials_read_from_environment(monkeypatch):
    monkeypatch.setenv("CISCO_CLIENT_ID", "env-client-id")
    monkeypatch.setenv("CISCO_CLIENT_SECRET", "env-client-secret")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "id.cisco.com":
            body = request.read().decode()
            assert "client_id=env-client-id" in body
            assert "client_secret=env-client-secret" in body
            return httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})
        return httpx.Response(200, json=SAMPLE_RESPONSE)

    adapter = CiscoAdapter(http_client=httpx.Client(transport=httpx.MockTransport(handler)))

    results = adapter.fetch()

    assert len(results) == 2
