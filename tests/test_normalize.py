from overseer.collector.base import RawAdvisory
from overseer.parser.normalize import normalize

# Fixtures mimic the messy, HTML-laden prose actually found in CISA ICS
# advisory RSS <description> text -- not clean structured data.

HIGH_SEVERITY_SUMMARY = (
    "<p>1. EXECUTIVE SUMMARY</p>"
    "<ul>"
    "<li>CVSS v3.1 9.8</li>"
    "<li>ATTENTION: Exploitable remotely/low attack complexity</li>"
    "<li>Vendor: Acme Corp</li>"
    "<li>Equipment: Widget Controller</li>"
    "<li>Vulnerability: Improper Input Validation</li>"
    "</ul>"
    "<p>2. RISK EVALUATION</p>"
    "<p>Successful exploitation of this vulnerability could allow an attacker to "
    "execute arbitrary code. CVSS v3.1 base score of 9.8 has been calculated; the "
    "CVSS vector string is (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).</p>"
)

LOW_SEVERITY_SUMMARY = (
    "<p>1. EXECUTIVE SUMMARY</p>"
    "<ul>"
    "<li>CVSS v3.1 5.3</li>"
    "<li>ATTENTION: Exploitable from adjacent network</li>"
    "<li>Vendor: Beta Systems</li>"
    "<li>Equipment: PLC Module</li>"
    "<li>Vulnerability: Missing Authentication for Critical Function</li>"
    "</ul>"
    "<p>2. RISK EVALUATION</p>"
    "<p>Successful exploitation could allow an attacker to read configuration data. "
    "CVSS v3.1 base score of 5.3 has been calculated; the CVSS vector string is "
    "(AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N).</p>"
)

NO_CVSS_SUMMARY = (
    "<p>1. EXECUTIVE SUMMARY</p>"
    "<ul>"
    "<li>ATTENTION: Update pending vendor review</li>"
    "<li>Vendor: Gamma Industrial</li>"
    "<li>Equipment: Flow Meter Gateway</li>"
    "<li>Vulnerability: Use of Hard-coded Credentials</li>"
    "</ul>"
    "<p>2. RISK EVALUATION</p>"
    "<p>CISA is aware of a public report affecting the Gamma Industrial Flow Meter "
    "Gateway. No further technical details or a CVSS score are available at this "
    "time; a fix is pending vendor confirmation.</p>"
)


def make_raw(unique_id, title_suffix, summary, **overrides):
    fields = dict(
        source_name="CISA ICS",
        raw_id=f"https://www.cisa.gov/news-events/ics-advisories/{unique_id.lower()}",
        raw_title=f"{unique_id} {title_suffix}",
        raw_summary=summary,
        raw_published="Thu, 18 Sep 2026 12:00:00 +0000",
        raw_link=f"https://www.cisa.gov/news-events/ics-advisories/{unique_id.lower()}",
        extra={},
    )
    fields.update(overrides)
    return RawAdvisory(**fields)


def test_high_cvss_is_kept_as_valid_advisory():
    raw = make_raw("ICSA-26-263-01", "Acme Widget Controller", HIGH_SEVERITY_SUMMARY)

    advisory = normalize(raw)

    assert advisory is not None
    assert advisory.unique_id == "ICSA-26-263-01"
    assert advisory.oem_name == "Acme"
    assert advisory.product_name == "Widget Controller"
    assert advisory.severity == "Critical"
    assert advisory.needs_review is False
    assert str(advisory.source_url) == raw.raw_link
    assert advisory.product_version == "NA"
    assert advisory.mitigation == "N/A - Pending Vendor Patch"


def test_low_cvss_is_filtered_out():
    raw = make_raw("ICSA-26-262-05", "Beta Systems PLC Module", LOW_SEVERITY_SUMMARY)

    advisory = normalize(raw)

    assert advisory is None


def test_missing_cvss_is_routed_to_manual_review():
    raw = make_raw("ICSA-26-261-09", "Gamma Industrial Flow Meter Gateway", NO_CVSS_SUMMARY)

    advisory = normalize(raw)

    assert advisory is not None
    assert advisory.severity == "UNSCORED - Manual Review"
    assert advisory.needs_review is True
    assert advisory.unique_id == "ICSA-26-261-09"
