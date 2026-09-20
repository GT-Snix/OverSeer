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

# Reconstructed from the real CISA advisory "Digital Watchdog VMAX DVR and
# NVR Product Lineups" (icsa-26-258-01), pulled from the live feed: 6 CVEs,
# each scored in both CVSS v3.1 and v4.0. Real CVE IDs and real vector
# strings; only the connective prose is representative CISA phrasing.
# v3.1 base scores: 6.5, 9.6, 8.8, 8.8, 9.6, 6.8 (max 9.6)
# v4.0 base scores: 7.1, 9.4, 8.7, 8.7, 9.4, 7.6 (max 9.4)
# Overall max across both versions: 9.6 -> Critical.
DIGITAL_WATCHDOG_MULTI_CVE_SUMMARY = (
    "<p>1. EXECUTIVE SUMMARY</p>"
    "<p>CISA is aware of multiple vulnerabilities affecting Digital Watchdog "
    "VMAX DVR and NVR Product Lineups.</p>"
    "<p>2. RISK EVALUATION</p>"
    "<p>CVE-2026-66372 CWE-306: Missing Authentication for Critical Function. "
    "Metrics CVSS Version Base Score Base Severity Vector String "
    "3.1 6.5 MEDIUM CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N "
    "4.0 7.1 HIGH CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N</p>"
    "<p>CVE-2026-66887 CWE-78: OS Command Injection. "
    "Metrics CVSS Version Base Score Base Severity Vector String "
    "3.1 9.6 CRITICAL CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H "
    "4.0 9.4 CRITICAL CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H</p>"
    "<p>CVE-2026-66890 CWE-798: Use of Hard-coded Credentials. "
    "Metrics CVSS Version Base Score Base Severity Vector String "
    "3.1 8.8 HIGH CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H "
    "4.0 8.7 HIGH CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N</p>"
    "<p>CVE-2026-68070 CWE-79: Cross-site Scripting. "
    "Metrics CVSS Version Base Score Base Severity Vector String "
    "3.1 8.8 HIGH CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H "
    "4.0 8.7 HIGH CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N</p>"
    "<p>CVE-2026-68950 CWE-89: SQL Injection. "
    "Metrics CVSS Version Base Score Base Severity Vector String "
    "3.1 9.6 CRITICAL CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H "
    "4.0 9.4 CRITICAL CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H</p>"
    "<p>CVE-2026-68953 CWE-287: Improper Authentication. "
    "Metrics CVSS Version Base Score Base Severity Vector String "
    "3.1 6.8 MEDIUM CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N "
    "4.0 7.6 HIGH CVSS:4.0/AV:A/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N</p>"
)

# The earlier text-example advisory that has one CVE scored in both v3.1
# (MEDIUM) and v4.0 (HIGH) -- confirms the v4.0 score wins the max.
V3_MEDIUM_V4_HIGH_SUMMARY = (
    "<p>1. EXECUTIVE SUMMARY</p>"
    "<p>2. RISK EVALUATION</p>"
    "<p>Successful exploitation could allow an attacker limited access to affected "
    "functionality. Metrics CVSS Version Base Score Base Severity Vector String "
    "3.1 6.5 MEDIUM CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N "
    "4.0 7.1 HIGH CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N</p>"
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


def test_multi_cve_bundled_advisory_scored_by_max_not_first_vector():
    raw = make_raw(
        "ICSA-26-258-01",
        "Digital Watchdog VMAX DVR and NVR Product Lineups",
        DIGITAL_WATCHDOG_MULTI_CVE_SUMMARY,
    )

    advisory = normalize(raw)

    # Before the fix, this was dropped: the FIRST vector found (CVE-2026-66372,
    # v3.1) scores 6.5, below the 7.0 threshold. The advisory actually
    # bundles a 9.6 CRITICAL CVE (CVE-2026-66887 / CVE-2026-68950).
    assert advisory is not None
    assert advisory.severity == "Critical"
    assert advisory.needs_review is False


def test_v4_vector_score_wins_over_v3_for_same_cve():
    raw = make_raw(
        "ICSA-26-999-01",
        "Example Vendor Example Product",
        V3_MEDIUM_V4_HIGH_SUMMARY,
    )

    advisory = normalize(raw)

    # v3.1 alone (6.5, MEDIUM) would be filtered out. The advisory also
    # states a v4.0 score of 7.1 (HIGH) for the same CVE, which must be
    # picked up and win the max -- CVSS:4.0/ vectors were previously
    # invisible to the extractor entirely.
    assert advisory is not None
    assert advisory.severity == "High"
    assert advisory.needs_review is False


def test_unique_id_extracted_from_link_when_title_and_id_lack_it():
    # Matches the real CISA ICS feed shape: title has no ID at all, the
    # `id`/guid is a bare relative Drupal path ("/node/25507"), and the
    # ID only appears lowercase inside the link URL.
    raw = RawAdvisory(
        source_name="CISA ICS",
        raw_id="/node/25507",
        raw_title="Schneider Electric PowerChute Serial Shutdown",
        raw_summary=HIGH_SEVERITY_SUMMARY,
        raw_published="Thu, 17 Sep 2026 12:00:00 +0000",
        raw_link="https://www.cisa.gov/news-events/ics-advisories/icsa-26-260-07",
        extra={},
    )

    advisory = normalize(raw)

    assert advisory is not None
    assert advisory.unique_id == "ICSA-26-260-07"
    assert "/" not in advisory.unique_id
