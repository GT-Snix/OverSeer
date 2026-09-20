from datetime import datetime, timezone
from pathlib import Path

from overseer.notifier.report import generate_report
from overseer.parser.schema import Advisory


def make_advisory(**overrides) -> Advisory:
    fields = dict(
        product_name="Widget Controller",
        product_version="2.1",
        oem_name="Acme",
        severity="Critical",
        unique_id="ICSA-26-263-01",
        description="An attacker could execute arbitrary code via crafted network packets.",
        mitigation="Update to firmware version 2.2 or later.",
        published_date=datetime(2026, 9, 18, 12, 0, 0, tzinfo=timezone.utc),
        source_url="https://www.cisa.gov/news-events/ics-advisories/icsa-26-263-01",
    )
    fields.update(overrides)
    return Advisory(**fields)


def expected_content(advisory: Advisory) -> str:
    return (
        f"# [PATCH ANALYSIS] {advisory.unique_id} | {advisory.severity} Severity\n"
        "\n"
        "## 1. Vulnerability Metadata\n"
        f"* **Product Name:** {advisory.product_name}\n"
        f"* **Product Version:** {advisory.product_version}\n"
        f"* **OEM Name:** {advisory.oem_name}\n"
        f"* **Severity Level:** {advisory.severity}\n"
        f"* **Unique ID:** {advisory.unique_id}\n"
        f"* **Published Date:** {advisory.published_date.isoformat()}\n"
        "\n"
        "## 2. Technical Breakdown\n"
        f"{advisory.description}\n"
        "\n"
        "## 3. Mitigation Strategy\n"
        f"{advisory.mitigation}\n"
    )


def test_critical_advisory_produces_exact_template_structure(tmp_path):
    advisory = make_advisory()

    report_path = generate_report(advisory, output_dir=str(tmp_path))

    assert report_path.read_text(encoding="utf-8") == expected_content(advisory)


def test_needs_review_advisory_still_generates_correctly(tmp_path):
    advisory = make_advisory(
        unique_id="ICSA-26-261-09",
        severity="UNSCORED - Manual Review",
        needs_review=True,
        description="No further technical details or a CVSS score are available at this time.",
    )

    report_path = generate_report(advisory, output_dir=str(tmp_path))

    content = report_path.read_text(encoding="utf-8")
    assert content == expected_content(advisory)
    assert "UNSCORED - Manual Review" in content
    assert "* **Severity Level:** UNSCORED - Manual Review" in content


def test_output_dir_is_created_if_missing(tmp_path):
    advisory = make_advisory()
    nested_dir = tmp_path / "does" / "not" / "exist"
    assert not nested_dir.exists()

    report_path = generate_report(advisory, output_dir=str(nested_dir))

    assert nested_dir.exists()
    assert report_path.exists()


def test_filename_matches_unique_id_pattern(tmp_path):
    advisory = make_advisory(unique_id="ICSA-26-263-01")

    report_path = generate_report(advisory, output_dir=str(tmp_path))

    assert report_path.name == "ICSA-26-263-01_Patch_Analysis.md"
    assert report_path.parent == Path(tmp_path)
