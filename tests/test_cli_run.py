from overseer.cli.main import _run_pipeline
from overseer.collector.cisa_ics import CISAICSAdapter
from overseer.storage import db
from tests.test_cisa_ics import SAMPLE_FEED_XML


def test_pipeline_counts_and_reports_on_disk(tmp_path):
    db.init_db(":memory:")
    adapter = CISAICSAdapter(feed_url=SAMPLE_FEED_XML)

    counts = _run_pipeline([adapter], output_dir=str(tmp_path))

    # Both fixture entries have no CVSS info in their summary text, so
    # they're neither filtered out nor dropped -- they're kept as
    # needs_review advisories.
    assert counts == {
        "total_fetched": 2,
        "filtered_out": 0,
        "needs_review": 2,
        "new_reports": 2,
        "duplicates_skipped": 0,
    }

    report_files = sorted(p.name for p in tmp_path.glob("*.md"))
    assert report_files == [
        "ICSA-26-262-05_Patch_Analysis.md",
        "ICSA-26-263-01_Patch_Analysis.md",
    ]
    for name in report_files:
        assert (tmp_path / name).read_text(encoding="utf-8").strip()


def test_pipeline_run_twice_produces_zero_duplicate_reports(tmp_path):
    db.init_db(":memory:")
    adapter = CISAICSAdapter(feed_url=SAMPLE_FEED_XML)

    first_counts = _run_pipeline([adapter], output_dir=str(tmp_path))
    assert first_counts["new_reports"] == 2
    assert first_counts["duplicates_skipped"] == 0

    report_paths_before = sorted(tmp_path.glob("*.md"))
    assert len(report_paths_before) == 2
    mtimes_before = {p.name: p.stat().st_mtime_ns for p in report_paths_before}

    second_counts = _run_pipeline([adapter], output_dir=str(tmp_path))

    assert second_counts["total_fetched"] == 2
    assert second_counts["filtered_out"] == 0
    assert second_counts["needs_review"] == 2
    assert second_counts["new_reports"] == 0
    assert second_counts["duplicates_skipped"] == 2

    report_paths_after = sorted(tmp_path.glob("*.md"))
    assert len(report_paths_after) == 2
    mtimes_after = {p.name: p.stat().st_mtime_ns for p in report_paths_after}
    assert mtimes_before == mtimes_after
