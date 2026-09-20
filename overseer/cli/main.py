import typer
from rich.console import Console
from rich.table import Table

from overseer.collector.base import SourceAdapter
from overseer.collector.cisa_ics import CISAICSAdapter
from overseer.notifier.report import generate_report
from overseer.parser.normalize import normalize
from overseer.storage import db

app = typer.Typer(name="overseer", help="OverSeer: advisory collection, normalization, and notification tool.")
console = Console()

ADAPTERS: list[SourceAdapter] = [CISAICSAdapter()]
DEFAULT_REPORTS_DIR = "reports/"


def _run_pipeline(adapters: list[SourceAdapter], output_dir: str = DEFAULT_REPORTS_DIR) -> dict[str, int]:
    """Fetch -> normalize -> dedup -> store -> report, across all given adapters.

    Assumes db.init_db() has already been called. Pulled out of the `run`
    command so it can be driven directly in tests with fixture adapters,
    an in-memory db, and a tmp_path output dir.
    """
    counts = {
        "total_fetched": 0,
        "filtered_out": 0,
        "needs_review": 0,
        "new_reports": 0,
        "duplicates_skipped": 0,
    }

    for adapter in adapters:
        raw_advisories = adapter.fetch()
        counts["total_fetched"] += len(raw_advisories)

        for raw in raw_advisories:
            advisory = normalize(raw)
            if advisory is None:
                counts["filtered_out"] += 1
                continue

            if advisory.needs_review:
                counts["needs_review"] += 1

            if db.is_duplicate(advisory.unique_id):
                counts["duplicates_skipped"] += 1
                continue

            db.insert_advisory(advisory)
            generate_report(advisory, output_dir=output_dir)
            counts["new_reports"] += 1

    return counts


def _print_summary(counts: dict[str, int]) -> None:
    table = Table(title="OverSeer Run Summary")
    table.add_column("Metric", style="bold")
    table.add_column("Count", justify="right")

    table.add_row("Total Fetched", str(counts["total_fetched"]))
    table.add_row("Filtered Out (severity < 7)", str(counts["filtered_out"]))
    table.add_row("Needs Review (no CVSS)", str(counts["needs_review"]))
    table.add_row("New Reports Written", str(counts["new_reports"]))
    table.add_row("Duplicates Skipped", str(counts["duplicates_skipped"]))

    console.print(table)


@app.command()
def run() -> None:
    """Fetch, normalize, dedup, store, and report on advisories from all registered sources."""
    db.init_db(db.DEFAULT_DB_PATH)
    counts = _run_pipeline(ADAPTERS, output_dir=DEFAULT_REPORTS_DIR)
    _print_summary(counts)


@app.command()
def config() -> None:
    """View or edit OverSeer configuration (stub)."""
    console.print("[yellow]overseer config: not yet implemented[/yellow]")


@app.command()
def history() -> None:
    """View previously collected advisories (stub)."""
    console.print("[yellow]overseer history: not yet implemented[/yellow]")


if __name__ == "__main__":
    app()
