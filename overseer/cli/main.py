import typer
from rich.console import Console

app = typer.Typer(name="overseer", help="OverSeer: advisory collection, normalization, and notification tool.")
console = Console()


@app.command()
def run() -> None:
    """Run a collection cycle (stub)."""
    console.print("[yellow]overseer run: not yet implemented[/yellow]")


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
