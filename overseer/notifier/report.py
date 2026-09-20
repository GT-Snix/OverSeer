from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from overseer.parser.schema import Advisory

TEMPLATE_DIR = Path(__file__).parent / "templates"
TEMPLATE_NAME = "report.md.j2"

_env = Environment(
    loader=FileSystemLoader(TEMPLATE_DIR),
    autoescape=False,
    trim_blocks=True,
    lstrip_blocks=True,
    keep_trailing_newline=True,
)


def generate_report(advisory: Advisory, output_dir: str = "reports/") -> Path:
    """Render an advisory to a Markdown patch-analysis report and write it to disk.

    Pure "advisory in, markdown file out": no storage lookups, no dedup
    logic. Callers are responsible for checking storage.is_duplicate()
    before calling this.
    """
    template = _env.get_template(TEMPLATE_NAME)
    content = template.render(
        product_name=advisory.product_name,
        product_version=advisory.product_version,
        oem_name=advisory.oem_name,
        severity=advisory.severity,
        unique_id=advisory.unique_id,
        published_date=advisory.published_date.isoformat(),
        description=advisory.description,
        mitigation=advisory.mitigation,
    )

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    report_path = output_path / f"{advisory.unique_id}_Patch_Analysis.md"
    report_path.write_text(content, encoding="utf-8")

    return report_path
