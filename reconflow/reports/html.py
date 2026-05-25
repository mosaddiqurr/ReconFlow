"""HTML report generation."""

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape


def render_html_report(
    scan_id: str,
    output_path: str | Path,
    context: dict,
    template_name: str = "report_summary.html.j2",
) -> None:
    """Render an HTML report using Jinja2 template."""
    templates_dir = Path(__file__).parent / "templates"
    env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template(template_name)
    content = template.render(**context)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
