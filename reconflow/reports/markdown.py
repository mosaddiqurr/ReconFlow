"""Markdown report generation."""

from pathlib import Path

from jinja2 import Environment, FileSystemLoader


def render_markdown_report(scan_id: str, output_path: str | Path, context: dict) -> None:
    """Render a markdown report using Jinja2 template."""
    templates_dir = Path(__file__).parent / "templates"
    env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template("report.md.j2")
    content = template.render(**context)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
