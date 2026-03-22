import os
from datetime import date
from jinja2 import Environment, FileSystemLoader
from pathlib import Path
from weasyprint import HTML
from reporterman.modules.reporting.section_generators import (
    generate_frontpage,
    generate_executive_summary,
    generate_audit_process_explanation,
)

templates_path = Path(__file__).parent / "templates"
# Jinja env
env = Environment(loader=FileSystemLoader(templates_path))


def generate_report(exec_time: int, path: str = None):
    if not path:
        path = os.getcwd()

    report_name = f"reporterman-audit-{date.today()}.pdf"
    out_path = Path(path) / report_name
    html = (
        generate_frontpage(env)
        + generate_executive_summary(env, exec_time)
        + generate_audit_process_explanation(env)
    )  # noqa
    HTML(string=html, base_url=templates_path).write_pdf(out_path)
