import os
from datetime import date
from jinja2 import Environment, FileSystemLoader
from pathlib import Path
from weasyprint import HTML
from reporterman.database.database import (
    get_targets_ip,
)
from reporterman.modules.reporting.section_generators import (
    generate_frontpage,
    generate_executive_summary,
    generate_audit_process_explanation,
    generate_single_target_section,
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
    )

    targets = get_targets_ip()
    for target_ip in targets:
        html = html + generate_single_target_section(env, target_ip)

    HTML(string=html, base_url=templates_path).write_pdf(out_path)
