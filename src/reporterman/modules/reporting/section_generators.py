from datetime import date
from jinja2 import Environment
from pathlib import Path
from reporterman.database.database import (
        get_n_targets,
        get_n_software,
        get_n_vuln,
        get_n_exploited_vuln,
)


assets_path = Path(__file__).parent / "assets"


def generate_frontpage(env: Environment) -> str:

    logo_file = assets_path / "logo.png"
    logo_path_formatted = logo_file.resolve().as_uri()

    template = env.get_template("frontpage.html")
    html = template.render(
            date=str(date.today()),
            logo_path=logo_path_formatted)
    return html


def generate_executive_summary(env: Environment, exec_time: int) -> str:

    # Get data
    n_targets = get_n_targets()
    n_soft = get_n_software()
    n_vuln = get_n_vuln()
    n_exploited_vuln = get_n_exploited_vuln()

    template = env.get_template("executive_summary.html")
    html = template.render(
            date=str(date.today()),
            exec_time=exec_time,
            targets=n_targets,
            soft=n_soft,
            vuln=n_vuln,
            exploited=n_exploited_vuln)
    return html
