from datetime import date
from jinja2 import Environment, FileSystemLoader
from pathlib import Path


assets_path = Path(__file__).parent / "assets"


def generate_frontpage(env: Environment) -> str:

    logo_file = assets_path / "logo.png"
    logo_path_formatted = logo_file.resolve().as_uri()

    template = env.get_template("frontpage.html")
    html = template.render(date=str(date.today()),
                           logo_path=logo_path_formatted)
    return html
