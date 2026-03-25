from datetime import date
from jinja2 import Environment
from pathlib import Path
from reporterman.database.database import (
    get_n_targets,
    get_n_software,
    get_n_vuln,
    get_n_exploited_vuln,
    get_target,
    get_n_software_by_t,
    get_n_vuln_by_t,
    get_n_exploited_by_t,
    get_target_id,
    get_software,
    get_target_ports,
)

assets_path = Path(__file__).parent / "assets"


def generate_frontpage(env: Environment) -> str:

    logo_file = assets_path / "logo.png"
    logo_path_formatted = logo_file.resolve().as_uri()

    template = env.get_template("frontpage.html")
    html = template.render(
        date=str(date.today()), logo_path=logo_path_formatted
    )  # noqa
    return html


def generate_executive_summary(env: Environment, exec_time: int) -> str:

    logo_file = assets_path / "logo2.png"
    logo_path_formatted = logo_file.resolve().as_uri()

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
        exploited=n_exploited_vuln,
        logo2_path=logo_path_formatted,
    )
    return html


def generate_audit_process_explanation(env: Environment) -> str:

    logo_file = assets_path / "logo2.png"
    logo_path_formatted = logo_file.resolve().as_uri()

    template = env.get_template("audit_explanation.html")
    html = template.render(logo2_path=logo_path_formatted)
    return html


def generate_target_title(env: Environment, target_ip: str) -> str:

    logo_file = assets_path / "logo2.png"
    logo_path_formatted = logo_file.resolve().as_uri()

    # Get data
    target = get_target(target_ip)
    target_vendor = target[0]["vendor"]
    target_product = target[0]["product"]
    target_version = target[0]["version"]
    target_other_info = target[0]["other_info"]

    target_id = target[0]["id"]
    n_software = get_n_software_by_t(target_id)
    n_vuln = get_n_vuln_by_t(target_id)
    n_exploited = get_n_exploited_by_t(target_id)

    template = env.get_template("target_info.html")
    html = template.render(
        target_ip=target_ip,
        vendor=target_vendor,
        product=target_product,
        version=target_version,
        other_info=target_other_info,
        n_software=n_software,
        n_vuln=n_vuln,
        n_exploited=n_exploited,
        logo2_path=logo_path_formatted,
    )
    return html


def manage_empty(input: str) -> str:
    if input is None or input == "":
        return "Unknown"
    else:
        return input


def generate_service_info(env: Environment, target_id: int, port: str) -> str:

    logo_file = assets_path / "logo2.png"
    logo_path_formatted = logo_file.resolve().as_uri()

    # Get data
    soft = get_software(target_id, port)
    s_product = manage_empty(soft[0]["product"])
    s_version = manage_empty(soft[0]["version"])
    s_other_info = manage_empty(soft[0]["other_info"])
    obs = "No"
    if soft[0]["obsolete"]:
        obs = "Yes"

    template = env.get_template("soft_serv_info.html")
    html = template.render(
        product=s_product,
        version=s_version,
        other_info=s_other_info,
        port=port,
        obs=obs,
        logo2_path=logo_path_formatted,
    )
    return html


def generate_single_target_section(env: Environment, target_ip: str) -> str:

    html = generate_target_title(env, target_ip)
    target_id = get_target_id(target_ip)
    ports = get_target_ports(target_id)
    for port in ports:
        html = html + generate_service_info(env, target_id, port)
    return html
