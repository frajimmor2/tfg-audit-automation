from reporterman.database.database import (
    get_target_id,
    insert_vulnerability,
)
from reporterman.modules.data_analysis.data_analysis import get_cve_description
from pathlib import Path
import subprocess
import typer
import socket

BASE_DIR = Path(__file__).resolve().parent
exec_m_path = BASE_DIR / "exec_m.sh"
exec_m_0_path = BASE_DIR / "exec_m_0.sh"
exec_m_1_path = BASE_DIR / "exec_m_1.sh"
get_cve_path = BASE_DIR / "get_cve.sh"


def execute_exploit(
    script_path: str, exploit: str, target: str, lhost: str
) -> str:  # noqa
    cmd = [script_path, exploit, target, lhost]
    # This function will be wrapped by a try statement
    output = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        stdin=subprocess.DEVNULL,
    )
    stdout, _ = output.communicate()
    return stdout


def execute_np(exploit: str, target: str, lhost: str) -> str:
    output = execute_exploit(exec_m_path, exploit, target, lhost)
    return output


def execute_p0(exploit: str, target: str, lhost: str) -> str:
    output = execute_exploit(exec_m_0_path, exploit, target, lhost)
    return output


def execute_p1(exploit: str, target: str, lhost: str) -> str:
    output = execute_exploit(exec_m_1_path, exploit, target, lhost)
    return output


def check_execution(execution: str) -> str:
    try:
        exec = execution.split(",")
        return exec[0] == "1"
    except Exception:
        return False


def manage_queue(queue: dict, execution: str, cve: str) -> dict:
    executionl = execution.split(",")
    key = executionl[1]
    value = [executionl[3].strip(), executionl[2], cve]
    # payload, success, cve

    if key in queue:
        queue[key].append(value)
    else:
        queue[key] = [value]

    return queue


def get_cve(exploit: str) -> list:
    cmd = [get_cve_path, exploit]
    try:
        # This function will be wrapped by a try statement
        output = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            stdin=subprocess.DEVNULL,
        )
        stdout, _ = output.communicate()
    except Exception:
        stdout = " , "

    output = stdout.split(",")
    # output = [cve, url]
    return output


def manage_no_cve(queue: dict, execution: str, target: str) -> None:
    exec = execution.split(",")
    cve_info = get_cve(exec[1])
    if not cve_info[0]:
        cve = "CVE-0000-0000"
        cve_info[0] = cve
        desc = "This invented CVE, manages those exploits that couldn't be matched with a vulnerability."
    else:
        cve = cve_info[0]
        desc = get_cve_description(exec[0])
    target_id = get_target_id(target)
    insert_vulnerability(target_id, cve_info, desc)  # Store info
    return cve


def manage_execution(
    selected: list,
    model_drift: int,
    queue: dict,
    payload: str,
    target: str,
    lhost: str,  # noqa
) -> list:  # noqa

    out_queue = queue
    out_model_d = model_drift
    try:
        match payload:
            case "n":
                execution = execute_np(selected[0], target, lhost)
            case "0":
                execution = execute_p0(selected[0], target, lhost)
            case "1":
                execution = execute_p1(selected[0], target, lhost)
        if check_execution(execution):
            # execution = "exploit_exists, exploit_name, success, payload"
            if selected[1]:
                queue = manage_queue(queue, execution, selected[1])
            else:
                cve = manage_no_cve(queue, execution, target)
                queue = manage_queue(queue, execution, cve)

        else:
            out_model_d += 1

    except Exception as e:
        msg = f"There was a problem executing f{selected[0]}"
        typer.secho(msg, fg=typer.colors.RED, err=True)
        typer.secho(f"Error: {e}", fg=typer.colors.RED, err=True)

    return [out_queue, out_model_d]


def get_local_ip():

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()

        return ip

    except Exception:
        return "127.0.0.1"
