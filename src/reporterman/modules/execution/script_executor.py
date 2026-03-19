from pathlib import Path
import subprocess
import typer

BASE_DIR = Path(__file__).resolve().parent
exec_m_path = BASE_DIR / "exec_m.sh"
exec_m_0_path = BASE_DIR / "exec_m_0.sh"
exec_m_1_path = BASE_DIR / "exec_m_1.sh"


def execute_exploit(
    script_path: str, exploit: str, target: str, lhost: str
) -> str:  # noqa
    cmd = [f"./{script_path}", exploit, target, lhost]
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


def manage_execution(
    selected: list, model_drift: int, queue: list, payload: str, target: str, lhost: str
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
            if selected[1]:
                queue.add(selected)
            else:
                pass
        # TODO: Manage not having CVE
        else:
            out_model_d += 1

    except Exception as e:
        msg = f"There was a problem executing f{selected[0]}"
        typer.secho(msg, fg=typer.colors.RED, err=True)
        typer.secho(f"Error: {e}", fg=typer.colors.RED, err=True)

    return [out_queue, out_model_d]
