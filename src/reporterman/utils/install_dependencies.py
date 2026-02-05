import subprocess
import typer
from importlib.resources import files

soft_obs_path = files("reporterman.utils.llms") / "soft_obs_analyzer"

# List of commands that will install all the dependencies
CMDs = []
CMDs.append(["apt", "update", "-y"])
CMDs.append(["apt-get", "install", "-y", "iputils-ping"])
CMDs.append(["apt", "install", "-y", "nmap"])
CMDs.append(["snap", "install", "ollama"])
CMDs.append(["ollama", "create", "soft_obs_analzer", "-f", f"{soft_obs_path}"])


def install_dependency(cmd: list[str]) -> None:
    try:
        subprocess.run(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )  # noqa
    except Exception as e:
        typer.secho(
            f"There was a problem installing {cmd}",
            fg=typer.colors.RED,
            err=True,  # noqa
        )
        typer.secho(f"Error: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)


def set_up_dependencies() -> None:

    for cmd in CMDs:
        install_dependency(cmd)
