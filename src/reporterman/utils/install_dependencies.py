import subprocess
import typer


# List of commands that will install all the dependencies
CMDs = []
CMDs.append(["apt", "update", "-y"])
CMDs.append(["apt-get", "install", "-y", "iputils-ping"])
CMDs.append(["apt", "install", "-y", "nmap"])


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
