import typer
from typing_extensions import Annotated
from reporterman.input_validations import (
    mode_validation,
    target_validation,
    ports_validation,
)


app = typer.Typer()


@app.command()
def run(
    target: Annotated[
        str,
        typer.Argument(
            help="The target must be an IP direction, \
                    IP domain or a list of IPs"
        ),
    ],
    mode: Annotated[
        int,
        typer.Option(
            "-m",
            "-mode",
            "--mode",
            help=(
                "The mode options specifies which \
                    target type will be processed.\n"
                "mode == 0: single IP\n"
                "mode == 1: IP domain\n"
                "mode == 2: list of IPs\n"
            ),
            callback=mode_validation,
        ),
    ] = 0,
    ports: Annotated[
        str,
        typer.Option(
            "-p",
            "-ports",
            "--ports",
            help="List of the ports that will be audited. \
                        It applies to each system in the modes 1 and 2",
        ),
    ] = "",
):
    target_validation(target, mode)
    ports_validation(ports)
    print("Running")


@app.command("setModels")
def setModels():
    print("Installing all the ollama models")


if __name__ == "__main__":
    app()
