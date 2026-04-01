from pyfiglet import Figlet
from colorama import Fore, Style
import typer


def banner() -> None:

    f = Figlet(font="slant")
    banner = f.renderText("reporterman")
    print(Fore.YELLOW + banner + Style.RESET_ALL)


def show_msg(msg: str) -> None:

    typer.secho(msg, fg=typer.colors.CYAN)
