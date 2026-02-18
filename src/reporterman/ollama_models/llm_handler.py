import typer

"""
EACH TIME THIS IS CALLED, THE CLIENT WILL BE ALWAYS CREATED
"""


def soft_obs_handler(input: str, client) -> int:

    try:
        return int(
            client.generate(model="soft_obs_analyzer", prompt=input).response
        )  # noqa
    except Exception as e:
        typer.secho(
            f"There was a problem evaluating {input}",
            fg=typer.colors.RED,
            err=True,  # noqa
        )
        typer.secho(f"Error: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)


def soft_obs_analyzer(input: str, client) -> int:
    obs_confidence = 0
    for i in range(7):
        obs_confidence = (obs_confidence + soft_obs_handler(input, client)) / 2
    return round(obs_confidence)


def exploit_selector_soft(cpe: str, other_info: str, client) -> list:
    input = f"{cpe[3]} {cpe[0]} {cpe[1]} {cpe[2]}, other_info: {other_info}."

    try:
        return client.generate(
                model="exploit_selector_soft",
                prompt=input).response
    except Exception as e:
        typer.secho(
            f"There was a problem evaluating {input}",
            fg=typer.colors.RED,
            err=True,  # noqa
        )
        typer.secho(f"Error: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)
