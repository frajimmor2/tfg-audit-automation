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


def exploit_selector_vuln(cve: str, client) -> list:

    try:
        response = client.generate(model="exploit_selector_vuln", prompt=cve).response  # noqa
        parsed_response = client.generate(model="llm_list_parser", prompt=response).response  # noqa
        return parsed_response
    except Exception as e:
        typer.secho(
            f"There was a problem evaluating {input}",
            fg=typer.colors.RED,
            err=True,  # noqa
        )
        typer.secho(f"Error: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)
