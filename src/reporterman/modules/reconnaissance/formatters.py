import typer
import ipaddress


def domain_target_formatter(target: str) -> list[str]:
    try:
        # Crear el objeto de red
        network = ipaddress.ip_network(target, strict=True)
        # Devolver solo hosts válidos
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        raise typer.BadParameter(
            f"There was a problem processing {target}. \
                    You must provide a correct subnet address"
        )


def list_target_formatter(target: str) -> list[str]:
    return [ip for ip in target.split(",")]
