import typer


def mode_validation(mode: int) -> int:
    if not (mode == 0 or mode == 1 or mode == 2):
        raise typer.BadParameter("Only the modes 0, 1 or 2 are allowed")
    return mode


def valid_IP(target: str) -> None:
    if target.count(".") != 3:
        raise typer.BadParameter(
            f"{target} is not a valid IP. \
                    Provide the plain IP address, not the CIDR"
        )

    for num in target.split("."):
        try:
            n = int(num)
        except ValueError:
            raise typer.BadParameter(
                f"{target} is not a valid IP. \
                        Provide the plain IP address, not the CIDR"
            )
        if not (0 <= n <= 255):
            raise typer.BadParameter(
                f"{target} is not a valid IP. \
                        Provide the plain IP address, not the CIDR"
            )


def valid_domain(target: str) -> None:
    if not ("/" in target) or (target.count("/") != 1):
        raise typer.BadParameter(f"{target} is not a valid IP domain")
    values = target.split("/")
    valid_IP(values[0])  # Check well formed IP numeric part
    try:  # Check the CIDR suffix
        n = int(values[1])
    except ValueError:
        raise typer.BadParameter(f"{values[1]} must be a number")
    if not (0 <= n <= 32):
        raise typer.BadParameter("Invalid CIDR suffix")


def valid_IP_list(target: str) -> None:
    if "," not in target:
        raise typer.BadParameter(
            "The provided list of IP addresses must \
                    follow this pattern: IP,IP,IP,IP"
        )
    for value in target.split(","):
        valid_IP(value)


def target_validation(target: str, mode: int) -> None:
    match mode:
        case 0:
            return valid_IP(target)
        case 1:
            return valid_domain(target)
        case 2:
            return valid_IP_list(target)


def check_port(port: str) -> None:
    try:
        n = int(port)
    except ValueError:
        raise typer.BadParameter("Port must be an int value")

    if not (0 < n <= 65535):  # Check is a logic port
        raise typer.BadParameter("Invalid port number")


def ports_validation(ports: str) -> None:
    if ports != "":
        if "," not in ports:
            check_port(ports)
        else:
            s = set()
            for port in ports.split(","):
                check_port(port)
                # Check they are not duplicated
                if port not in s:
                    s.add(port)
                else:
                    raise typer.BadParameter(
                        "Please provide the ports without duplications"
                    )
