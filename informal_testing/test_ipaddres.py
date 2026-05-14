import ipaddress


def domain_target_formatter(target: str) -> list[str]:
    # strict=False para aceptar cualquier IP dentro de la red
    network = ipaddress.ip_network(target, strict=False)
    return [str(ip) for ip in network.hosts()]


if __name__ == "__main__":
    resultado = domain_target_formatter("192.168.0.0/30")
    print(resultado)
