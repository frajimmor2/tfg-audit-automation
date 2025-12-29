import subprocess
import typer
from concurrent.futures import ThreadPoolExecutor, as_completed


def check_connectivity(target: str) -> bool:
    cmd = ["ping", "-c", "4", "-w", "2000", target]
    try:
        output = subprocess.run(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True  # noqa
        )
        return output.returncode == 0  # 0 means there wasn't any errors
    except Exception as e:
        print(f"Error: {e}")
        return False


def nmap_scan(cmd: list[str]) -> str:
    try:
        output = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            stdin=subprocess.DEVNULL,
        )
        stdout, _ = output.communicate()
        return stdout
    except Exception as e:
        msg = f"There was a problem connecting to {cmd[-1]}"
        typer.secho(msg, fg=typer.colors.RED, err=True)
        typer.secho(f"Error: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)


def os_scan(target: str) -> list:
    cmd = ["nmap", "-sV", "-O", target]
    scan_output = nmap_scan(cmd)
    # Filter the output
    listed_scan = scan_output.split("\n")
    # CPE Values: 0 = vendor 1 = product 2 = version 3 = other
    vendor = product = version = other = ""
    for line in listed_scan:
        match line:
            case _ if "OS CPE:" in line:
                parts = line.split(":")
                vendor = parts[3]
                product = parts[4]
                version = parts[5]
            case _ if ("OS details:" in line) or ("Service Info:" in line):
                if other != "":
                    other = other + " " + line
                else:
                    other = line
            case _:
                pass
    output_cpe = [vendor, product, version, other]
    return output_cpe


def get_ports_scan(target: str) -> str:
    cmd = ["nmap", "--open", "-p-", "--min-rate", "5000", "-n", "-Pn", target]
    output = nmap_scan(cmd)
    output_ports = ""
    for line in output.split("\n"):
        if line.count("/") == 1:
            port_info = line.split("/")
            port = port_info[0]
            output_ports = output_ports + port + ","
        else:
            pass
    return output_ports[:-1]


def version_scan_cpe_parser(scan_results: list[str]) -> list:
    output_cpe = []  # CPE list
    other = ""
    current_cpe = None
    for line in scan_results:
        # Is port
        if line and line[0].isdigit() and ("/tcp" in line or "/udp" in line):
            if current_cpe:
                output_cpe.append(current_cpe)
                other = ""
            info = line.split()
            s_product = info[2]
            s_version = " ".join(info[3:]) if len(info) > 3 else ""
            s_port = info[0]
            other = ""
            current_cpe = [s_product, s_version, other, s_port]
        # End of last port
        elif current_cpe and line.startswith("MAC Address:"):
            output_cpe.append(current_cpe)
            current_cpe = None
            other = line
        # Port info
        elif current_cpe:
            other = other + " " + line
            current_cpe[2] = other
        # End of the scan
        elif line.startswith("Service detection performed"):
            break
        else:
            other = other + " " + line
    return [output_cpe, other]


def version_scan(target: str, ports: str) -> list:
    cmd = ["nmap", f"-p{ports}", "-sVC", target]
    raw_output = nmap_scan(cmd)
    output = version_scan_cpe_parser(raw_output.split("\n"))
    return output


def vulns_scan_parser(scan_results: list[str]) -> list:
    output = []
    for line in scan_results:
        try:
            info = line.split()
            cond1 = info[0] == "|"
            cond2 = info[1].startswith("CVE")
            cond3 = info[3].startswith("http")
            if cond1 and cond2 and cond3:
                cve = info[1]
                link = info[3]
                output.append([cve, link])
        except Exception:
            pass
    return output


def vuln_scan(target: str, ports: str) -> list:
    cmd = ["nmap", "-sVC", f"-p{ports}", "--script", "vulners", target]
    raw_output = nmap_scan(cmd)
    output = vulns_scan_parser(raw_output.split("\n"))
    return output


def single_ip_scan(
    target: str, ports: str, single_exec: bool = True
) -> dict[str, list]:  # noqa
    if check_connectivity(target):
        # From now is supposed that the connection will be ok
        # but it would raise an err anyways if there is a problem
        output = dict()
        target_scan_results = []
        # Add every scan result
        target_scan_results.append(os_scan(target))  # OS cpe
        if not ports:
            ports = get_ports_scan(target)

        version_scan_results = version_scan(target, ports)

        target_scan_results.append(version_scan_results[0])  # Services cpe
        target_scan_results.append(version_scan_results[1])  # Other
        list_cve = vuln_scan(target, ports)
        target_scan_results.append(list_cve)  # Detected vulnerabilities
        output[target] = target_scan_results
        return output
    else:
        typer.secho(
            f"Couldn't connect to {target}", fg=typer.colors.RED, err=True
        )  # noqa
        if single_exec:
            raise typer.Exit(1)


def list_ip_scan(targets: str, ports: str) -> dict[str, list]:
    output = dict()

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {
            executor.submit(single_ip_scan, target, ports, False): target
            for target in targets
        }
        for future in as_completed(futures):
            try:
                output.update(future.result())
                print("Finished scan")
            except Exception as e:
                typer.secho(f"Couldn't add a target to the output dict")  # noqa
                typer.secho(
                    f"Error processing a scan output: {e}",
                    fg=typer.colors.RED,
                    err=True,
                )  # noqa
    return output
