from reporterman.modules.reconnaissance.formatters import (
    domain_target_formatter,
    list_target_formatter
    )
from reporterman.modules.reconnaissance.nmap_scanners import (
    single_ip_scan,
    list_ip_scan
    )


def reconnaissance(target: str, mode: int, ports: str) -> dict[str, list]:
    match mode:
        case 0:
            # Is already formatted
            output = single_ip_scan(target, ports)
        case 1:
            targets = domain_target_formatter(target)
            output = list_ip_scan(targets, ports)
        case 2:
            targets = list_target_formatter(target)
            output = list_ip_scan(targets, ports)

    '''
    OUTPUT CONTENTS EXPLAINED:
        output = Dict
        Dict[target_IP (str)] = target_info (list)
        len(target_info) == 4
        All the values are str

            target_info[0] = cpe-OS (list)
            len(cpe-OS) == 4

                cpe-OS[0] = vendor
                cpe-OS[1] = product
                cpe-OS[2] = version
                cpe-OS[3] = other

            target_info[1] = cpe-Services (list)
            // X means any number
            cpe-Servies[X] = cpe (list)

                len(cpe) == 4

                    cpe[0] = product
                    cpe[1] = version
                    cpe[2] = other
                    cpe[3] = port

            target_info[2] = other_scanned_info (str)

            target_info[3] = scanned_cve (list)
            scanned-cve[X] = cve (list)

                len(cve) == 2
                    cve[0] == cve
                    cve[1] == link
    '''
    return output
