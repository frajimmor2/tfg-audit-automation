from reporterman.database.database import (
    insert_target,
    get_target_id,
    insert_software,
    insert_vulnerability,
)


def data_analysis(input_info: dict) -> dict:
    output = dict()
    targets = list(input_info.keys())
    for target in targets:
        # Store the info
        exploits = set()
        target_info = input_info[target][0]
        insert_target(target, target_info)
        # other_info = input_info[target][2]
        target_id = get_target_id(target)

        for cpe in input_info[target][1]:
            obs = False  # LLM: Data_obs_analyzer(soft)
            # Store the info
            insert_software(target_id, cpe, obs)
            # LLM: exploit_selector
            # exploits.append([response, ""])

        for vuln in input_info[target][3]:
            desc = "lorem_ipsum"  # LLM: cve_descriptor
            # check vuln link - else https://nvd.nist.gov/vuln/detail/{CVE}
            insert_vulnerability(target_id, vuln, desc)
            # LLM: vuln input exploit selector
            # exploits.append([response, vuln[0]])
        output[target] = exploits

    return output
