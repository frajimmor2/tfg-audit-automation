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
        other_info = input_info[target][2]
        target_id = get_target_id(target)

        for soft in input_info[target][1]:
            obs = False  # Data_obs_analyzer(soft)
            # Store the info
            insert_software(target_id, soft, obs)

        for vuln in input_info[target][3]:
            desc = "lorem_ipsum"  # CVE_descriptor
            insert_vulnerability(target_id, vuln, desc)

        output[target] = exploits 


    return output
