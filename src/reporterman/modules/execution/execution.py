from reporterman.modules.execution.script_executor import (
    manage_execution,
    get_local_ip,
)
from reporterman.database.database import (
    insert_exploit,
    get_vulnerability_id,
    insert_attemp,
    insert_llm_stats,
)

"""
INPUT: dict[target]:[("exploit","CVE")]
"""


def execution(input: dict) -> None:
    targets = list(input.keys())
    lhost = get_local_ip()
    exploit_suggested = 0
    model_drift = 0

    for target in targets:

        queue = dict()
        # queue: dict[exploit]:[attemp] ->
        # attemp = (payload:str, success:bool, cve: str)

        for selected in input[target]:
            queue, model_drift = manage_execution(
                selected, model_drift, queue, "n", target, lhost
            )  # noqa
            queue, model_drift = manage_execution(
                selected, model_drift, queue, "0", target, lhost
            )  # noqa
            queue, model_drift = manage_execution(
                selected, model_drift, queue, "1", target, lhost
            )  # noqa
            exploit_suggested += 3

        # Insert results info in db
        exploits = list(queue.keys)
        for exploit in exploits:
            attemps = queue[exploit]
            vuln_id = get_vulnerability_id(target, attemps[0][2])
            insert_exploit(vuln_id, exploit)  # Store info

            for attemp in attemps:
                insert_attemp(target, exploit, attemp)  # Store info

    fail_rate = (model_drift / exploit_suggested) * 100
    insert_llm_stats(model_drift, exploit_suggested, fail_rate)
