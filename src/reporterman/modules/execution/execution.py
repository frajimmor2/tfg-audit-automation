from reporterman.modules.execution.script_executor import (
    manage_execution,
)

"""
INPUT: dict[target]:[("exploit","CVE")]
"""


def execution(input: dict) -> None:
    targets = list(input.keys())
    lhost = "TODO: GET MY IP"
    model_drift = 0

    for target in targets:

        queue = dict()
        """
        queue: dict[exploit]:[attemp] -> attemp = (payload:str, success:bool)
        """

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

        # Insert results info in db
        exploits = list(queue.keys)
        for exploit in exploits:
            # insert_exploit(target, cve, exploit)
            attemps = queue[exploit]
            for attemp in attemps:
                # insert_attemp(exploit, attemp)
                print("linter fix")

    # insert_model_drift(model_drift)
