import typer

"""
INPUT: dict[target]:[("exploit","CVE")]
"""


def execution(input: dict) -> None:
    targets = list(input.keys())
    for target in targets:

        metasploit_queue = set()
        searchsploit_queue = set()
        
        # TODO: thread execution this for
        for selected in input[target]:
            try:
                # execution = execute_exploit_m(selected[0])
                # if check_execution(execution):
                #       if selected[1]:
                #           metasploit_queue.add(selected)
                # TODO: Manage not having CVE
                print("linter fix")

            except Exception as e:
                msg = f"There was a problem executing f{selected[0]}"
                typer.secho(msg, fg=typer.colors.RED, err=True)
                typer.secho(f"Error: {e}", fg=typer.colors.RED, err=True)

            try:
                # execution = execute_exploit_s(selected[0])
                # if check_execution(execution):
                #       if selectec[1]:
                #           searchsploit_queue.add(selected)
                # TODO: Manage not having CVE
                print("linter fix")

            except Exception as e:
                msg = f"There was a problem executing f{selected[0]}"
                typer.secho(msg, fg=typer.colors.RED, err=True)
                typer.secho(f"Error: {e}", fg=typer.colors.RED, err=True)

        for exec in metasploit_queue:
            # insert_execution(exec, target)
            pass
        for exec in searchsploit_queue:
            # insert_execution(exec, target)
            pass
