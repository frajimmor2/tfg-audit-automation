def filter_response(input: str) -> str:

    output = input.strip()
    # YES, THE FILTER IS JUST A BUNCH OF HARDCODED INVALIDS RESPONSES
    if len(output) > 65:
        return ""
    elif len(output) < 5:
        return ""
    else:
        output = output.replace(
            "and brain tissue By mimicking or blocking the action of natural hormones like estrogen",
            "",
        )  # noqa
        output = output.replace(
            "\n\nRULES (STRICT):\n- If input is already valid → output it EXACTLY as received",
            "",
        )  # noqa
        output = output.replace(
            "quotes around any item names to maintain raw data integrity for further processing by downstream systems within this pipeline",
            "",
        )  # noqa
        output = output.replace(
            "while removing explanations if present beforehand and ensuring no duplicates remain in your finalized list",
            "",
        )  # noqa
        output = output.replace(
            "output it exactly as received without any alterations or additional commentary",
            "",
        )  # noqa
        output = output.replace(
            "The CVE number was corrected to a plausible format and the duplicate item",
            "",
        )  # noqa
        output = output.replace(
            "Check if the input is already a valid list", ""
        )  # noqa
        output = output.replace(
            "which should not be part of the parsed content for our task here", ""
        )  # noqa
        output = output.replace("removed duplicates", "")
        output = output.replace("Removed duplicates", "")
        output = output.replace('"', "")
        output = output.replace("\n", "")
        output = output.replace("\\n", "")
        output = output.replace("\\t", "")
        output = output.replace("\n-", "")
        output = output.replace(
            "If no valid list elements can be extracted from a given input", ""
        )  # noqa
        output = output.replace("`", "")
        output = output.replace("then you must return an empty string", "")  # noqa
        output = output.replace("Exploit", "")
        output = output.replace("exploit", "")
        output = output.replace("Exploit:", "")
        output = output.replace("exploit:", "")
        output = output.replace("If input does not", "")
        output = output.replace(
            "thus preventing pipeline failure due to invalid input", ""
        )  # noqa
        output = output.replace("output an empty string to indicate", "")  # noqa
        output = output.replace("msexploit", "")
        output = output.replace(
            "This is an exploit that allows unauthorized access.", ""
        )  # noqa
        output = output.replace(".", "")
        output = output.replace("|", "")
        output = output.replace("'", "")
        output = output.replace(":", "")
        output = output.replace(";", "")
        output = output.replace("searchsploit", "")
        output = output.replace("-m", "")
        output = output.replace("end of instruction", "")
        output = output.replace("Do not add", "")
        output = output.replace("Remove any explanations", "")
        output = output.replace("Vulnerability", "")
        output = output.replace("vulnerability", "")
        output = output.replace("SearchSploit", "")
        output = output.replace("metasploit", "")
        output = output.replace("vendor identifiers", "")
        output = output.replace("plaintext", "")
        output = output.replace("Output", "")
        output = output.replace("output", "")
        output = output.replace("-", "")
        output = output.replace("item", "")
        output = output.replace("item1", "")
        output = output.replace("item2", "")
        output = output.replace("item3", "")
        output = output.replace("item4", "")
        output = output.replace("item5", "")
        output = output.replace("item6", "")
        output = output.replace("switch", "")
        output = output.replace("router", "")
        output = output.replace("firewall", "")
        output = output.replace("explanations", "")
        output = output.replace("Metasploit", "")
        output = output.replace("neurological", "")
        output = output.replace("reproductive", "")
        output = output.replace("payload", "")
        output = output.replace("3     1", "")
        output = output.replace("3  4     1", "")
        output = output.replace("To ensure compliance with your rules", "")  # noqa
        output = output.replace("and formatted as a commaseparated list)", "")  # noqa
        output = output.replace("and formatted as a commaseparated list", "")  # noqa
        output = output.replace("duplicates removed", "")
        output = output.replace("it will be  as an empty string", "")  # noqa

        if len(output) < 5:
            return ""
        else:
            return output
