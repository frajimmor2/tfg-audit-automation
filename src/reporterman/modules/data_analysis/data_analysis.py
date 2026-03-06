from reporterman.database.database import (
    insert_target,
    get_target_id,
    insert_software,
    insert_vulnerability,
)
from reporterman.ollama_models.llm_handler import (
    soft_obs_handler,
    exploit_selector_vuln,
    exploit_selector_soft,
)
from reporterman.ollama_models.filters import (
    filter_response
)
from dotenv import load_dotenv
import os
import requests
import ollama

load_dotenv()

API_KEY = os.getenv("API_KEY")


def get_cve_data(cve_id: str):

    headers = {
        "User-Agent": "Reporterman/1.0 (Security Research Tool)",
        "apiKey": API_KEY,
    }
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    return requests.get(url, headers=headers).json()


def extract_desc(data: dict, lang="en") -> str:

    if data.get("totalResults", 0) == 0:
        return "Description not available"

    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        return "Description not avaliable"

    cve = vulnerabilities[0].get("cve", {})
    descriptions = cve.get("descriptions", [])

    for desc in descriptions:
        if desc.get("lang") == lang:
            return desc.get("value")

    return "Description not available"


def get_cve_description(cve_id: str) -> str:
    data = get_cve_data(cve_id)
    description = extract_desc(data)
    return description


def data_analysis(input_info: dict) -> dict:
    output = dict()
    targets = list(input_info.keys())
    for target in targets:

        exploits = set()
        target_info = input_info[target][0]
        insert_target(target, target_info)  # Store info
        other_info = input_info[target][2]
        target_id = get_target_id(target)
        client = ollama.Client()

        for cpe in input_info[target][1]:
            
            obs = soft_obs_handler(cpe[0]+ f" {other_info}", client)
            insert_software(target_id, cpe, obs)  # Store info
            for i in range(3):  # Ask 3 times due to the fail rate
                selected_exploits = exploit_selector_soft(cpe, other_info, client)  # noqa
                if selected_exploits:
                    for exploit in selected_exploits:
                        selected = filter_response(exploit).strip()
                        if selected:
                            exploits.add((selected, ""))

        for vuln in input_info[target][3]:
            aux_vuln = vuln
            # Add nist link
            aux_vuln[1] = (vuln[1] + f" https://nvd.nist.gov/vuln/detail/{vuln[0]}").strip()  # noqa
            desc = get_cve_description(vuln[0])
            insert_vulnerability(target_id, aux_vuln, desc)  # Store info
            for i in range(3):  # Ask 3 times due to the fail rate
                selected_exploits = exploit_selector_vuln(vuln[0], client)  # noqa
                if selected_exploits:
                    for exploit in selected_exploits:
                        selected = filter_response(exploit).strip()
                        if selected:
                            exploits.add((selected, vuln[0]))

        output[target] = exploits

    return output
