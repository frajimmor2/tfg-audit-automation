from reporterman.database.database import (
    insert_target,
    get_target_id,
    insert_software,
    insert_vulnerability,
)
from dotenv import load_dotenv
import os
import requests
import hashlib

load_dotenv()

API_KEY = os.getenv("API_KEY")

def get_cve_data(cve_id: str):
 
    headers = {
        "User-Agent": "Reporterman/1.0 (Security Research Tool)",
        "apiKey": API_KEY
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
