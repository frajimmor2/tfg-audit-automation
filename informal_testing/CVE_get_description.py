import requests
import hashlib
API_KEY = "LOL NO"
URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-1284"


def safe_extract_description(data, lang="en"):
    if data.get("totalResults", 0) == 0:
        return None

    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        return None

    cve = vulnerabilities[0].get("cve", {})
    descriptions = cve.get("descriptions", [])

    for desc in descriptions:
        if desc.get("lang") == lang:
            return desc.get("value")

    return None


def get_cve(cve_id):
 
    headers = {
        "User-Agent": "Reporterman/1.0 (Security Research Tool)",
        "apiKey": API_KEY
    }
    return requests.get(URL, headers=headers)


def main():
    response = get_cve(URL)

    print("=== STATUS CODE ===")
    print(response.status_code)

    print("\n=== HEADERS ===")
    for key, value in response.headers.items():
        print(f"{key}: {value}")
    print("\n=== DATA ===")
    data = response.json()
    print(data)
    print("\n=== BODY ===")
    print(data["vulnerabilities"][0]["cve"]["descriptions"][0]["value"])


    print("\n=== GPT ===")
    print(safe_extract_description(data))
    print(hashlib.sha256(safe_extract_description(data).encode("utf-8")).hexdigest())
if __name__ == "__main__":
    main()
