import requests

OSV_API = "https://api.osv.dev/v1/query"


def check_vulnerabilities(package: dict) -> list:
    """Query the OSV API for known vulnerabilities in a package version."""
    payload = {
        "version": package["version"],
        "package": {
            "name": package["name"],
            "ecosystem": package["ecosystem"]
        }
    }
    try:
        response = requests.post(OSV_API, json=payload, timeout=10)
        if response.status_code == 200:
            return response.json().get("vulns", [])
    except requests.RequestException as e:
        print(f"[ERROR] OSV API request failed for {package['name']}: {e}")
    return []


def get_safe_version(vuln: dict) -> str | None:
    """Extract the recommended patched version from an OSV vulnerability entry."""
    for affected in vuln.get("affected", []):
        for r in affected.get("ranges", []):
            for event in r.get("events", []):
                if "fixed" in event:
                    return event["fixed"]
    return None


def get_severity(vuln: dict) -> str:
    """Extract severity level from vulnerability data."""
    return vuln.get("database_specific", {}).get("severity", "UNKNOWN")
