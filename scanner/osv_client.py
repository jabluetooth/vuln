import time
import logging
import requests
from packaging.version import Version, InvalidVersion

logger = logging.getLogger(__name__)

OSV_API = "https://api.osv.dev/v1/query"
RETRY_ATTEMPTS = 3
RETRY_BACKOFF = 2  # seconds, doubles each attempt


def check_vulnerabilities(package: dict) -> list:
    payload = {
        "version": package["version"],
        "package": {
            "name": package["name"],
            "ecosystem": package["ecosystem"]
        }
    }
    for attempt in range(RETRY_ATTEMPTS):
        try:
            response = requests.post(OSV_API, json=payload, timeout=10)
            if response.status_code == 200:
                return response.json().get("vulns", [])
            elif response.status_code in (429, 503):
                wait = RETRY_BACKOFF ** attempt
                logger.warning("OSV rate limited for %s — retrying in %ds", package["name"], wait)
                time.sleep(wait)
                continue
            else:
                logger.error("OSV returned %d for %s", response.status_code, package["name"])
                return []
        except requests.RequestException as e:
            if attempt < RETRY_ATTEMPTS - 1:
                wait = RETRY_BACKOFF ** attempt
                logger.warning("OSV request failed for %s (%s) — retrying in %ds", package["name"], e, wait)
                time.sleep(wait)
            else:
                logger.error("OSV request failed for %s after %d attempts: %s", package["name"], RETRY_ATTEMPTS, e)
    return []


def get_safe_version(vuln: dict) -> str | None:
    """Return the highest fixed version across all affected ranges."""
    best = None
    for affected in vuln.get("affected", []):
        for r in affected.get("ranges", []):
            for event in r.get("events", []):
                if "fixed" in event:
                    v = event["fixed"]
                    try:
                        if best is None or Version(v) > Version(best):
                            best = v
                    except InvalidVersion:
                        if best is None:
                            best = v
    return best


def get_severity(vuln: dict) -> str:
    return vuln.get("database_specific", {}).get("severity", "UNKNOWN")
