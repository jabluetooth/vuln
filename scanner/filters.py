import os
import logging
import requests

logger = logging.getLogger(__name__)


def _load_set(env_var: str) -> set[str]:
    """Parse a comma-separated env var into a lower-cased set."""
    raw = os.environ.get(env_var, "").strip()
    if not raw:
        return set()
    return {item.strip().lower() for item in raw.split(",") if item.strip()}


# Loaded once at import time so the sets are available globally
PACKAGE_DENYLIST: set[str] = _load_set("PACKAGE_DENYLIST")
CVE_DENYLIST:     set[str] = _load_set("CVE_DENYLIST")
CVSS_THRESHOLD:   float    = float(os.environ.get("CVSS_THRESHOLD", "0"))  # 0 = disabled


def is_package_allowed(package_name: str) -> bool:
    """Return False if the package appears in PACKAGE_DENYLIST."""
    if package_name.lower() in PACKAGE_DENYLIST:
        logger.info("Skipping denied package: %s", package_name)
        return False
    return True


def filter_vulns(vulns: list[dict]) -> list[dict]:
    """Remove vulns whose CVE IDs are deny-listed or whose CVSS score is below threshold."""
    filtered = []
    for v in vulns:
        cve_id = v.get("id", "")
        if cve_id.lower() in CVE_DENYLIST:
            logger.info("Skipping denied CVE: %s", cve_id)
            continue
        if CVSS_THRESHOLD > 0:
            score = _get_cvss_score(v)
            if score is not None and score < CVSS_THRESHOLD:
                logger.info(
                    "Skipping %s (CVSS %.1f < threshold %.1f)",
                    cve_id, score, CVSS_THRESHOLD,
                )
                continue
        filtered.append(v)
    return filtered


def _get_cvss_score(vuln: dict) -> float | None:
    """Extract the highest CVSS score from OSV severity data."""
    best: float | None = None
    for sev in vuln.get("severity", []):
        if sev.get("type") in ("CVSS_V3", "CVSS_V2"):
            raw = sev.get("score", "")
            score = _parse_score(raw)
            if score is not None and (best is None or score > best):
                best = score
    return best


def _parse_score(raw: str) -> float | None:
    """Try to parse a plain float or extract the base score from a CVSS vector string."""
    try:
        return float(raw)
    except ValueError:
        pass
    # CVSS vector strings end with the base score after the last "/"
    # e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" → no score embedded
    # OSV sometimes uses "score" as just the numeric value; this is a best-effort fallback
    for part in reversed(raw.split("/")):
        try:
            return float(part)
        except ValueError:
            continue
    return None


def get_dependabot_packages(repo: str, token: str, gh_api_url: str = "https://api.github.com") -> set[str]:
    """Return package names that already have an open Dependabot PR so we can skip them."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    }
    covered: set[str] = set()
    try:
        r = requests.get(
            f"{gh_api_url}/repos/{repo}/pulls",
            headers=headers,
            params={"state": "open", "per_page": "100"},
            timeout=10,
        )
        if r.status_code != 200:
            logger.warning("Could not fetch open PRs for Dependabot check: %d", r.status_code)
            return covered
        for pr in r.json():
            user = pr.get("user", {}).get("login", "")
            if "dependabot" not in user.lower():
                continue
            # Typical title: "Bump requests from 2.31.0 to 2.33.0"
            title = pr.get("title", "").lower()
            if title.startswith("bump "):
                parts = title.split()
                if len(parts) >= 2:
                    covered.add(parts[1])
    except requests.RequestException as e:
        logger.warning("Could not fetch Dependabot PRs: %s", e)
    return covered
