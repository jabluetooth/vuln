import os
import time
import logging
import requests

logger = logging.getLogger(__name__)


def explain_vulnerability(package_name: str, vulns: list[dict], old_version: str, safe_version: str) -> str:
    """Generate a plain-English PR description. Falls back to a template if Gemini is unavailable."""
    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not api_key:
        logger.warning("GEMINI_API_KEY not set — using fallback PR description.")
        return _fallback(package_name, vulns, old_version, safe_version)

    vuln_lines = []
    for v in vulns[:5]:
        cve_id   = v.get("id", "Unknown ID")
        summary  = v.get("summary", "No summary available.")
        severity = v.get("database_specific", {}).get("severity", "Unknown")
        vuln_lines.append(f"  - {cve_id} ({severity}): {summary}")

    refs = []
    for v in vulns[:3]:
        for r in v.get("references", [])[:2]:
            url = r.get("url", "")
            if url and url not in refs:
                refs.append(url)

    count = len(vulns)
    prompt = f"""A security scan found {count} vulnerability(ies) in the open-source package '{package_name}'.

Current version: {old_version}
Safe version: {safe_version}

Vulnerabilities being fixed:
{chr(10).join(vuln_lines)}

References:
{chr(10).join(refs[:4])}

Write a clear, developer-friendly GitHub Pull Request description (5-7 sentences) that:
1. Summarises what the vulnerabilities are and what an attacker could do
2. Rates how serious they are in plain terms (no jargon)
3. Explains why upgrading to {safe_version} is the right fix
4. Ends with a short line encouraging the reviewer to merge promptly

Use a professional but friendly tone. Plain text only — no bullet points, no markdown headers."""

    api_url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"gemini-2.5-flash:generateContent?key={api_key}"
    )
    payload = {"contents": [{"parts": [{"text": prompt}]}]}

    for attempt in range(3):
        try:
            response = requests.post(api_url, json=payload, timeout=30)
            if response.status_code in (429, 503) and attempt < 2:
                time.sleep(15 * (attempt + 1))
                continue
            if not response.ok:
                logger.warning(
                    "Gemini API error %d (attempt %d/3) — %s",
                    response.status_code, attempt + 1, response.text[:200],
                )
                if attempt < 2 and response.status_code not in (400, 403):
                    continue
                # Non-retryable or exhausted retries → use fallback
                return _fallback(package_name, vulns, old_version, safe_version)
            return response.json()["candidates"][0]["content"]["parts"][0]["text"]
        except requests.RequestException as e:
            logger.warning("Gemini request failed (attempt %d/3): %s", attempt + 1, e)
            if attempt == 2:
                return _fallback(package_name, vulns, old_version, safe_version)
            time.sleep(5)

    return _fallback(package_name, vulns, old_version, safe_version)


def _fallback(package_name: str, vulns: list[dict], old_version: str, safe_version: str) -> str:
    """Plain-text fallback when Gemini is unavailable."""
    count    = len(vulns)
    ids      = ", ".join(v.get("id", "?") for v in vulns[:5])
    if len(vulns) > 5:
        ids += f" and {len(vulns) - 5} more"
    severities = {v.get("database_specific", {}).get("severity", "UNKNOWN") for v in vulns}
    worst = max(severities, key=lambda s: {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "LOW": 1}.get(s, 0))

    return (
        f"This PR upgrades **{package_name}** from `{old_version}` to `{safe_version}` "
        f"to fix {count} known security vulnerability(ies) ({ids}). "
        f"The highest severity is **{worst}**. "
        f"Upgrading to `{safe_version}` resolves all listed CVEs. "
        f"Please review and merge promptly to keep dependencies secure."
    )
