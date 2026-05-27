import os
import time
import requests


def explain_vulnerability(package_name: str, vulns: list[dict], old_version: str, safe_version: str) -> str:
    """Generate a plain-English PR description covering all CVEs being fixed."""
    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not api_key:
        raise ValueError("[ERROR] GEMINI_API_KEY secret is missing or empty.")

    # Summarise all vulns for the prompt
    vuln_lines = []
    for v in vulns[:5]:  # cap at 5 to keep prompt size reasonable
        cve_id   = v.get("id", "Unknown ID")
        summary  = v.get("summary", "No summary available.")
        severity = v.get("database_specific", {}).get("severity", "Unknown")
        vuln_lines.append(f"  - {cve_id} ({severity}): {summary}")
    vuln_block = "\n".join(vuln_lines)

    # Collect reference URLs
    refs = []
    for v in vulns[:3]:
        for r in v.get("references", [])[:2]:
            url = r.get("url", "")
            if url and url not in refs:
                refs.append(url)
    ref_block = "\n".join(refs[:4])

    count = len(vulns)
    prompt = f"""A security scan found {count} vulnerability(ies) in the open-source package '{package_name}'.

Current version: {old_version}
Safe version: {safe_version}

Vulnerabilities being fixed:
{vuln_block}

References:
{ref_block}

Write a clear, developer-friendly GitHub Pull Request description (5-7 sentences) that:
1. Summarises what the vulnerabilities are and what an attacker could do
2. Rates how serious they are in plain terms (no jargon)
3. Explains why upgrading to {safe_version} is the right fix
4. Ends with a short line encouraging the reviewer to merge promptly

Use a professional but friendly tone. Plain text only — no bullet points, no markdown headers."""

    url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"gemini-2.5-flash:generateContent?key={api_key}"
    )
    payload = {"contents": [{"parts": [{"text": prompt}]}]}

    for attempt in range(3):
        response = requests.post(url, json=payload, timeout=30)
        if response.status_code in (429, 503) and attempt < 2:
            time.sleep(15 * (attempt + 1))
            continue
        if not response.ok:
            raise ValueError(f"Gemini API error {response.status_code}: {response.text}")
        return response.json()["candidates"][0]["content"]["parts"][0]["text"]
