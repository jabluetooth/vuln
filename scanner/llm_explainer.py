import os
import requests


def explain_vulnerability(package_name: str, vuln: dict, safe_version: str) -> str:
    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not api_key:
        raise ValueError("[ERROR] GEMINI_API_KEY secret is missing or empty.")

    vuln_summary = vuln.get("summary", "No summary available.")
    cve_id = vuln.get("id", "Unknown ID")
    severity = vuln.get("database_specific", {}).get("severity", "Unknown")
    references = vuln.get("references", [])
    ref_links = "\n".join([r.get("url", "") for r in references[:3] if r.get("url")])

    prompt = f"""A vulnerability was found in the open-source package '{package_name}'.

CVE / OSV ID: {cve_id}
Severity: {severity}
Summary: {vuln_summary}
References: {ref_links}
Recommended fix: Upgrade to version {safe_version}

Write a clear, developer-friendly GitHub Pull Request description (5-7 sentences) that:
1. Explains what the vulnerability is and what an attacker could do with it
2. Rates how serious it is in plain terms (avoid jargon)
3. Explains what this version bump fixes and why it is safe to upgrade
4. Ends with a short action line encouraging the reviewer to merge promptly

Use a professional but friendly tone. Format as plain text, no bullet points."""

    url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"gemini-2.0-flash-lite:generateContent?key={api_key}"
    )
    payload = {"contents": [{"parts": [{"text": prompt}]}]}
    response = requests.post(url, json=payload, timeout=30)
    if not response.ok:
        raise ValueError(f"Gemini API error {response.status_code}: {response.text}")
    return response.json()["candidates"][0]["content"]["parts"][0]["text"]
