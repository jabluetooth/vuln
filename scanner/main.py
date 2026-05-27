import os
import sys
import subprocess
sys.path.insert(0, os.path.dirname(__file__))

from dotenv import load_dotenv
load_dotenv()

from dependency_parser import get_all_packages
from osv_client import check_vulnerabilities, get_safe_version, get_severity
from llm_explainer import explain_vulnerability
from patcher import bump_version_in_file, git_setup, create_branch_and_commit, create_pull_request

# ── Config ──────────────────────────────────────────────────────────────────
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
REPO_NAME = os.environ.get("REPO_NAME")  # e.g. "your-username/your-repo"

# Only patch vulnerabilities at or above this severity
# Options: LOW, MODERATE, HIGH, CRITICAL
MIN_SEVERITY = os.environ.get("MIN_SEVERITY", "HIGH")

SEVERITY_RANK = {"LOW": 1, "MODERATE": 2, "HIGH": 3, "CRITICAL": 4, "UNKNOWN": 0}
# ────────────────────────────────────────────────────────────────────────────


def should_patch(severity: str) -> bool:
    return SEVERITY_RANK.get(severity.upper(), 0) >= SEVERITY_RANK.get(MIN_SEVERITY, 3)


def main():
    if not GITHUB_TOKEN or not REPO_NAME:
        print("[ERROR] GITHUB_TOKEN and REPO_NAME environment variables are required.")
        return

    print(f"[SCAN] Starting vulnerability scan for {REPO_NAME}...")
    print(f"[CONFIG] MIN_SEVERITY = {MIN_SEVERITY}")
    packages = get_all_packages()

    if not packages:
        print("[INFO] No packages found to scan.")
        return

    print(f"[SCAN] Found {len(packages)} packages. Checking OSV database...")

    git_setup()
    patched_count = 0

    for pkg in packages:
        vulns = check_vulnerabilities(pkg)
        if not vulns:
            continue

        print(f"[VULN] {pkg['name']}@{pkg['version']} — {len(vulns)} vulnerability(s) found")

        # Pick the single highest safe version across all CVEs for this package
        best_vuln = None
        best_version = None
        for vuln in vulns:
            safe_version = get_safe_version(vuln)
            severity = get_severity(vuln)
            if not safe_version or not should_patch(severity):
                continue
            if best_version is None or safe_version > best_version:
                best_version = safe_version
                best_vuln = vuln

        if not best_vuln:
            print(f"  [SKIP] No patchable vulnerabilities above threshold.")
            continue

        severity = get_severity(best_vuln)
        cve_id = best_vuln.get("id", "UNKNOWN")
        print(f"  [FIX] {cve_id} ({severity}): {pkg['name']} → v{best_version}")

        # Generate AI explanation
        explanation = explain_vulnerability(pkg["name"], best_vuln, best_version)

        # Create branch name
        branch = f"fix/vuln-{pkg['name']}-{best_version}".replace(".", "-").lower()

        # Patch the dependency file
        bump_version_in_file(pkg["source_file"], pkg["name"], pkg["version"], best_version)

        # Commit and push — skip if branch already exists
        if not create_branch_and_commit(branch, pkg["source_file"], pkg["name"], best_version):
            subprocess.run(["git", "checkout", "main"], check=False)
            continue

        # Open PR
        title = f"Security Fix: {pkg['name']} {pkg['version']} → {best_version} [{severity}]"
        create_pull_request(
            repo=REPO_NAME,
            branch_name=branch,
            title=title,
            body=explanation,
            token=GITHUB_TOKEN
        )

        patched_count += 1

    print(f"\n[DONE] Scan complete. {patched_count} patch PR(s) opened.")


if __name__ == "__main__":
    main()
