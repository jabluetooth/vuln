import os
import sys
import subprocess
import logging

sys.path.insert(0, os.path.dirname(__file__))

from dotenv import load_dotenv
load_dotenv()

from dependency_parser import get_all_packages
from osv_client import check_vulnerabilities, get_safe_version, get_severity
from llm_explainer import explain_vulnerability
from patcher import bump_version_in_file, git_setup, create_branch_and_commit, create_pull_request, DEFAULT_BRANCH

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)

# ── Config ───────────────────────────────────────────────────────────────────
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
REPO_NAME = os.environ.get("REPO_NAME")

VALID_SEVERITIES = {"LOW", "MODERATE", "HIGH", "CRITICAL"}
MIN_SEVERITY = os.environ.get("MIN_SEVERITY", "HIGH").upper()
MAX_PRS_PER_RUN = int(os.environ.get("MAX_PRS_PER_RUN", "10"))

SEVERITY_RANK = {"LOW": 1, "MODERATE": 2, "HIGH": 3, "CRITICAL": 4, "UNKNOWN": 0}
# ─────────────────────────────────────────────────────────────────────────────


def validate_config():
    if not GITHUB_TOKEN or not REPO_NAME:
        logger.error("GITHUB_TOKEN and REPO_NAME environment variables are required.")
        return False
    if MIN_SEVERITY not in VALID_SEVERITIES:
        logger.error("Invalid MIN_SEVERITY '%s'. Must be one of: %s", MIN_SEVERITY, ", ".join(VALID_SEVERITIES))
        return False
    return True


def should_patch(severity: str) -> bool:
    return SEVERITY_RANK.get(severity.upper(), 0) >= SEVERITY_RANK.get(MIN_SEVERITY, 3)


def main():
    if not validate_config():
        sys.exit(1)

    logger.info("Starting vulnerability scan for %s", REPO_NAME)
    logger.info("MIN_SEVERITY = %s | MAX_PRS_PER_RUN = %d | DEFAULT_BRANCH = %s",
                MIN_SEVERITY, MAX_PRS_PER_RUN, DEFAULT_BRANCH)

    packages = get_all_packages()
    if not packages:
        logger.info("No packages found to scan.")
        return

    logger.info("Found %d package(s). Checking OSV database...", len(packages))
    git_setup()
    patched_count = 0

    for pkg in packages:
        if patched_count >= MAX_PRS_PER_RUN:
            logger.warning("Reached MAX_PRS_PER_RUN limit (%d). Stopping.", MAX_PRS_PER_RUN)
            break

        vulns = check_vulnerabilities(pkg)
        if not vulns:
            continue

        logger.info("%s@%s — %d vulnerability(s) found", pkg["name"], pkg["version"], len(vulns))

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
            logger.info("  No patchable vulnerabilities above threshold for %s.", pkg["name"])
            continue

        severity = get_severity(best_vuln)
        cve_id = best_vuln.get("id", "UNKNOWN")
        logger.info("  Fixing %s (%s): %s → v%s", cve_id, severity, pkg["name"], best_version)

        explanation = explain_vulnerability(pkg["name"], best_vuln, best_version)
        branch = f"fix/vuln-{pkg['name']}-{best_version}".replace(".", "-").lower()

        bump_version_in_file(pkg["source_file"], pkg["name"], pkg["version"], best_version)

        if not create_branch_and_commit(branch, pkg["source_file"], pkg["name"], best_version):
            subprocess.run(["git", "checkout", DEFAULT_BRANCH], check=False)
            continue

        title = f"Security Fix: {pkg['name']} {pkg['version']} → {best_version} [{severity}]"
        create_pull_request(
            repo=REPO_NAME,
            branch_name=branch,
            title=title,
            body=explanation,
            token=GITHUB_TOKEN
        )

        subprocess.run(["git", "checkout", DEFAULT_BRANCH], check=False)
        patched_count += 1

    logger.info("Scan complete. %d patch PR(s) opened.", patched_count)


if __name__ == "__main__":
    main()
