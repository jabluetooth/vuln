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
from patcher import (
    bump_version_in_file,
    git_setup,
    create_branch_and_commit,
    create_pull_request,
    get_default_branch,
    is_patch_bump,
    SEVERITY_LABELS,
)

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
GITHUB_TOKEN     = os.environ.get("GITHUB_TOKEN")
REPO_NAME        = os.environ.get("REPO_NAME")
MIN_SEVERITY     = os.environ.get("MIN_SEVERITY", "HIGH").upper()
MAX_PRS_PER_RUN  = int(os.environ.get("MAX_PRS_PER_RUN", "10"))
AUTO_MERGE_PATCH = os.environ.get("AUTO_MERGE_PATCH", "false").lower() == "true"

# Comma-separated GitHub usernames, e.g. "alice,bob"
PR_REVIEWERS = [r.strip() for r in os.environ.get("PR_REVIEWERS", "").split(",") if r.strip()]

# Comma-separated label names always added to every PR
_extra_labels   = [l.strip() for l in os.environ.get("PR_LABELS", "security,dependencies").split(",") if l.strip()]

VALID_SEVERITIES = {"LOW", "MODERATE", "HIGH", "CRITICAL"}
SEVERITY_RANK    = {"LOW": 1, "MODERATE": 2, "HIGH": 3, "CRITICAL": 4, "UNKNOWN": 0}
# ─────────────────────────────────────────────────────────────────────────────


def validate_config() -> bool:
    if not GITHUB_TOKEN or not REPO_NAME:
        logger.error("GITHUB_TOKEN and REPO_NAME environment variables are required.")
        return False
    if MIN_SEVERITY not in VALID_SEVERITIES:
        logger.error("Invalid MIN_SEVERITY '%s'. Must be one of: %s", MIN_SEVERITY, ", ".join(VALID_SEVERITIES))
        return False
    return True


def should_patch(severity: str) -> bool:
    return SEVERITY_RANK.get(severity.upper(), 0) >= SEVERITY_RANK.get(MIN_SEVERITY, 3)


def _advisory_url(cve_id: str) -> str:
    if cve_id.upper().startswith("GHSA-"):
        return f"https://github.com/advisories/{cve_id}"
    return f"https://osv.dev/vulnerability/{cve_id}"


def build_pr_body(
    ai_explanation: str,
    fixable_vulns: list[dict],
    package_name: str,
    old_version: str,
    new_version: str,
    source_file: str,
) -> str:
    """Compose the full PR body: AI explanation + CVE table + diff preview."""
    # CVE table
    rows = []
    for v in fixable_vulns:
        cve_id   = v.get("id", "UNKNOWN")
        severity = v.get("database_specific", {}).get("severity", "UNKNOWN")
        url      = _advisory_url(cve_id)
        rows.append(f"| [{cve_id}]({url}) | {severity} |")
    cve_table = (
        "**Vulnerabilities Fixed:**\n\n"
        "| CVE / OSV ID | Severity |\n"
        "|---|---|\n"
        + "\n".join(rows)
    )

    # Diff preview
    filename = os.path.basename(source_file)
    diff_preview = (
        f"**Diff Preview (`{filename}`):**\n\n"
        f"```diff\n"
        f"- {package_name}=={old_version}\n"
        f"+ {package_name}=={new_version}\n"
        f"```"
    )

    return f"{ai_explanation}\n\n---\n\n{cve_table}\n\n{diff_preview}"


def main():
    if not validate_config():
        sys.exit(1)

    # Auto-detect the repo's actual default branch
    default_branch = get_default_branch(REPO_NAME, GITHUB_TOKEN)

    logger.info("Starting vulnerability scan for %s", REPO_NAME)
    logger.info("MIN_SEVERITY=%s | MAX_PRS=%d | DEFAULT_BRANCH=%s | AUTO_MERGE_PATCH=%s",
                MIN_SEVERITY, MAX_PRS_PER_RUN, default_branch, AUTO_MERGE_PATCH)

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

        # Collect all fixable vulns and find the highest safe version
        fixable_vulns = []
        best_version  = None
        for vuln in vulns:
            safe_version = get_safe_version(vuln)
            severity     = get_severity(vuln)
            if not safe_version or not should_patch(severity):
                continue
            fixable_vulns.append(vuln)
            if best_version is None or safe_version > best_version:
                best_version = safe_version

        if not fixable_vulns or not best_version:
            logger.info("  No patchable vulnerabilities above threshold for %s.", pkg["name"])
            continue

        # Use severity of the worst vuln for labelling
        worst_severity = max(
            (get_severity(v) for v in fixable_vulns),
            key=lambda s: SEVERITY_RANK.get(s.upper(), 0)
        )
        logger.info("  Fixing %d CVE(s) in %s: %s → %s [%s]",
                    len(fixable_vulns), pkg["name"], pkg["version"], best_version, worst_severity)

        # Build label list: base labels + severity label
        severity_label_name = SEVERITY_LABELS.get(worst_severity.upper(), {}).get("name")
        label_names = list(_extra_labels)
        if severity_label_name and severity_label_name not in label_names:
            label_names.append(severity_label_name)

        # AI explanation covering all CVEs
        ai_text = explain_vulnerability(pkg["name"], fixable_vulns, pkg["version"], best_version)

        # Full PR body with CVE table + diff preview
        body = build_pr_body(
            ai_explanation=ai_text,
            fixable_vulns=fixable_vulns,
            package_name=pkg["name"],
            old_version=pkg["version"],
            new_version=best_version,
            source_file=pkg["source_file"],
        )

        branch = f"fix/vuln-{pkg['name']}-{best_version}".replace(".", "-").lower()

        bump_version_in_file(pkg["source_file"], pkg["name"], pkg["version"], best_version)

        if not create_branch_and_commit(branch, pkg["source_file"], pkg["name"], best_version, default_branch):
            subprocess.run(["git", "checkout", default_branch], check=False)
            continue

        title = f"Security Fix: {pkg['name']} {pkg['version']} → {best_version} [{worst_severity}]"
        patch = is_patch_bump(pkg["version"], best_version)

        create_pull_request(
            repo=REPO_NAME,
            branch_name=branch,
            title=title,
            body=body,
            token=GITHUB_TOKEN,
            default_branch=default_branch,
            label_names=label_names,
            reviewers=PR_REVIEWERS,
            auto_merge=(AUTO_MERGE_PATCH and patch),
        )

        subprocess.run(["git", "checkout", default_branch], check=False)
        patched_count += 1

    logger.info("Scan complete. %d patch PR(s) opened.", patched_count)


if __name__ == "__main__":
    main()
