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
from notifier import notify_all
from reporter import (
    write_job_summary,
    write_json_report,
    update_scan_history,
    export_sbom,
    generate_dashboard,
)
from filters import (
    is_package_allowed,
    filter_vulns,
    get_dependabot_packages,
    PACKAGE_DENYLIST,
    CVE_DENYLIST,
    CVSS_THRESHOLD,
)

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
GITHUB_TOKEN     = os.environ.get("GITHUB_TOKEN")
REPO_NAME        = os.environ.get("REPO_NAME")
MIN_SEVERITY     = os.environ.get("MIN_SEVERITY", "HIGH").upper()
MAX_PRS_PER_RUN  = int(os.environ.get("MAX_PRS_PER_RUN", "10"))
AUTO_MERGE_PATCH = os.environ.get("AUTO_MERGE_PATCH", "false").lower() == "true"
DRY_RUN          = os.environ.get("DRY_RUN", "false").lower() == "true"

# GitHub Enterprise: override API base URL (e.g. https://github.mycompany.com/api/v3)
GH_API_URL = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")

# Comma-separated GitHub usernames for review requests
PR_REVIEWERS = [r.strip() for r in os.environ.get("PR_REVIEWERS", "").split(",") if r.strip()]

# Comma-separated label names added to every PR
_extra_labels = [
    l.strip()
    for l in os.environ.get("PR_LABELS", "security,dependencies").split(",")
    if l.strip()
]

# Skip packages already covered by Dependabot
SKIP_DEPENDABOT = os.environ.get("SKIP_DEPENDABOT", "false").lower() == "true"

VALID_SEVERITIES = {"LOW", "MODERATE", "HIGH", "CRITICAL"}
SEVERITY_RANK    = {"LOW": 1, "MODERATE": 2, "HIGH": 3, "CRITICAL": 4, "UNKNOWN": 0}
# ─────────────────────────────────────────────────────────────────────────────


def validate_config() -> bool:
    if not GITHUB_TOKEN or not REPO_NAME:
        logger.error("GITHUB_TOKEN and REPO_NAME environment variables are required.")
        return False
    if MIN_SEVERITY not in VALID_SEVERITIES:
        logger.error(
            "Invalid MIN_SEVERITY '%s'. Must be one of: %s",
            MIN_SEVERITY, ", ".join(VALID_SEVERITIES),
        )
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

    if DRY_RUN:
        logger.info("DRY RUN mode — no branches, commits, or PRs will be created.")

    if PACKAGE_DENYLIST:
        logger.info("Package deny-list: %s", ", ".join(sorted(PACKAGE_DENYLIST)))
    if CVE_DENYLIST:
        logger.info("CVE deny-list: %s", ", ".join(sorted(CVE_DENYLIST)))
    if CVSS_THRESHOLD > 0:
        logger.info("CVSS threshold: %.1f", CVSS_THRESHOLD)

    default_branch = get_default_branch(REPO_NAME, GITHUB_TOKEN, GH_API_URL)

    logger.info("Starting vulnerability scan for %s", REPO_NAME)
    logger.info(
        "MIN_SEVERITY=%s | MAX_PRS=%d | DEFAULT_BRANCH=%s | AUTO_MERGE=%s | DRY_RUN=%s",
        MIN_SEVERITY, MAX_PRS_PER_RUN, default_branch, AUTO_MERGE_PATCH, DRY_RUN,
    )

    packages = get_all_packages()
    if not packages:
        logger.info("No packages found to scan.")
        _finish([], packages, REPO_NAME)
        return

    logger.info("Found %d package(s). Checking OSV database...", len(packages))

    # Export SBOM of all discovered packages before filtering
    export_sbom(packages, REPO_NAME)

    # Optionally skip packages already handled by Dependabot
    dependabot_covered: set[str] = set()
    if SKIP_DEPENDABOT:
        dependabot_covered = get_dependabot_packages(REPO_NAME, GITHUB_TOKEN, GH_API_URL)
        if dependabot_covered:
            logger.info("Dependabot already covers: %s", ", ".join(sorted(dependabot_covered)))

    if not DRY_RUN:
        git_setup()

    patched_count = 0
    findings: list[dict] = []

    for pkg in packages:
        if patched_count >= MAX_PRS_PER_RUN:
            logger.warning("Reached MAX_PRS_PER_RUN limit (%d). Stopping.", MAX_PRS_PER_RUN)
            break

        # Phase 6 filters
        if not is_package_allowed(pkg["name"]):
            continue
        if pkg["name"].lower() in dependabot_covered:
            logger.info("Skipping %s — already covered by Dependabot.", pkg["name"])
            continue

        vulns = check_vulnerabilities(pkg)
        if not vulns:
            continue

        # Apply CVE deny-list and CVSS threshold
        vulns = filter_vulns(vulns)
        if not vulns:
            continue

        logger.info("%s@%s — %d vulnerability(s) found", pkg["name"], pkg["version"], len(vulns))

        # Collect fixable vulns and find the highest safe version
        fixable_vulns: list[dict] = []
        best_version: str | None  = None
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

        worst_severity = max(
            (get_severity(v) for v in fixable_vulns),
            key=lambda s: SEVERITY_RANK.get(s.upper(), 0),
        )
        cve_ids = [v.get("id", "UNKNOWN") for v in fixable_vulns]
        logger.info(
            "  Fixing %d CVE(s) in %s: %s → %s [%s]",
            len(fixable_vulns), pkg["name"], pkg["version"], best_version, worst_severity,
        )

        # Build label list: base labels + severity label
        severity_label_name = SEVERITY_LABELS.get(worst_severity.upper(), {}).get("name")
        label_names = list(_extra_labels)
        if severity_label_name and severity_label_name not in label_names:
            label_names.append(severity_label_name)

        ai_text = explain_vulnerability(pkg["name"], fixable_vulns, pkg["version"], best_version)
        body = build_pr_body(
            ai_explanation=ai_text,
            fixable_vulns=fixable_vulns,
            package_name=pkg["name"],
            old_version=pkg["version"],
            new_version=best_version,
            source_file=pkg["source_file"],
        )

        branch = f"fix/vuln-{pkg['name']}-{best_version}".replace(".", "-").lower()
        title  = f"Security Fix: {pkg['name']} {pkg['version']} → {best_version} [{worst_severity}]"
        patch  = is_patch_bump(pkg["version"], best_version)

        finding: dict = {
            "package":        pkg["name"],
            "ecosystem":      pkg.get("ecosystem", ""),
            "old_version":    pkg["version"],
            "new_version":    best_version,
            "worst_severity": worst_severity,
            "cve_count":      len(fixable_vulns),
            "cve_ids":        cve_ids,
            "source_file":    pkg["source_file"],
            "pr_url":         None,
            "pr_number":      None,
        }

        if DRY_RUN:
            logger.info(
                "  [DRY RUN] Would open PR: %s  branch=%s", title, branch,
            )
            findings.append(finding)
            patched_count += 1
            continue

        bump_version_in_file(pkg["source_file"], pkg["name"], pkg["version"], best_version)

        if not create_branch_and_commit(
            branch, pkg["source_file"], pkg["name"], best_version, default_branch
        ):
            subprocess.run(["git", "checkout", default_branch], check=False)
            continue

        pr_result = create_pull_request(
            repo=REPO_NAME,
            branch_name=branch,
            title=title,
            body=body,
            token=GITHUB_TOKEN,
            default_branch=default_branch,
            label_names=label_names,
            reviewers=PR_REVIEWERS,
            auto_merge=(AUTO_MERGE_PATCH and patch),
            gh_api_url=GH_API_URL,
        )

        if pr_result:
            finding["pr_url"]    = pr_result["url"]
            finding["pr_number"] = pr_result["number"]

        findings.append(finding)
        subprocess.run(["git", "checkout", default_branch], check=False)
        patched_count += 1

    logger.info("Scan complete. %d patch PR(s) opened.", patched_count)
    _finish(findings, packages, REPO_NAME)


def _finish(findings: list[dict], packages: list[dict], repo: str):
    """Run all post-scan reporting and notification steps."""
    # Observability (Phase 5)
    write_job_summary(findings, repo, len(packages))
    write_json_report(findings, repo, len(packages))
    history = update_scan_history(findings, repo)
    generate_dashboard(history, repo)

    # Notifications (Phase 5)
    notify_all(findings, repo)


if __name__ == "__main__":
    main()
