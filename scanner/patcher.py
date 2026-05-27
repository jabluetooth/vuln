import re
import os
import subprocess
import logging
import requests

logger = logging.getLogger(__name__)

DEFAULT_BRANCH = os.environ.get("DEFAULT_BRANCH", "main")


def bump_version_in_file(filepath: str, package_name: str, old_version: str, new_version: str):
    with open(filepath, "r") as f:
        content = f.read()

    updated = re.sub(
        rf'({re.escape(package_name)}\s*[=><~!]+\s*){re.escape(old_version)}',
        rf'\g<1>{new_version}',
        content
    )

    with open(filepath, "w") as f:
        f.write(updated)

    logger.info("Bumped %s from %s → %s in %s", package_name, old_version, new_version, filepath)


def git_setup():
    try:
        subprocess.run(["git", "config", "user.email", "vuln-patcher-bot@noreply.github.com"], check=True)
        subprocess.run(["git", "config", "user.name", "Vuln Auto-Patcher Bot"], check=True)
        logger.info("Git identity configured.")
    except subprocess.CalledProcessError as e:
        logger.error("Failed to configure git identity: %s", e)
        raise


def branch_exists_on_remote(branch_name: str) -> bool:
    result = subprocess.run(
        ["git", "ls-remote", "--heads", "origin", branch_name],
        capture_output=True, text=True
    )
    return branch_name in result.stdout


def create_branch_and_commit(branch_name: str, filepath: str, package_name: str, new_version: str) -> bool:
    """Create branch, commit, and push. Returns False if branch already exists."""
    if branch_exists_on_remote(branch_name):
        logger.info("Branch '%s' already exists on remote — skipping.", branch_name)
        return False

    try:
        subprocess.run(["git", "checkout", "-b", branch_name], check=True)
        subprocess.run(["git", "add", filepath], check=True)
        subprocess.run(
            ["git", "commit", "-m", f"fix(deps): bump {package_name} to {new_version} (security patch)"],
            check=True
        )
        subprocess.run(["git", "push", "origin", branch_name], check=True)
        logger.info("Pushed branch '%s'.", branch_name)
        return True
    except subprocess.CalledProcessError as e:
        logger.error("Git operation failed on branch '%s': %s", branch_name, e)
        # Clean up: return to default branch and delete the local branch if it was created
        subprocess.run(["git", "checkout", DEFAULT_BRANCH], check=False)
        subprocess.run(["git", "branch", "-D", branch_name], check=False)
        return False


def create_pull_request(repo: str, branch_name: str, title: str, body: str, token: str) -> str | None:
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json"
    }
    pr_payload = {
        "title": title,
        "body": body,
        "head": branch_name,
        "base": DEFAULT_BRANCH
    }

    for attempt in range(3):
        try:
            response = requests.post(
                f"https://api.github.com/repos/{repo}/pulls",
                headers=headers,
                json=pr_payload,
                timeout=15
            )
            if response.status_code == 201:
                pr_url = response.json().get("html_url")
                logger.info("PR opened: %s", pr_url)
                return pr_url
            elif response.status_code == 422:
                logger.warning("PR already exists for branch '%s'.", branch_name)
                return None
            elif response.status_code in (429, 503):
                import time
                time.sleep(2 ** attempt)
                continue
            else:
                logger.error("Failed to create PR: %d %s", response.status_code, response.text)
                return None
        except requests.RequestException as e:
            logger.error("PR creation request failed: %s", e)
            return None
    return None
