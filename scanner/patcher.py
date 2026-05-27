import re
import os
import subprocess
import requests


def bump_version_in_file(filepath: str, package_name: str, old_version: str, new_version: str):
    """Replace the old version of a package with the new version in the given file."""
    with open(filepath, "r") as f:
        content = f.read()

    updated = re.sub(
        rf'({re.escape(package_name)}[=><~!]+){re.escape(old_version)}',
        rf'\g<1>{new_version}',
        content
    )

    with open(filepath, "w") as f:
        f.write(updated)

    print(f"[PATCH] Bumped {package_name} from {old_version} → {new_version} in {filepath}")


def git_setup():
    """Configure git identity for the bot."""
    subprocess.run(["git", "config", "user.email", "vuln-patcher-bot@noreply.github.com"], check=True)
    subprocess.run(["git", "config", "user.name", "Vuln Auto-Patcher Bot"], check=True)


def branch_exists_on_remote(branch_name: str) -> bool:
    result = subprocess.run(
        ["git", "ls-remote", "--heads", "origin", branch_name],
        capture_output=True, text=True
    )
    return branch_name in result.stdout


def create_branch_and_commit(branch_name: str, filepath: str, package_name: str, new_version: str) -> bool:
    """Create a new git branch, stage changes, and commit. Returns False if branch already exists."""
    if branch_exists_on_remote(branch_name):
        print(f"[SKIP] Branch '{branch_name}' already exists — PR likely already open.")
        return False

    subprocess.run(["git", "checkout", "-b", branch_name], check=True)
    subprocess.run(["git", "add", filepath], check=True)
    subprocess.run(
        ["git", "commit", "-m", f"fix(deps): bump {package_name} to {new_version} (security patch)"],
        check=True
    )
    subprocess.run(["git", "push", "origin", branch_name], check=True)
    return True


def create_pull_request(repo: str, branch_name: str, title: str, body: str, token: str) -> str | None:
    """Open a pull request on GitHub via the REST API."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json"
    }

    pr_payload = {
        "title": title,
        "body": body,
        "head": branch_name,
        "base": "main"  # Change to your default branch if different
    }

    response = requests.post(
        f"https://api.github.com/repos/{repo}/pulls",
        headers=headers,
        json=pr_payload
    )

    if response.status_code == 201:
        pr_url = response.json().get("html_url")
        print(f"[PR] Opened: {pr_url}")
        return pr_url
    else:
        print(f"[ERROR] Failed to create PR: {response.status_code} {response.text}")
        return None
