import re
import os
import json
import time
import subprocess
import logging
import requests
from packaging.version import Version, InvalidVersion

logger = logging.getLogger(__name__)

# ── Label definitions ─────────────────────────────────────────────────────────
SEVERITY_LABELS = {
    "LOW":      {"name": "severity: low",      "color": "0e8a16", "description": "Low severity vulnerability"},
    "MODERATE": {"name": "severity: moderate",  "color": "e4e669", "description": "Moderate severity vulnerability"},
    "HIGH":     {"name": "severity: high",      "color": "e87c0d", "description": "High severity vulnerability"},
    "CRITICAL": {"name": "severity: critical",  "color": "b60205", "description": "Critical severity vulnerability"},
}
BASE_LABELS = [
    {"name": "security",      "color": "d73a4a", "description": "Security vulnerability patch"},
    {"name": "dependencies",  "color": "0075ca", "description": "Dependency version bump"},
]

# ── GitHub helpers ────────────────────────────────────────────────────────────

def _gh_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}


def get_default_branch(repo: str, token: str, gh_api_url: str = "https://api.github.com") -> str:
    """Fetch the repo's actual default branch from GitHub API."""
    try:
        r = requests.get(
            f"{gh_api_url}/repos/{repo}",
            headers=_gh_headers(token),
            timeout=10
        )
        if r.status_code == 200:
            branch = r.json().get("default_branch", "main")
            logger.info("Auto-detected default branch: %s", branch)
            return branch
    except requests.RequestException as e:
        logger.warning("Could not auto-detect default branch (%s) — using fallback.", e)
    return os.environ.get("DEFAULT_BRANCH", "main")


def open_pr_exists(repo: str, branch: str, token: str, gh_api_url: str = "https://api.github.com") -> bool:
    """Return True if an open PR already targets this branch."""
    owner = repo.split("/")[0]
    try:
        r = requests.get(
            f"{gh_api_url}/repos/{repo}/pulls",
            headers=_gh_headers(token),
            params={"head": f"{owner}:{branch}", "state": "open"},
            timeout=10
        )
        if r.status_code == 200:
            return len(r.json()) > 0
    except requests.RequestException as e:
        logger.warning("Could not check for existing PR: %s", e)
    return False


def ensure_labels(repo: str, token: str, extra_names: list[str], gh_api_url: str = "https://api.github.com"):
    """Create standard labels and any custom labels if they don't exist yet."""
    labels_to_create = BASE_LABELS + list(SEVERITY_LABELS.values())
    for name in extra_names:
        if name not in {l["name"] for l in labels_to_create}:
            labels_to_create.append({"name": name, "color": "cccccc", "description": ""})

    for label in labels_to_create:
        requests.post(
            f"{gh_api_url}/repos/{repo}/labels",
            headers=_gh_headers(token),
            json=label,
            timeout=10
        )
        # 422 = label already exists — silently ignored


def add_labels_to_pr(repo: str, pr_number: int, label_names: list[str], token: str, gh_api_url: str = "https://api.github.com"):
    r = requests.post(
        f"{gh_api_url}/repos/{repo}/issues/{pr_number}/labels",
        headers=_gh_headers(token),
        json={"labels": label_names},
        timeout=10
    )
    if r.status_code not in (200, 201):
        logger.warning("Could not add labels to PR #%d: %s", pr_number, r.text)


def request_reviewers(repo: str, pr_number: int, reviewers: list[str], token: str, gh_api_url: str = "https://api.github.com"):
    if not reviewers:
        return
    r = requests.post(
        f"{gh_api_url}/repos/{repo}/pulls/{pr_number}/requested_reviewers",
        headers=_gh_headers(token),
        json={"reviewers": reviewers},
        timeout=10
    )
    if r.status_code not in (200, 201):
        logger.warning("Could not add reviewers to PR #%d: %s", pr_number, r.text)


def enable_auto_merge(pr_node_id: str, token: str, gh_api_url: str = "https://api.github.com"):
    """Enable GitHub auto-merge on the PR via GraphQL (requires branch protection to be set up)."""
    query = """
    mutation($prId: ID!) {
      enablePullRequestAutoMerge(input: {pullRequestId: $prId, mergeMethod: SQUASH}) {
        pullRequest { number autoMergeRequest { enabledAt } }
      }
    }
    """
    graphql_url = gh_api_url.rstrip("/").replace("/api/v3", "") + "/graphql"
    try:
        r = requests.post(
            graphql_url,
            headers={"Authorization": f"Bearer {token}"},
            json={"query": query, "variables": {"prId": pr_node_id}},
            timeout=15
        )
        data = r.json()
        if "errors" in data:
            logger.warning("Auto-merge could not be enabled: %s", data["errors"])
        else:
            logger.info("Auto-merge enabled on PR.")
    except requests.RequestException as e:
        logger.warning("Failed to enable auto-merge: %s", e)


def is_patch_bump(old_version: str, new_version: str) -> bool:
    """Return True if only the patch component changed (e.g. 1.2.3 → 1.2.4)."""
    try:
        old = Version(old_version)
        new = Version(new_version)
        return old.major == new.major and old.minor == new.minor and old.micro != new.micro
    except InvalidVersion:
        return False


# ── Git helpers ───────────────────────────────────────────────────────────────

_GIT_TIMEOUT = 60  # seconds — prevents hung git network operations


def git_setup(cwd: str | None = None):
    try:
        subprocess.run(["git", "config", "user.email", "vuln-patcher-bot@noreply.github.com"], check=True, cwd=cwd, timeout=_GIT_TIMEOUT)
        subprocess.run(["git", "config", "user.name",  "Vuln Auto-Patcher Bot"], check=True, cwd=cwd, timeout=_GIT_TIMEOUT)
        logger.info("Git identity configured.")
    except subprocess.CalledProcessError as e:
        logger.error("Failed to configure git identity: %s", e)
        raise


def branch_exists_on_remote(branch_name: str, cwd: str | None = None) -> bool:
    result = subprocess.run(
        ["git", "ls-remote", "--heads", "origin", branch_name],
        capture_output=True, text=True, cwd=cwd, timeout=_GIT_TIMEOUT,
    )
    return branch_name in result.stdout


def create_branch_and_commit(
    branch_name: str,
    filepath: str,
    package_name: str,
    new_version: str,
    default_branch: str = "main",
    cwd: str | None = None,
) -> bool:
    """Create branch, commit, push. Returns False if branch already exists."""
    if branch_exists_on_remote(branch_name, cwd=cwd):
        logger.info("Branch '%s' already exists on remote — skipping.", branch_name)
        return False

    git_filepath = os.path.relpath(filepath, cwd) if cwd else filepath

    try:
        subprocess.run(["git", "checkout", "-b", branch_name], check=True, cwd=cwd, timeout=_GIT_TIMEOUT)
        subprocess.run(["git", "add", git_filepath], check=True, cwd=cwd, timeout=_GIT_TIMEOUT)
        subprocess.run(
            ["git", "commit", "-m",
             f"fix(deps): bump {package_name} to {new_version} (security patch)"],
            check=True, cwd=cwd, timeout=_GIT_TIMEOUT,
        )
        subprocess.run(["git", "push", "origin", branch_name], check=True, cwd=cwd, timeout=_GIT_TIMEOUT)
        logger.info("Pushed branch '%s'.", branch_name)
        return True
    except subprocess.TimeoutExpired as e:
        logger.error("Git operation timed out on branch '%s': %s", branch_name, e)
        subprocess.run(["git", "checkout", default_branch], check=False, cwd=cwd, timeout=_GIT_TIMEOUT)
        subprocess.run(["git", "branch", "-D", branch_name], check=False, cwd=cwd, timeout=_GIT_TIMEOUT)
        return False
    except subprocess.CalledProcessError as e:
        logger.error("Git operation failed on branch '%s': %s", branch_name, e)
        subprocess.run(["git", "checkout", default_branch], check=False, cwd=cwd, timeout=_GIT_TIMEOUT)
        subprocess.run(["git", "branch", "-D", branch_name], check=False, cwd=cwd, timeout=_GIT_TIMEOUT)
        return False


# ── Version bumping ───────────────────────────────────────────────────────────

def bump_version_in_file(filepath: str, package_name: str, old_version: str, new_version: str):
    filename = os.path.basename(filepath)
    if filename == "package.json":
        _bump_package_json(filepath, package_name, old_version, new_version)
    elif filename in ("Pipfile.lock", "package-lock.json"):
        _bump_json(filepath, package_name, old_version, new_version)
    elif filename in ("poetry.lock", "Cargo.lock"):
        _bump_toml_lock(filepath, package_name, old_version, new_version)
    elif filename == "go.mod":
        _bump_go_mod(filepath, package_name, old_version, new_version)
    else:
        _bump_regex(filepath, package_name, old_version, new_version)
    logger.info("Bumped %s %s → %s in %s", package_name, old_version, new_version, filepath)


def _bump_package_json(filepath: str, package_name: str, old_version: str, new_version: str):
    with open(filepath) as f:
        data = json.load(f)
    changed = False
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        pkg_map = data.get(section, {})
        if package_name not in pkg_map:
            continue
        current = pkg_map[package_name].strip()
        # Preserve leading range prefix (^, ~, >=, etc.)
        prefix = re.match(r'^([^0-9]*)', current).group(1)
        bare = current.lstrip('^~>=<! ')
        if bare == old_version:
            pkg_map[package_name] = f"{prefix}{new_version}"
            changed = True
    if changed:
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)
            f.write("\n")


def _bump_regex(filepath: str, package_name: str, old_version: str, new_version: str):
    with open(filepath) as f:
        content = f.read()
    updated = re.sub(
        rf'({re.escape(package_name)}\s*[=><~!]+\s*){re.escape(old_version)}',
        rf'\g<1>{new_version}',
        content
    )
    with open(filepath, "w") as f:
        f.write(updated)


def _bump_toml_lock(filepath: str, package_name: str, old_version: str, new_version: str):
    with open(filepath) as f:
        content = f.read()
    pattern = re.compile(
        rf'(\[\[package\]\][^\[]*?name\s*=\s*"{re.escape(package_name)}"[^\[]*?version\s*=\s*")'
        rf'{re.escape(old_version)}"',
        re.DOTALL
    )
    updated = pattern.sub(rf'\g<1>{new_version}"', content)
    with open(filepath, "w") as f:
        f.write(updated)


def _bump_go_mod(filepath: str, package_name: str, old_version: str, new_version: str):
    with open(filepath) as f:
        content = f.read()
    updated = re.sub(
        rf'({re.escape(package_name)}\s+v){re.escape(old_version)}',
        rf'\g<1>{new_version}',
        content
    )
    with open(filepath, "w") as f:
        f.write(updated)


def _bump_json(filepath: str, package_name: str, old_version: str, new_version: str):
    with open(filepath) as f:
        data = json.load(f)
    filename = os.path.basename(filepath)
    if filename == "Pipfile.lock":
        for section in ("default", "develop"):
            pkg = data.get(section, {}).get(package_name, {})
            if pkg.get("version", "").lstrip("=") == old_version:
                pkg["version"] = f"=={new_version}"
    elif filename == "package-lock.json":
        for path_key, info in data.get("packages", {}).items():
            name = path_key.removeprefix("node_modules/").lstrip("/")
            if name == package_name and info.get("version") == old_version:
                info["version"] = new_version
        for name, info in data.get("dependencies", {}).items():
            if name == package_name and info.get("version", "").lstrip("^~=> ") == old_version:
                info["version"] = new_version
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


# ── PR creation (orchestrator) ────────────────────────────────────────────────

def create_pull_request(
    repo: str,
    branch_name: str,
    title: str,
    body: str,
    token: str,
    default_branch: str = "main",
    label_names: list[str] | None = None,
    reviewers: list[str] | None = None,
    auto_merge: bool = False,
    gh_api_url: str = "https://api.github.com",
) -> dict | None:
    """Open a PR and apply labels, reviewers, and auto-merge as configured."""
    label_names = label_names or []
    reviewers   = reviewers or []

    # Guard: don't open a duplicate PR
    if open_pr_exists(repo, branch_name, token, gh_api_url):
        logger.info("Open PR already exists for branch '%s' — skipping.", branch_name)
        return None

    # Ensure all labels exist in the repo before applying them
    if label_names:
        ensure_labels(repo, token, label_names, gh_api_url)

    for attempt in range(3):
        try:
            r = requests.post(
                f"{gh_api_url}/repos/{repo}/pulls",
                headers=_gh_headers(token),
                json={"title": title, "body": body, "head": branch_name, "base": default_branch},
                timeout=15
            )
            if r.status_code == 201:
                pr        = r.json()
                pr_url    = pr.get("html_url")
                pr_number = pr.get("number")
                pr_node   = pr.get("node_id")
                logger.info("PR #%d opened: %s", pr_number, pr_url)

                if label_names:
                    add_labels_to_pr(repo, pr_number, label_names, token, gh_api_url)

                if reviewers:
                    request_reviewers(repo, pr_number, reviewers, token, gh_api_url)

                if auto_merge:
                    enable_auto_merge(pr_node, token, gh_api_url)

                return {"url": pr_url, "number": pr_number, "node_id": pr_node}

            elif r.status_code == 422:
                logger.warning("PR already exists for branch '%s'.", branch_name)
                return None
            elif r.status_code in (429, 503):
                time.sleep(2 ** attempt)
                continue
            else:
                logger.error("Failed to create PR: %d %s", r.status_code, r.text)
                return None

        except requests.RequestException as e:
            logger.error("PR creation request failed: %s", e)
            return None

    return None
