# Vuln Auto-Patcher

A GitHub Actions bot that automatically scans your dependencies for known CVEs,
generates plain-English explanations using a free AI model, and opens pull requests
with the patched version — making security proactive, not reactive.

---

## AI Model — Free Tier Recommendation

This project originally used Claude (Anthropic). For a **completely free** alternative,
use **Google Gemini 2.0 Flash** via Google AI Studio:

| Model | Free Quota | Quality |
|-------|-----------|---------|
| `gemini-2.0-flash` | 1,500 req/day · 15 RPM · 1M TPM | Best free option |
| `gemini-1.5-flash` | 1,500 req/day · 15 RPM · 1M TPM | Solid backup |

**Why Gemini 2.0 Flash:**
- No credit card required — just a Google account
- Generous daily quota (far exceeds what a weekly scan needs)
- Strong instruction-following for structured PR descriptions
- Official Python SDK: `google-genai`

**Setup:**
1. Go to [aistudio.google.com](https://aistudio.google.com) and generate a free API key
2. Add the secret `GEMINI_API_KEY` to your GitHub repo (Settings → Secrets → Actions)
3. Replace `llm_explainer.py` usage — see [scanner/llm_explainer.py](scanner/llm_explainer.py)

```python
# requirements.txt — swap anthropic for google-genai
google-genai>=1.0.0
```

```python
# scanner/llm_explainer.py — drop-in replacement
import os
from google import genai

def explain_vulnerability(package, version, vuln_id, summary, references):
    client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
    prompt = f"""You are a security engineer writing a pull request description...
Package: {package} {version}
CVE: {vuln_id}
Summary: {summary}
References: {chr(10).join(references[:3])}
Write a concise PR description: what the vulnerability is, why it matters,
what version fixes it, and what the reviewer should verify."""
    response = client.models.generate_content(
        model="gemini-2.0-flash", contents=prompt
    )
    return response.text
```

> The `GITHUB_TOKEN` is automatically provided by GitHub Actions — no setup needed.

---

## Quick Setup

### 1. Clone and open in VS Code
```bash
git clone https://github.com/your-username/vuln-auto-patcher.git
cd vuln-auto-patcher
code .
```

### 2. Install dependencies locally (optional, for testing)
```bash
pip install -r requirements.txt
```

### 3. Add GitHub Secrets
Go to your repo → **Settings → Secrets and variables → Actions** and add:

| Secret Name      | Value                                           |
|------------------|-------------------------------------------------|
| `GEMINI_API_KEY` | Your free key from https://aistudio.google.com  |

### 4. Configure your environment
```bash
cp .env.example .env
# Edit .env with your values
```

### 5. Push to GitHub and trigger manually
Go to **Actions → Vulnerability Auto-Patcher → Run workflow**

---

## Configuration

Edit these environment variables in `.env` or in your GitHub Actions workflow:

| Variable          | Default  | Description                                                        |
|-------------------|----------|--------------------------------------------------------------------|
| `MIN_SEVERITY`    | `HIGH`   | Minimum CVE severity to patch (`LOW`, `MODERATE`, `HIGH`, `CRITICAL`) |
| `REPO_NAME`       | —        | Your repo in `username/repo` format (not a full URL)               |
| `DEFAULT_BRANCH`  | `main`   | Base branch for pull requests (`main`, `master`, `develop`)        |
| `MAX_PRS_PER_RUN` | `10`     | Cap on PRs opened per workflow run                                 |

---

## Project Structure

```
vuln-auto-patcher/
├── .github/
│   └── workflows/
│       └── vuln_scan.yml        # Scheduled GitHub Actions trigger
├── scanner/
│   ├── main.py                  # Entry point — orchestrates everything
│   ├── dependency_parser.py     # Reads requirements.txt / package.json
│   ├── osv_client.py            # Queries OSV API for CVEs
│   ├── patcher.py               # Bumps versions + opens PRs
│   └── llm_explainer.py         # AI generates PR descriptions
├── .env.example                 # Environment variable template
├── .gitignore
├── requirements.txt             # Bot dependencies
└── README.md
```

---

## Supported Dependency Files

| File               | Ecosystem | Status      |
|--------------------|-----------|-------------|
| `requirements.txt` | PyPI      | Supported   |
| `package.json`     | npm       | Supported   |
| `poetry.lock`      | PyPI      | Phase 3     |
| `Pipfile`          | PyPI      | Phase 3     |
| `Cargo.toml`       | Rust      | Phase 3     |
| `go.mod`           | Go        | Phase 3     |

---

## Audit Findings (Current Codebase)

A full audit of the current code identified the following issues, tracked as fix targets in Phase 2:

| Severity | Issue | File |
|----------|-------|------|
| Critical | Relative imports (`from dependency_parser import`) fail in GitHub Actions | `scanner/main.py` |
| Critical | `REPO_NAME` must be `username/repo` format, not a full URL | `.env` |
| High | Regex doesn't match package names containing dots (e.g., `zope.interface`) | `dependency_parser.py` |
| High | PR base branch hardcoded to `main` — breaks repos using `master` or `develop` | `patcher.py` |
| High | No error handling on `subprocess` git calls — crashes and leaves orphaned branches | `patcher.py` |
| High | No retry logic for OSV, AI, or GitHub API calls — single transient failure = full crash | all modules |
| Medium | Duplicate branch creation crashes second run for the same vulnerability | `patcher.py` |
| Medium | No deduplication — can open multiple PRs for the same CVE on the same package | `main.py` |
| Medium | No validation that `MIN_SEVERITY` env var is one of the four accepted values | `main.py` |
| Medium | `get_safe_version()` picks first fixed version, not the latest | `osv_client.py` |
| Low | No structured logging — only print statements, hard to debug in CI | all modules |
| Low | No tests — no unit or integration test suite | — |

---

## Roadmap

### Phase 1 — MVP (Current)
Core pipeline is in place and functional in a clean environment:

- [x] Parse `requirements.txt` and `package.json`
- [x] Query the OSV API for known CVEs per package
- [x] Filter by minimum severity (`LOW` / `MODERATE` / `HIGH` / `CRITICAL`)
- [x] Generate plain-English PR descriptions via AI (Claude → Gemini)
- [x] Bump version in dependency file, commit, and open a GitHub PR
- [x] Weekly scheduled run via GitHub Actions (`cron: '0 9 * * 1'`)
- [x] Manual trigger via `workflow_dispatch`

---

### Phase 2 — Hardening (Next)
Fix all audit-identified issues so the bot runs reliably in production:

- [ ] Convert relative imports to absolute (`from scanner.X import ...`)
- [ ] Fix `dependency_parser.py` regex to handle dots and spaces in package names
- [ ] Make default branch configurable via `DEFAULT_BRANCH` env var (not hardcoded `main`)
- [ ] Add try/except around all subprocess git calls with cleanup on failure
- [ ] Add retry logic with exponential backoff for OSV, AI, and GitHub API calls
- [ ] Guard against duplicate branches — skip or update existing open PRs for same CVE
- [ ] Deduplicate vulnerabilities before opening PRs
- [ ] Validate `MIN_SEVERITY` env var at startup; exit early with a clear message if invalid
- [ ] Upgrade `get_safe_version()` to pick the highest available fixed version
- [ ] Replace print statements with Python `logging` module
- [ ] Cache pip dependencies in GitHub Actions workflow (`actions/cache`)
- [ ] Add `MAX_PRS_PER_RUN` guard to prevent runaway PR creation
- [ ] Migrate from Claude to Gemini 2.0 Flash (free tier)

---

### Phase 3 — Ecosystem Expansion
Broaden dependency file support so the bot covers more languages and lock file formats:

- [ ] Support `poetry.lock` (Python/PyPI)
- [ ] Support `Pipfile` / `Pipfile.lock` (Python/PyPI)
- [ ] Support `Cargo.toml` / `Cargo.lock` (Rust/crates.io)
- [ ] Support `go.mod` / `go.sum` (Go/pkg.go.dev)
- [ ] Support `package-lock.json` for accurate locked version scanning (npm)
- [ ] Monorepo support — recursively scan all dependency files in subdirectories
- [ ] Normalize package names across ecosystems (case-insensitive matching)

---

### Phase 4 — Smart PR Management
Make the bot smarter about how it creates and manages pull requests:

- [ ] Auto-detect the repo's default branch instead of relying on env var
- [ ] Check for an existing open PR for the same package + CVE before creating a new one
- [ ] Batch multiple vulnerabilities in the same package into a single PR
- [ ] Add configurable labels to PRs (e.g., `security`, `dependencies`, severity label)
- [ ] Auto-assign reviewers or team from config
- [ ] Auto-merge PRs for patch-level bumps when CI passes (using `gh pr merge --auto`)
- [ ] Include a diff preview of the changed line in the PR description
- [ ] Link PRs to GitHub Security Advisories when a matching GHSA ID is available

---

### Phase 5 — Observability & Notifications
Give teams visibility into what the bot is doing without having to dig through Actions logs:

- [ ] Post a Slack message when new CVEs are discovered (webhook-based, no paid plan needed)
- [ ] Post a Discord notification via webhook on CVE discovery
- [ ] Generate a scan summary as a GitHub Actions Job Summary (visible in the Actions UI)
- [ ] Upload a structured JSON scan report as a workflow artifact for audit trails
- [ ] Weekly email digest using GitHub Actions + a free SMTP provider (e.g., Mailgun free tier)
- [ ] Severity dashboard deployed to GitHub Pages showing open vs. patched vulns over time

---

### Phase 6 — Advanced Features
Power-user and enterprise-hardening features for larger or more complex repos:

- [ ] Allow/deny-list for specific packages or CVE IDs (skip known false positives)
- [ ] CVSS score threshold as an alternative to severity string filtering
- [ ] `--dry-run` mode: log everything but open no PRs (useful for previewing in forks)
- [ ] Support GitHub Enterprise and self-hosted GitHub runners
- [ ] Configurable scan schedule per ecosystem (e.g., PyPI daily, npm weekly)
- [ ] Integrate with Dependabot alerts API to avoid duplicating its open PRs
- [ ] Track mean time to remediation (MTTR) per package and CVE severity
- [ ] Optional SBOM (Software Bill of Materials) export in CycloneDX or SPDX format

---

## License

MIT
