# Vuln Auto-Patcher

A GitHub Actions bot that automatically scans your dependencies for known CVEs,
generates plain-English explanations using AI, and opens pull requests with the
patched version — making security proactive, not reactive.

---

## Quick Setup

### 1. Clone and open in VS Code
```bash
git clone https://github.com/jabluetooth/vuln.git
cd vuln
code .
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Add GitHub Secrets
Go to your repo → **Settings → Secrets and variables → Actions** and add:

| Secret Name      | Value                                          |
|------------------|------------------------------------------------|
| `GEMINI_API_KEY` | Your free key from https://aistudio.google.com |

> `GITHUB_TOKEN` is automatically provided by GitHub Actions — no setup needed.

### 4. Configure your environment
```bash
cp .env.example .env
# Fill in your values
```

### 5. Trigger the workflow
Go to **Actions → Vulnerability Auto-Patcher → Run workflow**

---

## Configuration

| Variable          | Default  | Description                                                           |
|-------------------|----------|-----------------------------------------------------------------------|
| `MIN_SEVERITY`    | `HIGH`   | Minimum CVE severity to patch (`LOW`, `MODERATE`, `HIGH`, `CRITICAL`) |
| `REPO_NAME`       | —        | Your repo in `username/repo` format                                   |
| `DEFAULT_BRANCH`  | `main`   | Base branch for pull requests                                         |
| `MAX_PRS_PER_RUN` | `10`     | Cap on PRs opened per workflow run                                    |

---

## Project Structure

```
vuln/
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
├── requirements.txt
└── README.md
```

---

## Supported Dependency Files

| File               | Ecosystem |
|--------------------|-----------|
| `requirements.txt` | PyPI      |
| `package.json`     | npm       |

---

## AI Model

Uses **Google Gemini 2.0 Flash** (free tier — no credit card required).
Get your free API key at [aistudio.google.com](https://aistudio.google.com).

---

## License

MIT
