# Vuln Auto-Patcher

A GitHub Actions bot that automatically scans your dependencies for known CVEs,
generates plain-English explanations using AI, and opens pull requests with the
patched version - making security proactive, not reactive.

![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-2671E5?style=for-the-badge&logo=githubactions&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Gemini](https://img.shields.io/badge/Gemini-8E75B2?style=for-the-badge&logo=googlegemini&logoColor=white)

<br>

<!-- HERO: screenshot of an actual pull request this bot opened - the PR description
     is the real "product" here (the plain-English CVE explanation + the version bump),
     so a screenshot of that PR view on GitHub is the single best proof this works.
     Save as docs/example-pr.png, add here as: -->
<!-- <p align="center"><img src="docs/example-pr.png" alt="Example auto-patch PR" width="800"></p> -->

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

> `GITHUB_TOKEN` is automatically provided by GitHub Actions - no setup needed.

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
| `REPO_NAME`       | -        | Your repo in `username/repo` format                                   |
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
│   ├── main.py                  # Entry point - orchestrates everything
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

Uses **Google Gemini 2.0 Flash** (free tier - no credit card required).
Get your free API key at [aistudio.google.com](https://aistudio.google.com).

---

## About the developer

**Fil Heinz O. Re La Torre** - Automation & AI Solutions Engineer, building integrations and AI-backed workflows that go from idea to production in days.

[![Portfolio](https://img.shields.io/badge/Portfolio-000000?style=for-the-badge&logo=vercel&logoColor=white)](https://www.filheinzrelatorre.com)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://ph.linkedin.com/in/filheinzrelatorre)
[![GitHub](https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white)](https://github.com/jabluetooth)
[![Gmail](https://img.shields.io/badge/Gmail-D14836?style=for-the-badge&logo=gmail&logoColor=white)](mailto:filheinz27@gmail.com)

**Other projects:** [Match](https://github.com/jabluetooth/match) · [ZeroPress](https://github.com/jabluetooth/zeropress) · [Mimo](https://github.com/jabluetooth/mimo) · [Insight](https://github.com/jabluetooth/insight) · [see all →](https://github.com/jabluetooth)

## License

MIT
