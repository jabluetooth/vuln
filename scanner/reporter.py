import os
import json
import logging
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

HISTORY_FILE  = "scan_history.json"
REPORT_FILE   = "scan_report.json"
SBOM_FILE     = "sbom.json"
DASHBOARD_DIR = "docs"

_SEVERITY_COLORS = {
    "CRITICAL": "#b60205",
    "HIGH":     "#e87c0d",
    "MODERATE": "#e4e669",
    "LOW":      "#0e8a16",
}
_PURL_ECO = {
    "PyPI":       "pypi",
    "npm":        "npm",
    "crates.io":  "cargo",
    "Go":         "golang",
}


# ── Job Summary ───────────────────────────────────────────────────────────────

def write_job_summary(findings: list[dict], repo: str, scanned_count: int):
    """Append a markdown table to $GITHUB_STEP_SUMMARY."""
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY", "")
    if not summary_path:
        return

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"## 🔐 Vulnerability Scan — {repo}",
        f"*{ts} — {scanned_count} package(s) scanned*",
        "",
    ]

    if not findings:
        lines.append("✅ **No vulnerabilities found above threshold.**")
    else:
        lines += [
            f"### {len(findings)} Package(s) Patched",
            "",
            "| Package | Old → New | Severity | CVEs | PR |",
            "|---------|-----------|----------|------|----|",
        ]
        for f in findings:
            cves = ", ".join(f.get("cve_ids", [])[:3])
            if len(f.get("cve_ids", [])) > 3:
                cves += f" (+{len(f['cve_ids']) - 3} more)"
            pr_cell = (
                f"[#{f['pr_number']}]({f['pr_url']})"
                if f.get("pr_url")
                else "*(dry run)*"
            )
            lines.append(
                f"| `{f['package']}` | {f['old_version']} → {f['new_version']}"
                f" | {f['worst_severity']} | {cves} | {pr_cell} |"
            )

    try:
        with open(summary_path, "a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n\n")
        logger.info("GitHub Job Summary written.")
    except OSError as e:
        logger.warning("Could not write Job Summary: %s", e)


# ── JSON Report artifact ───────────────────────────────────────────────────────

def write_json_report(findings: list[dict], repo: str, scanned_count: int):
    """Write scan_report.json for upload as a workflow artifact."""
    report = {
        "repo":             repo,
        "scanned_at":       datetime.now(timezone.utc).isoformat(),
        "packages_scanned": scanned_count,
        "patches_opened":   len(findings),
        "findings":         findings,
    }
    try:
        with open(REPORT_FILE, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        logger.info("JSON report written to %s.", REPORT_FILE)
    except OSError as e:
        logger.warning("Could not write JSON report: %s", e)


# ── MTTR scan history ─────────────────────────────────────────────────────────

def update_scan_history(findings: list[dict], repo: str) -> list[dict]:
    """Persist scan_history.json and compute MTTR for resolved CVEs."""
    history: list[dict] = []
    if Path(HISTORY_FILE).exists():
        try:
            history = json.loads(Path(HISTORY_FILE).read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            history = []

    now = datetime.now(timezone.utc).isoformat()

    # Keys still open this run
    open_keys = {
        (f["package"], cve)
        for f in findings
        for cve in f.get("cve_ids", [])
    }

    # Mark resolved entries
    for entry in history:
        if entry.get("resolved_at") is None:
            key = (entry["package"], entry["cve_id"])
            if key not in open_keys:
                entry["resolved_at"] = now
                try:
                    delta = (
                        datetime.fromisoformat(now)
                        - datetime.fromisoformat(entry["first_seen"])
                    )
                    entry["mttr_hours"] = round(delta.total_seconds() / 3600, 1)
                except Exception:
                    pass

    # Add new CVEs not yet tracked
    existing_open = {
        (e["package"], e["cve_id"])
        for e in history
        if e.get("resolved_at") is None
    }
    for f in findings:
        for cve in f.get("cve_ids", []):
            if (f["package"], cve) not in existing_open:
                history.append({
                    "repo":         repo,
                    "package":      f["package"],
                    "cve_id":       cve,
                    "severity":     f["worst_severity"],
                    "old_version":  f["old_version"],
                    "new_version":  f["new_version"],
                    "pr_url":       f.get("pr_url"),
                    "first_seen":   now,
                    "resolved_at":  None,
                    "mttr_hours":   None,
                })

    try:
        Path(HISTORY_FILE).write_text(json.dumps(history, indent=2), encoding="utf-8")
        logger.info("Scan history updated (%d total entries).", len(history))
    except OSError as e:
        logger.warning("Could not write scan history: %s", e)

    return history


# ── SBOM export ───────────────────────────────────────────────────────────────

def export_sbom(packages: list[dict], repo: str):
    """Export a CycloneDX 1.4 JSON SBOM."""
    now = datetime.now(timezone.utc).isoformat()
    components = [
        {
            "type":    "library",
            "name":    pkg["name"],
            "version": pkg["version"],
            "purl":    _purl(pkg),
        }
        for pkg in packages
    ]
    sbom = {
        "bomFormat":   "CycloneDX",
        "specVersion": "1.4",
        "version":     1,
        "metadata": {
            "timestamp": now,
            "component": {"type": "application", "name": repo},
        },
        "components": components,
    }
    try:
        with open(SBOM_FILE, "w", encoding="utf-8") as fh:
            json.dump(sbom, fh, indent=2)
        logger.info("SBOM written to %s (%d components).", SBOM_FILE, len(components))
    except OSError as e:
        logger.warning("Could not write SBOM: %s", e)


def _purl(pkg: dict) -> str:
    eco = _PURL_ECO.get(pkg.get("ecosystem", ""), "generic")
    return f"pkg:{eco}/{pkg['name']}@{pkg['version']}"


# ── Severity dashboard ────────────────────────────────────────────────────────

def generate_dashboard(history: list[dict], repo: str):
    """Render docs/index.html — a static severity dashboard for GitHub Pages."""
    Path(DASHBOARD_DIR).mkdir(exist_ok=True)

    open_entries     = [e for e in history if e.get("resolved_at") is None]
    resolved_entries = [e for e in history if e.get("resolved_at") is not None]
    open_by_sev      = Counter(e["severity"] for e in open_entries)
    mttr_values      = [e["mttr_hours"] for e in history if e.get("mttr_hours") is not None]
    avg_mttr         = round(sum(mttr_values) / len(mttr_values), 1) if mttr_values else None

    severity_bars = "".join(
        f'<div class="bar-row">'
        f'<span class="bar-label">{sev}</span>'
        f'<div class="bar" style="background:{_SEVERITY_COLORS.get(sev,"#ccc")};'
        f'width:{min(count * 24, 480)}px"></div>'
        f'<span class="bar-count">{count}</span></div>'
        for sev, count in open_by_sev.most_common()
    )
    if not severity_bars:
        severity_bars = "<p>No open vulnerabilities 🎉</p>"

    def _row(e: dict) -> str:
        status = (
            f'<span class="resolved">✅ {e["resolved_at"][:10]}</span>'
            if e.get("resolved_at")
            else '<span class="open">⏳ Open</span>'
        )
        mttr_cell = str(e.get("mttr_hours", "—"))
        cve_url = (
            f"https://github.com/advisories/{e['cve_id']}"
            if e["cve_id"].upper().startswith("GHSA-")
            else f"https://osv.dev/vulnerability/{e['cve_id']}"
        )
        return (
            f"<tr>"
            f"<td>{e['package']}</td>"
            f'<td><a href="{cve_url}" target="_blank">{e["cve_id"]}</a></td>'
            f"<td>{e['severity']}</td>"
            f"<td>{e['first_seen'][:10]}</td>"
            f"<td>{status}</td>"
            f"<td>{mttr_cell}</td>"
            f"</tr>"
        )

    rows = "".join(_row(e) for e in reversed(history[-200:]))
    updated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{repo} — Vulnerability Dashboard</title>
<style>
  *{{box-sizing:border-box}}
  body{{font-family:system-ui,-apple-system,sans-serif;max-width:1000px;margin:2rem auto;
       padding:0 1.25rem;color:#24292f;background:#fff}}
  h1{{border-bottom:3px solid #d73a4a;padding-bottom:.5rem;margin-bottom:1.5rem}}
  h2{{margin-top:2rem;color:#24292f}}
  .stats{{display:flex;gap:1.5rem;flex-wrap:wrap;margin-bottom:2rem}}
  .stat{{background:#f6f8fa;border:1px solid #d0d7de;border-radius:8px;
         padding:1rem 1.5rem;text-align:center;min-width:120px}}
  .stat .num{{font-size:2rem;font-weight:700;color:#d73a4a}}
  .stat .lbl{{font-size:.8rem;color:#57606a;margin-top:.25rem}}
  .bar-row{{display:flex;align-items:center;margin:5px 0;gap:8px}}
  .bar-label{{width:80px;font-weight:600;font-size:.9rem}}
  .bar{{height:22px;border-radius:4px;transition:width .3s}}
  .bar-count{{font-size:.9rem;color:#57606a}}
  table{{width:100%;border-collapse:collapse;font-size:.9rem;margin-top:1rem}}
  thead tr{{background:#24292f;color:#fff}}
  th,td{{padding:.5rem .75rem;text-align:left;border-bottom:1px solid #e1e4e8}}
  tr:nth-child(even) td{{background:#f6f8fa}}
  a{{color:#0969da;text-decoration:none}}
  a:hover{{text-decoration:underline}}
  .open{{color:#cf222e;font-weight:600}}
  .resolved{{color:#1a7f37}}
  .updated{{font-size:.75rem;color:#57606a;margin-top:1.5rem;text-align:right}}
</style>
</head>
<body>
<h1>🔐 {repo} — Vulnerability Dashboard</h1>

<div class="stats">
  <div class="stat">
    <div class="num">{len(open_entries)}</div>
    <div class="lbl">Open CVEs</div>
  </div>
  <div class="stat">
    <div class="num">{len(resolved_entries)}</div>
    <div class="lbl">Resolved</div>
  </div>
  <div class="stat">
    <div class="num">{avg_mttr if avg_mttr is not None else "—"}</div>
    <div class="lbl">Avg MTTR (hrs)</div>
  </div>
  <div class="stat">
    <div class="num">{len(history)}</div>
    <div class="lbl">Total Tracked</div>
  </div>
</div>

<h2>Open Vulnerabilities by Severity</h2>
{severity_bars}

<h2>Vulnerability History</h2>
<table>
<thead>
  <tr>
    <th>Package</th><th>CVE / OSV ID</th><th>Severity</th>
    <th>First Seen</th><th>Status</th><th>MTTR (hrs)</th>
  </tr>
</thead>
<tbody>{rows}</tbody>
</table>

<p class="updated">Last updated: {updated}</p>
</body>
</html>"""

    path = Path(DASHBOARD_DIR) / "index.html"
    try:
        path.write_text(html, encoding="utf-8")
        logger.info("Dashboard written to %s.", path)
    except OSError as e:
        logger.warning("Could not write dashboard: %s", e)
