import os
import logging
import smtplib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger(__name__)


def send_slack(findings: list[dict], repo: str):
    """Post a scan summary to Slack via incoming webhook."""
    webhook_url = os.environ.get("SLACK_WEBHOOK_URL", "").strip()
    if not webhook_url:
        return

    if not findings:
        text = f":white_check_mark: *{repo}* — Scan complete. No vulnerabilities found above threshold."
    else:
        lines = [f":lock: *{repo}* — {len(findings)} vulnerability fix(es) prepared:"]
        for f in findings:
            pr_link = f"<{f['pr_url']}|PR #{f['pr_number']}>" if f.get("pr_url") else "no PR (dry run)"
            lines.append(
                f"  • `{f['package']}` {f['old_version']} → {f['new_version']}"
                f" [{f['worst_severity']}] — {pr_link}"
            )
        text = "\n".join(lines)

    try:
        r = requests.post(webhook_url, json={"text": text}, timeout=10)
        if r.status_code != 200:
            logger.warning("Slack notification failed: %d %s", r.status_code, r.text)
        else:
            logger.info("Slack notification sent.")
    except requests.RequestException as e:
        logger.warning("Slack notification error: %s", e)


def send_discord(findings: list[dict], repo: str):
    """Post a scan summary to Discord via webhook."""
    webhook_url = os.environ.get("DISCORD_WEBHOOK_URL", "").strip()
    if not webhook_url:
        return

    if not findings:
        content = f"✅ **{repo}** — Scan complete. No vulnerabilities found above threshold."
    else:
        lines = [f"🔐 **{repo}** — {len(findings)} vulnerability fix(es) prepared:"]
        for f in findings:
            pr_text = (
                f"[PR #{f['pr_number']}]({f['pr_url']})"
                if f.get("pr_url")
                else "no PR (dry run)"
            )
            lines.append(
                f"• `{f['package']}` {f['old_version']} → {f['new_version']}"
                f" [{f['worst_severity']}] — {pr_text}"
            )
        content = "\n".join(lines)

    # Discord enforces a 2000-char limit
    if len(content) > 1900:
        content = content[:1900] + "\n…(truncated)"

    try:
        r = requests.post(webhook_url, json={"content": content}, timeout=10)
        if r.status_code not in (200, 204):
            logger.warning("Discord notification failed: %d %s", r.status_code, r.text)
        else:
            logger.info("Discord notification sent.")
    except requests.RequestException as e:
        logger.warning("Discord notification error: %s", e)


def send_email_digest(findings: list[dict], repo: str):
    """Send a scan digest via SMTP (TLS on port 587)."""
    smtp_host  = os.environ.get("SMTP_HOST", "").strip()
    smtp_port  = int(os.environ.get("SMTP_PORT", "587"))
    smtp_user  = os.environ.get("SMTP_USER", "").strip()
    smtp_pass  = os.environ.get("SMTP_PASS", "").strip()
    alert_email = os.environ.get("ALERT_EMAIL", "").strip()

    if not all([smtp_host, smtp_user, smtp_pass, alert_email]):
        return

    subject = f"[Vuln Patcher] {repo} — {len(findings)} fix(es) this run"

    if not findings:
        body = f"Vulnerability scan for {repo} complete.\n\nNo new vulnerabilities found above threshold."
    else:
        rows = "\n\n".join(
            f"  {f['package']}  {f['old_version']} → {f['new_version']}  [{f['worst_severity']}]\n"
            f"  CVEs: {', '.join(f.get('cve_ids', []))}\n"
            + (f"  PR:   {f['pr_url']}" if f.get("pr_url") else "  PR:   (dry run)")
            for f in findings
        )
        body = f"Vulnerability scan for {repo} — {len(findings)} fix(es):\n\n{rows}"

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = smtp_user
    msg["To"]      = alert_email
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.ehlo()
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_user, [alert_email], msg.as_string())
        logger.info("Email digest sent to %s.", alert_email)
    except Exception as e:
        logger.warning("Email digest failed: %s", e)


def notify_all(findings: list[dict], repo: str):
    """Fire all configured notification channels."""
    send_slack(findings, repo)
    # send_discord(findings, repo)  # disabled — re-enable when Discord account is accessible
    send_email_digest(findings, repo)
