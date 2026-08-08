#!/usr/bin/env python3
"""
Sends an alert (Slack and/or email) summarizing Critical/High findings
from a scanner.py JSON report. Designed to be run right after scanner.py,
or wired into a scheduled job (cron / Lambda) for continuous monitoring.

Slack setup:
    Create an Incoming Webhook in your Slack workspace, then either:
      export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
    or pass --slack-webhook directly.

Email setup (optional, uses SMTP):
    export SMTP_HOST="smtp.gmail.com"
    export SMTP_PORT="587"
    export SMTP_USER="you@example.com"
    export SMTP_PASS="app-specific-password"
    export ALERT_EMAIL_TO="you@example.com"

Usage:
    python alert.py report.json --slack
    python alert.py report.json --email
    python alert.py report.json --slack --email --min-severity HIGH
"""

import argparse
import json
import os
import smtplib
import sys
import urllib.request
from email.mime.text import MIMEText

SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def collect_alertable_findings(data, min_severity):
    threshold = SEVERITY_RANK.get(min_severity, 0)
    alertable = []
    for bucket, findings in data["results"].items():
        for f in findings:
            if SEVERITY_RANK.get(f["severity"], 99) <= threshold:
                alertable.append((bucket, f))
    alertable.sort(key=lambda bf: SEVERITY_RANK.get(bf[1]["severity"], 99))
    return alertable


def build_summary_text(alertable, scan_time):
    if not alertable:
        return None

    lines = [f"*S3 Security Audit — {len(alertable)} finding(s) at or above threshold*",
             f"Scan time: {scan_time}", ""]
    for bucket, f in alertable[:20]:  # cap to keep messages readable
        lines.append(f"• [{f['severity']}] `{bucket}` — {f['message']}")
    if len(alertable) > 20:
        lines.append(f"...and {len(alertable) - 20} more. See full report for details.")
    return "\n".join(lines)


def send_slack(webhook_url, text):
    payload = json.dumps({"text": text}).encode("utf-8")
    req = urllib.request.Request(
        webhook_url, data=payload, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status == 200:
                print("[*] Slack alert sent.")
            else:
                print(f"[!] Slack responded with status {resp.status}")
    except Exception as e:
        print(f"[!] Failed to send Slack alert: {e}")


def send_email(text):
    host = os.environ.get("SMTP_HOST")
    port = int(os.environ.get("SMTP_PORT", "587"))
    user = os.environ.get("SMTP_USER")
    password = os.environ.get("SMTP_PASS")
    to_addr = os.environ.get("ALERT_EMAIL_TO")

    missing = [n for n, v in [("SMTP_HOST", host), ("SMTP_USER", user),
                               ("SMTP_PASS", password), ("ALERT_EMAIL_TO", to_addr)] if not v]
    if missing:
        print(f"[!] Missing env vars for email: {', '.join(missing)}. Skipping email alert.")
        return

    msg = MIMEText(text)
    msg["Subject"] = "S3 Security Audit — Critical findings"
    msg["From"] = user
    msg["To"] = to_addr

    try:
        with smtplib.SMTP(host, port, timeout=10) as server:
            server.starttls()
            server.login(user, password)
            server.sendmail(user, [to_addr], msg.as_string())
        print("[*] Email alert sent.")
    except Exception as e:
        print(f"[!] Failed to send email alert: {e}")


def main():
    parser = argparse.ArgumentParser(description="Alert on Critical/High findings from a scan report.")
    parser.add_argument("input", nargs="?", default="report.json")
    parser.add_argument("--slack", action="store_true", help="Send a Slack alert")
    parser.add_argument("--email", action="store_true", help="Send an email alert")
    parser.add_argument("--slack-webhook", default=None, help="Override SLACK_WEBHOOK_URL env var")
    parser.add_argument("--min-severity", default="CRITICAL",
                         choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                         help="Minimum severity to alert on (default: CRITICAL)")
    args = parser.parse_args()

    if not args.slack and not args.email:
        print("[!] Specify --slack and/or --email, or nothing happens.")
        sys.exit(1)

    with open(args.input) as f:
        data = json.load(f)

    alertable = collect_alertable_findings(data, args.min_severity)
    summary = build_summary_text(alertable, data.get("scan_time", "unknown"))

    if not summary:
        print(f"[*] No findings at or above {args.min_severity}. No alert sent.")
        return

    if args.slack:
        webhook = args.slack_webhook or os.environ.get("SLACK_WEBHOOK_URL")
        if not webhook:
            print("[!] No Slack webhook URL provided (set SLACK_WEBHOOK_URL or use --slack-webhook).")
        else:
            send_slack(webhook, summary)

    if args.email:
        send_email(summary)


if __name__ == "__main__":
    main()
