#!/usr/bin/env python3
"""
Generates a clean HTML report from scanner.py's JSON output.
Usage: python report.py [report.json] [--out report.html]
"""

import argparse
import json
from html import escape

SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#ca8a04",
    "LOW": "#2563eb",
    "INFO": "#6b7280",
}

TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>S3 Security Audit Report</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; background:#0f172a; color:#e2e8f0; margin:0; padding:2rem; }}
  h1 {{ font-size:1.5rem; margin-bottom:0.25rem; }}
  .meta {{ color:#94a3b8; margin-bottom:2rem; font-size:0.9rem; }}
  .summary {{ display:flex; gap:1rem; margin-bottom:2rem; flex-wrap:wrap; }}
  .stat {{ background:#1e293b; border-radius:8px; padding:0.75rem 1.25rem; min-width:110px; }}
  .stat .num {{ font-size:1.6rem; font-weight:700; }}
  .stat .label {{ font-size:0.75rem; color:#94a3b8; text-transform:uppercase; letter-spacing:0.05em; }}
  .bucket {{ background:#1e293b; border-radius:10px; padding:1.25rem 1.5rem; margin-bottom:1rem; }}
  .bucket h2 {{ margin:0 0 0.75rem 0; font-size:1.1rem; display:flex; align-items:center; gap:0.5rem; }}
  .ok {{ color:#22c55e; font-size:0.85rem; }}
  .finding {{ display:flex; gap:0.75rem; padding:0.5rem 0; border-top:1px solid #334155; }}
  .finding:first-child {{ border-top:none; }}
  .badge {{ font-size:0.7rem; font-weight:700; padding:0.15rem 0.5rem; border-radius:4px; color:white; height:fit-content; white-space:nowrap; }}
  .msg {{ font-size:0.9rem; }}
</style>
</head>
<body>
  <h1>🔎 S3 Security Audit Report</h1>
  <div class="meta">Scanned {bucket_count} bucket(s) at {scan_time}</div>
  <div class="summary">{summary_html}</div>
  {buckets_html}
</body>
</html>
"""


def build_report(data):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    buckets_html = ""

    for bucket, findings in data["results"].items():
        real_findings = [f for f in findings if f["severity"] != "INFO"]
        for f in real_findings:
            if f["severity"] in counts:
                counts[f["severity"]] += 1

        if not real_findings:
            buckets_html += f'<div class="bucket"><h2>🪣 {escape(bucket)}</h2><div class="ok">✓ No issues found</div></div>\n'
            continue

        rows = ""
        for f in real_findings:
            color = SEVERITY_COLORS.get(f["severity"], "#6b7280")
            rows += (
                f'<div class="finding">'
                f'<span class="badge" style="background:{color}">{f["severity"]}</span>'
                f'<span class="msg">{escape(f["message"])}</span>'
                f'</div>\n'
            )
        buckets_html += f'<div class="bucket"><h2>🪣 {escape(bucket)}</h2>{rows}</div>\n'

    summary_html = ""
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        color = SEVERITY_COLORS[sev]
        summary_html += (
            f'<div class="stat"><div class="num" style="color:{color}">{counts[sev]}</div>'
            f'<div class="label">{sev}</div></div>\n'
        )

    return TEMPLATE.format(
        bucket_count=data["bucket_count"],
        scan_time=data["scan_time"],
        summary_html=summary_html,
        buckets_html=buckets_html,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", nargs="?", default="report.json")
    parser.add_argument("--out", default="report.html")
    args = parser.parse_args()

    with open(args.input) as f:
        data = json.load(f)

    html = build_report(data)
    with open(args.input.replace(".json", ".html"), "w", encoding="utf-8") as f:
      f.write(html)

    print(f"[*] HTML report written to {args.out}")


if __name__ == "__main__":
    main()
