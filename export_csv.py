#!/usr/bin/env python3
"""
Exports scanner.py's JSON report to CSV — one row per finding.
Usage: python export_csv.py [report.json] [--out findings.csv]
"""

import argparse
import csv
import json

FIELDNAMES = ["bucket", "severity", "check", "message"]


def export(data, out_path):
    rows = []

    for bucket, findings in data["results"].items():
        for f in findings:
            if f["severity"] == "INFO":
                continue

            rows.append({
                "bucket": bucket,
                "severity": f["severity"],
                "check": f["check"],
                "message": f["message"],
            })

    severity_order = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
    }

    rows.sort(
        key=lambda r: severity_order.get(r["severity"], 99)
    )

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)

    return len(rows)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", nargs="?", default="report.json")
    parser.add_argument("--out", default="findings.csv")
    args = parser.parse_args()

    with open(args.input, encoding="utf-8") as f:
        data = json.load(f)

    count = export(data, args.out)

    print(f"[*] Wrote {count} finding(s) to {args.out}")


if __name__ == "__main__":
    main()