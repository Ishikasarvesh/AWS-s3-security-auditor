#!/usr/bin/env python3
"""
S3 Security Auditor
--------------------
Scans all S3 buckets in an AWS account for common misconfigurations
that are a leading cause of real-world cloud data breaches.

Checks performed:
  1. Public Access Block settings
  2. Bucket ACL (public read/write grants)
  3. Bucket Policy (wildcard Principal, public statements)
  4. Server-side encryption at rest
  5. Versioning (protects against accidental delete / ransomware)
  6. Server access logging

Usage:
    python scanner.py [--profile PROFILE_NAME] [--region REGION]

Requires read-only AWS credentials (see IAM policy in README).
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound

SEVERITY = {
    "public_access_block": "CRITICAL",
    "public_acl": "CRITICAL",
    "public_policy": "CRITICAL",
    "no_encryption": "HIGH",
    "no_versioning": "MEDIUM",
    "no_logging": "LOW",
}


def get_session(profile=None):
    try:
        return boto3.Session(profile_name=profile) if profile else boto3.Session()
    except ProfileNotFound:
        print(f"[!] AWS profile '{profile}' not found. Check ~/.aws/credentials")
        sys.exit(1)


def list_buckets(s3_client):
    try:
        return [b["Name"] for b in s3_client.list_buckets().get("Buckets", [])]
    except NoCredentialsError:
        print("[!] No AWS credentials found. Configure with `aws configure`.")
        sys.exit(1)
    except ClientError as e:
        print(f"[!] Could not list buckets: {e}")
        sys.exit(1)


def check_public_access_block(s3_client, bucket, findings):
    try:
        cfg = s3_client.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
        all_blocked = all(cfg.values())
        if not all_blocked:
            findings.append({
                "check": "public_access_block",
                "severity": SEVERITY["public_access_block"],
                "message": "Block Public Access is not fully enabled",
                "detail": cfg,
            })
    except ClientError as e:
        # If there's no config at all, S3 treats the bucket as NOT protected
        if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            findings.append({
                "check": "public_access_block",
                "severity": SEVERITY["public_access_block"],
                "message": "No Block Public Access configuration set (bucket is unprotected by default)",
                "detail": None,
            })
        else:
            findings.append({"check": "public_access_block", "severity": "INFO",
                              "message": f"Could not check: {e}", "detail": None})


def check_acl(s3_client, bucket, findings):
    try:
        acl = s3_client.get_bucket_acl(Bucket=bucket)
        public_uris = {
            "http://acs.amazonaws.com/groups/global/AllUsers",
            "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
        }
        for grant in acl.get("Grants", []):
            grantee = grant.get("Grantee", {})
            if grantee.get("URI") in public_uris:
                findings.append({
                    "check": "public_acl",
                    "severity": SEVERITY["public_acl"],
                    "message": f"ACL grants '{grant['Permission']}' to {grantee.get('URI')}",
                    "detail": grant,
                })
    except ClientError as e:
        findings.append({"check": "public_acl", "severity": "INFO",
                          "message": f"Could not check ACL: {e}", "detail": None})


def check_bucket_policy(s3_client, bucket, findings):
    try:
        policy_str = s3_client.get_bucket_policy(Bucket=bucket)["Policy"]
        policy = json.loads(policy_str)
        for stmt in policy.get("Statement", []):
            principal = stmt.get("Principal")
            effect = stmt.get("Effect")
            is_wildcard = principal == "*" or (
                isinstance(principal, dict) and principal.get("AWS") == "*"
            )
            if effect == "Allow" and is_wildcard:
                findings.append({
                    "check": "public_policy",
                    "severity": SEVERITY["public_policy"],
                    "message": "Bucket policy allows public (wildcard Principal) access",
                    "detail": stmt,
                })
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
            findings.append({"check": "public_policy", "severity": "INFO",
                              "message": f"Could not check policy: {e}", "detail": None})


def check_encryption(s3_client, bucket, findings):
    try:
        s3_client.get_bucket_encryption(Bucket=bucket)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
            findings.append({
                "check": "no_encryption",
                "severity": SEVERITY["no_encryption"],
                "message": "Default server-side encryption is not enabled",
                "detail": None,
            })
        else:
            findings.append({"check": "no_encryption", "severity": "INFO",
                              "message": f"Could not check encryption: {e}", "detail": None})


def check_versioning(s3_client, bucket, findings):
    try:
        resp = s3_client.get_bucket_versioning(Bucket=bucket)
        if resp.get("Status") != "Enabled":
            findings.append({
                "check": "no_versioning",
                "severity": SEVERITY["no_versioning"],
                "message": "Versioning is not enabled (no protection against accidental delete/overwrite)",
                "detail": None,
            })
    except ClientError as e:
        findings.append({"check": "no_versioning", "severity": "INFO",
                          "message": f"Could not check versioning: {e}", "detail": None})


def check_logging(s3_client, bucket, findings):
    try:
        resp = s3_client.get_bucket_logging(Bucket=bucket)
        if "LoggingEnabled" not in resp:
            findings.append({
                "check": "no_logging",
                "severity": SEVERITY["no_logging"],
                "message": "Server access logging is not enabled",
                "detail": None,
            })
    except ClientError as e:
        findings.append({"check": "no_logging", "severity": "INFO",
                          "message": f"Could not check logging: {e}", "detail": None})


def scan_bucket(s3_client, bucket):
    findings = []
    check_public_access_block(s3_client, bucket, findings)
    check_acl(s3_client, bucket, findings)
    check_bucket_policy(s3_client, bucket, findings)
    check_encryption(s3_client, bucket, findings)
    check_versioning(s3_client, bucket, findings)
    check_logging(s3_client, bucket, findings)
    return findings


def main():
    parser = argparse.ArgumentParser(description="Audit S3 buckets for common security misconfigurations.")
    parser.add_argument("--profile", help="AWS named profile to use", default=None)
    parser.add_argument("--region", help="AWS region", default="us-east-1")
    parser.add_argument("--out", help="Output JSON report path", default="report.json")
    parser.add_argument("--csv", action="store_true", help="Also export findings.csv")
    parser.add_argument("--html", action="store_true", help="Also generate report.html")
    parser.add_argument("--slack", action="store_true", help="Send Slack alert for Critical findings")
    parser.add_argument("--email", action="store_true", help="Send email alert for Critical findings")
    args = parser.parse_args()

    session = get_session(args.profile)
    s3_client = session.client("s3", region_name=args.region)

    buckets = list_buckets(s3_client)
    print(f"[*] Found {len(buckets)} bucket(s). Scanning...\n")

    report = {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "bucket_count": len(buckets),
        "results": {},
    }

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    for bucket in buckets:
        findings = scan_bucket(s3_client, bucket)
        findings.sort(key=lambda f: severity_order.get(f["severity"], 99))
        report["results"][bucket] = findings

        if findings:
            worst = findings[0]["severity"]
            print(f"  [{worst:8}] {bucket} — {len(findings)} finding(s)")
        else:
            print(f"  [OK      ] {bucket} — no issues found")

    with open(args.out, "w") as f:
        json.dump(report, f, indent=2, default=str)

    print(f"\n[*] Full report written to {args.out}")

    if args.csv:
        from export_csv import export as export_csv
        count = export_csv(report, "findings.csv")
        print(f"[*] Exported {count} finding(s) to findings.csv")

    if args.html:
        from report import build_report
        with open("report.html", "w") as f:
            f.write(build_report(report))
        print("[*] HTML report written to report.html")

    if args.slack or args.email:
        from alert import collect_alertable_findings, build_summary_text, send_slack, send_email
        alertable = collect_alertable_findings(report, "CRITICAL")
        summary = build_summary_text(alertable, report["scan_time"])
        if summary:
            if args.slack:
                webhook = os.environ.get("SLACK_WEBHOOK_URL")
                if webhook:
                    send_slack(webhook, summary)
                else:
                    print("[!] SLACK_WEBHOOK_URL not set — skipping Slack alert.")
            if args.email:
                send_email(summary)
        else:
            print("[*] No Critical findings — no alert sent.")

    if not (args.csv or args.html):
        print("[*] Run `python report.py` for HTML or `python export_csv.py` for CSV.")


if __name__ == "__main__":
    main()
