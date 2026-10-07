#!/usr/bin/env python3
"""
CloudCosmo CLI.

Usage:
    python main.py scan --profile myprofile --region eu-west-3 --output results/

Requires only read permissions (e.g. the AWS-managed ReadOnlyAccess policy).
Nothing is ever created, modified, or deleted.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import boto3

from cloudcosmo.collectors import collect_all
from cloudcosmo.graph import attack_paths_to, build_graph
from cloudcosmo.report import to_html, to_json
from cloudcosmo.rules import run_all_rules
from cloudcosmo.scoring import score_findings


def main() -> int:
    ap = argparse.ArgumentParser(description="CloudCosmo - AWS resource graph and misconfiguration mapper")
    ap.add_argument("action", choices=["scan"])
    ap.add_argument("--profile", default=None, help="AWS named profile (see ~/.aws/credentials)")
    ap.add_argument("--region", default="eu-west-1")
    ap.add_argument("--output", default="results", help="Output directory")
    args = ap.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)

    print(f"[*] Collecting inventory (region={args.region}, profile={args.profile or 'default'})...")
    inv = collect_all(session)
    print(f"[*] {len(inv.buckets)} buckets, {len(inv.security_groups)} security groups, "
          f"{len(inv.instances)} instances, {len(inv.roles)} roles, {len(inv.users)} users.")

    print("[*] Building resource graph...")
    g = build_graph(inv)
    print(f"[*] Graph: {g.number_of_nodes()} nodes, {g.number_of_edges()} edges.")

    print("[*] Running detection rules...")
    findings = run_all_rules(inv)
    scoring = score_findings(findings)
    print(f"[*] {len(findings)} finding(s). Score: {scoring['score']}/100 ({scoring['grade']}).")

    paths_to_s3 = attack_paths_to(g, "s3_bucket")
    if paths_to_s3:
        print(f"[*] {len(paths_to_s3)} identity-to-S3-bucket path(s) found via role assumption.")

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    (out / "findings.json").write_text(to_json(findings, scoring), encoding="utf-8")
    (out / "report.html").write_text(to_html(findings, scoring), encoding="utf-8")
    print(f"[*] Reports written to {out}/findings.json and {out}/report.html")
    return 0


if __name__ == "__main__":
    sys.exit(main())
