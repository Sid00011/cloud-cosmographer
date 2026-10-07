"""Standalone demo: builds the same synthetic vulnerable account as the test
suite (via moto, no real AWS needed) and runs the full scan -> report pipeline,
to produce a real sample report."""
import json
import boto3
from moto import mock_aws

with mock_aws():
    session = boto3.Session(region_name="eu-west-1")
    s3, ec2, iam = session.client("s3"), session.client("ec2"), session.client("iam")

    s3.create_bucket(Bucket="public-leaky-bucket", CreateBucketConfiguration={"LocationConstraint": "eu-west-1"})
    s3.put_bucket_policy(Bucket="public-leaky-bucket", Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                       "Resource": "arn:aws:s3:::public-leaky-bucket/*"}]}))

    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    sg = ec2.create_security_group(GroupName="open-ssh", Description="bad", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[{
        "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])

    admin_policy = iam.create_policy(PolicyName="TooMuchPower", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}))["Policy"]["Arn"]
    iam.create_user(UserName="over-privileged-user")
    iam.attach_user_policy(UserName="over-privileged-user", PolicyArn=admin_policy)
    iam.create_access_key(UserName="over-privileged-user")

    from cloudcosmo.collectors import collect_all
    from cloudcosmo.graph import build_graph
    from cloudcosmo.rules import run_all_rules
    from cloudcosmo.scoring import score_findings
    from cloudcosmo.report import to_html, to_json

    inv = collect_all(session)
    g = build_graph(inv)
    findings = run_all_rules(inv)
    scoring = score_findings(findings)

    print(f"Graph: {g.number_of_nodes()} nodes, {g.number_of_edges()} edges")
    print(f"Findings: {len(findings)}  Score: {scoring['score']}/100  Grade: {scoring['grade']}")
    for f in findings:
        print(f"  [{f.severity:8s}] {f.rule_id:28s} {f.resource}")

    import os
    os.makedirs("results", exist_ok=True)
    open("results/findings.json", "w").write(to_json(findings, scoring))
    open("results/report.html", "w").write(to_html(findings, scoring))
    print("\nWrote results/findings.json and results/report.html")
