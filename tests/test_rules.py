"""
Builds a small synthetic AWS account entirely in memory with moto (no real
AWS account, no network, no credentials needed) containing one deliberate
misconfiguration of each kind, then asserts CloudCosmo detects every one of
them and detects nothing extra on a clean control resource.

Run: pytest -v
"""
import json

import boto3
import pytest
from moto import mock_aws

from cloudcosmo.collectors import collect_all
from cloudcosmo.rules import run_all_rules
from cloudcosmo.scoring import score_findings

REGION = "eu-west-1"


@pytest.fixture
def vulnerable_account():
    with mock_aws():
        session = boto3.Session(region_name=REGION)
        s3 = session.client("s3")
        ec2 = session.client("ec2")
        iam = session.client("iam")

        # --- S3: one public bucket, one private control bucket ---
        s3.create_bucket(Bucket="public-leaky-bucket",
                          CreateBucketConfiguration={"LocationConstraint": REGION})
        s3.put_bucket_policy(Bucket="public-leaky-bucket", Policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": "*",
                           "Action": "s3:GetObject", "Resource": "arn:aws:s3:::public-leaky-bucket/*"}],
        }))

        s3.create_bucket(Bucket="private-control-bucket",
                          CreateBucketConfiguration={"LocationConstraint": REGION})
        s3.put_public_access_block(Bucket="private-control-bucket", PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
        })

        # --- EC2: a security group open to the world on SSH ---
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        sg = ec2.create_security_group(GroupName="open-ssh", Description="bad sg", VpcId=vpc)["GroupId"]
        ec2.authorize_security_group_ingress(
            GroupId=sg, IpPermissions=[{
                "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }])

        # --- IAM: one wildcard admin policy, attached to a user with active keys ---
        admin_policy = iam.create_policy(PolicyName="TooMuchPower", PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        }))["Policy"]["Arn"]
        iam.create_user(UserName="over-privileged-user")
        iam.attach_user_policy(UserName="over-privileged-user", PolicyArn=admin_policy)
        key = iam.create_access_key(UserName="over-privileged-user")
        assert key["AccessKey"]["Status"] == "Active"

        # --- IAM: a role with a known privesc action combo ---
        privesc_policy = iam.create_policy(PolicyName="PrivescPath", PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Action": ["iam:PassRole", "ec2:RunInstances"],
                           "Resource": "*"}],
        }))["Policy"]["Arn"]
        iam.create_role(RoleName="escalatable-role", AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
                           "Action": "sts:AssumeRole"}],
        }))
        iam.attach_role_policy(RoleName="escalatable-role", PolicyArn=privesc_policy)

        # --- A clean, boring IAM user that should trigger nothing ---
        iam.create_user(UserName="read-only-reporting-user")

        yield session


def test_detects_public_s3_bucket(vulnerable_account):
    inv = collect_all(vulnerable_account)
    findings = run_all_rules(inv)
    hits = [f for f in findings if f.rule_id == "S3_PUBLIC_BUCKET"]
    assert len(hits) == 1
    assert hits[0].resource == "s3:public-leaky-bucket"


def test_does_not_flag_protected_bucket(vulnerable_account):
    inv = collect_all(vulnerable_account)
    findings = run_all_rules(inv)
    flagged_buckets = {f.resource for f in findings if f.rule_id == "S3_PUBLIC_BUCKET"}
    assert "s3:private-control-bucket" not in flagged_buckets


def test_detects_security_group_open_to_world(vulnerable_account):
    inv = collect_all(vulnerable_account)
    findings = run_all_rules(inv)
    hits = [f for f in findings if f.rule_id == "SG_OPEN_TO_WORLD"]
    assert len(hits) == 1
    assert hits[0].severity == "Critical"  # port 22 = SSH, sensitive


def test_detects_iam_wildcard_policy(vulnerable_account):
    inv = collect_all(vulnerable_account)
    findings = run_all_rules(inv)
    hits = [f for f in findings if f.rule_id == "IAM_WILDCARD_POLICY"]
    assert len(hits) == 1


def test_detects_admin_user_with_active_keys(vulnerable_account):
    inv = collect_all(vulnerable_account)
    findings = run_all_rules(inv)
    hits = [f for f in findings if f.rule_id == "ADMIN_USER_WITH_ACTIVE_KEYS"]
    assert len(hits) == 1
    assert "over-privileged-user" in hits[0].resource


def test_detects_privesc_pattern_on_role(vulnerable_account):
    inv = collect_all(vulnerable_account)
    findings = run_all_rules(inv)
    hits = [f for f in findings if f.rule_id == "IAM_PRIVESC_PATTERN"]
    assert any("escalatable-role" in f.resource for f in hits)


def test_clean_user_triggers_nothing(vulnerable_account):
    inv = collect_all(vulnerable_account)
    findings = run_all_rules(inv)
    flagged = {f.resource for f in findings}
    assert not any("read-only-reporting-user" in r for r in flagged)


def test_score_reflects_findings(vulnerable_account):
    inv = collect_all(vulnerable_account)
    findings = run_all_rules(inv)
    scoring = score_findings(findings)
    assert scoring["score"] < 100
    assert scoring["grade"] in {"D", "E"}  # several Critical findings present
    assert scoring["total_findings"] == len(findings)
