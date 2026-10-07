"""
Read-only AWS inventory collectors.

Every function here only calls List*/Describe*/Get* APIs. Nothing is ever
created, modified or deleted. Intended to run with a read-only IAM policy
(e.g. the AWS managed "ReadOnlyAccess" policy, or narrower).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field


@dataclass
class Inventory:
    buckets: list[dict] = field(default_factory=list)
    security_groups: list[dict] = field(default_factory=list)
    instances: list[dict] = field(default_factory=list)
    roles: list[dict] = field(default_factory=list)
    users: list[dict] = field(default_factory=list)
    policies: dict[str, dict] = field(default_factory=dict)  # policy_arn -> document


def collect_s3(s3_client) -> list[dict]:
    buckets = []
    for b in s3_client.list_buckets().get("Buckets", []):
        name = b["Name"]
        entry = {"name": name, "public_acl": False, "public_policy": False,
                 "block_public_access": None, "policy": None}

        try:
            acl = s3_client.get_bucket_acl(Bucket=name)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                uri = grantee.get("URI", "")
                if uri.endswith("/AllUsers") or uri.endswith("/AuthenticatedUsers"):
                    entry["public_acl"] = True
        except Exception:
            pass

        try:
            pab = s3_client.get_public_access_block(Bucket=name)
            entry["block_public_access"] = pab["PublicAccessBlockConfiguration"]
        except Exception:
            entry["block_public_access"] = None  # no block configured = more exposed

        try:
            pol = s3_client.get_bucket_policy(Bucket=name)
            doc = json.loads(pol["Policy"])
            entry["policy"] = doc
            for stmt in doc.get("Statement", []):
                principal = stmt.get("Principal")
                if stmt.get("Effect") == "Allow" and (principal == "*" or principal == {"AWS": "*"}):
                    entry["public_policy"] = True
        except Exception:
            pass

        buckets.append(entry)
    return buckets


def collect_security_groups(ec2_client) -> list[dict]:
    groups = []
    for sg in ec2_client.describe_security_groups().get("SecurityGroups", []):
        ingress = []
        for perm in sg.get("IpPermissions", []):
            from_port = perm.get("FromPort")
            to_port = perm.get("ToPort")
            for rng in perm.get("IpRanges", []):
                if rng.get("CidrIp") == "0.0.0.0/0":
                    ingress.append({"from_port": from_port, "to_port": to_port,
                                     "protocol": perm.get("IpProtocol"), "cidr": "0.0.0.0/0"})
        groups.append({
            "id": sg["GroupId"], "name": sg.get("GroupName", ""),
            "vpc_id": sg.get("VpcId"), "open_to_world": ingress,
        })
    return groups


def collect_instances(ec2_client) -> list[dict]:
    instances = []
    for res in ec2_client.describe_instances().get("Reservations", []):
        for inst in res.get("Instances", []):
            instances.append({
                "id": inst["InstanceId"],
                "security_groups": [g["GroupId"] for g in inst.get("SecurityGroups", [])],
                "public_ip": inst.get("PublicIpAddress"),
                "iam_profile": (inst.get("IamInstanceProfile") or {}).get("Arn"),
            })
    return instances


def collect_iam(iam_client) -> tuple[list[dict], list[dict], dict[str, dict]]:
    roles = []
    for role in iam_client.list_roles().get("Roles", []):
        name = role["RoleName"]
        attached = iam_client.list_attached_role_policies(RoleName=name)
        policy_arns = [p["PolicyArn"] for p in attached.get("AttachedPolicies", [])]
        inline_names = iam_client.list_role_policies(RoleName=name).get("PolicyNames", [])
        inline_docs = []
        for pname in inline_names:
            doc = iam_client.get_role_policy(RoleName=name, PolicyName=pname)
            inline_docs.append(doc["PolicyDocument"])
        roles.append({
            "name": name, "arn": role["Arn"],
            "trust_policy": role.get("AssumeRolePolicyDocument"),
            "attached_policy_arns": policy_arns,
            "inline_policies": inline_docs,
        })

    users = []
    for user in iam_client.list_users().get("Users", []):
        name = user["UserName"]
        attached = iam_client.list_attached_user_policies(UserName=name)
        policy_arns = [p["PolicyArn"] for p in attached.get("AttachedPolicies", [])]
        inline_names = iam_client.list_user_policies(UserName=name).get("PolicyNames", [])
        inline_docs = []
        for pname in inline_names:
            doc = iam_client.get_user_policy(UserName=name, PolicyName=pname)
            inline_docs.append(doc["PolicyDocument"])
        keys = iam_client.list_access_keys(UserName=name).get("AccessKeyMetadata", [])
        users.append({
            "name": name, "arn": user["Arn"],
            "attached_policy_arns": policy_arns,
            "inline_policies": inline_docs,
            "active_access_keys": [k["AccessKeyId"] for k in keys if k["Status"] == "Active"],
        })

    policies: dict[str, dict] = {}
    for pol in iam_client.list_policies(Scope="Local").get("Policies", []):
        arn = pol["Arn"]
        version_id = pol["DefaultVersionId"]
        v = iam_client.get_policy_version(PolicyArn=arn, VersionId=version_id)
        policies[arn] = v["PolicyVersion"]["Document"]

    return roles, users, policies


def collect_all(session) -> Inventory:
    """Run every collector against a boto3 Session and return one Inventory."""
    s3 = session.client("s3")
    ec2 = session.client("ec2")
    iam = session.client("iam")

    inv = Inventory()
    inv.buckets = collect_s3(s3)
    inv.security_groups = collect_security_groups(ec2)
    inv.instances = collect_instances(ec2)
    inv.roles, inv.users, inv.policies = collect_iam(iam)
    return inv
