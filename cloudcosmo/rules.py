"""
Misconfiguration detection rules.

Each rule is a plain function: (Inventory) -> list[Finding]. Keeping rules as
small independent functions mirrors zparty's module layout (one file per
vulnerability class), so new checks can be added without touching the engine.
"""
from __future__ import annotations

from dataclasses import dataclass

SENSITIVE_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL",
                    6379: "Redis", 9200: "Elasticsearch", 27017: "MongoDB"}

# A handful of well-documented AWS IAM privilege-escalation action combinations
# (publicly catalogued by AWS security researchers). Each entry: a set of
# actions that, together on one identity, allow escalating privileges.
PRIVESC_PATTERNS = {
    "pass_role_to_new_ec2": {"iam:PassRole", "ec2:RunInstances"},
    "create_policy_version": {"iam:CreatePolicyVersion"},
    "attach_user_policy": {"iam:AttachUserPolicy"},
    "put_user_policy": {"iam:PutUserPolicy"},
    "update_assume_role_policy": {"iam:UpdateAssumeRolePolicy"},
}


@dataclass
class Finding:
    rule_id: str
    severity: str  # Critical | High | Medium | Low
    resource: str
    description: str
    evidence: dict


def _policy_actions(doc: dict) -> set[str]:
    actions: set[str] = set()
    if not doc:
        return actions
    for stmt in doc.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        acts = stmt.get("Action", [])
        acts = acts if isinstance(acts, list) else [acts]
        actions.update(acts)
    return actions


def rule_public_s3_bucket(inv) -> list[Finding]:
    out = []
    for b in inv.buckets:
        if b["public_acl"] or b["public_policy"]:
            pab = b["block_public_access"] or {}
            fully_blocked = all(pab.get(k) for k in
                                 ("BlockPublicAcls", "BlockPublicPolicy",
                                  "IgnorePublicAcls", "RestrictPublicBuckets"))
            if not fully_blocked:
                out.append(Finding(
                    rule_id="S3_PUBLIC_BUCKET", severity="Critical",
                    resource=f"s3:{b['name']}",
                    description=f"Bucket '{b['name']}' est accessible publiquement "
                                f"(ACL publique: {b['public_acl']}, policy publique: {b['public_policy']}) "
                                f"et Block Public Access n'est pas pleinement activé.",
                    evidence={"public_acl": b["public_acl"], "public_policy": b["public_policy"],
                              "block_public_access": pab},
                ))
    return out


def rule_security_group_open_to_world(inv) -> list[Finding]:
    out = []
    for sg in inv.security_groups:
        for rule in sg["open_to_world"]:
            port = rule.get("from_port")
            severity = "Critical" if port in SENSITIVE_PORTS else "High"
            service = SENSITIVE_PORTS.get(port, f"port {port}")
            out.append(Finding(
                rule_id="SG_OPEN_TO_WORLD", severity=severity,
                resource=f"sg:{sg['id']}",
                description=f"Security group '{sg['name']}' ({sg['id']}) autorise {service} "
                            f"depuis 0.0.0.0/0.",
                evidence=rule,
            ))
    return out


def rule_iam_wildcard_policy(inv) -> list[Finding]:
    out = []
    for arn, doc in inv.policies.items():
        for stmt in doc.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            actions = stmt.get("Action", [])
            actions = actions if isinstance(actions, list) else [actions]
            resources = stmt.get("Resource", [])
            resources = resources if isinstance(resources, list) else [resources]
            if "*" in actions and "*" in resources:
                out.append(Finding(
                    rule_id="IAM_WILDCARD_POLICY", severity="Critical",
                    resource=f"policy:{arn}",
                    description=f"La policy '{arn}' autorise Action:* sur Resource:* "
                                f"(privilège administrateur de facto).",
                    evidence={"statement": stmt},
                ))
    return out


def rule_iam_privesc_patterns(inv) -> list[Finding]:
    out = []
    for identity in list(inv.roles) + list(inv.users):
        actions: set[str] = set()
        for doc in identity.get("inline_policies", []):
            actions |= _policy_actions(doc)
        for arn in identity.get("attached_policy_arns", []):
            actions |= _policy_actions(inv.policies.get(arn, {}))

        for pattern_name, needed in PRIVESC_PATTERNS.items():
            if needed.issubset(actions):
                kind = "role" if "RoleName" in identity or "trust_policy" in identity else "user"
                out.append(Finding(
                    rule_id="IAM_PRIVESC_PATTERN", severity="High",
                    resource=f"{'role' if kind == 'role' else 'user'}:{identity.get('arn', identity.get('name'))}",
                    description=f"L'identité '{identity.get('name')}' dispose des permissions "
                                f"{sorted(needed)}, un chemin d'escalade de privilèges connu ({pattern_name}).",
                    evidence={"pattern": pattern_name, "actions": sorted(needed)},
                ))
    return out


def rule_root_like_access_keys(inv) -> list[Finding]:
    out = []
    for user in inv.users:
        if user["active_access_keys"] and user["attached_policy_arns"]:
            for arn in user["attached_policy_arns"]:
                doc = inv.policies.get(arn, {})
                actions = _policy_actions(doc)
                if "*" in actions:
                    out.append(Finding(
                        rule_id="ADMIN_USER_WITH_ACTIVE_KEYS", severity="High",
                        resource=f"user:{user['arn']}",
                        description=f"L'utilisateur '{user['name']}' a des clés d'accès actives "
                                    f"et une policy administrateur attachée.",
                        evidence={"active_keys": user["active_access_keys"]},
                    ))
    return out


ALL_RULES = [
    rule_public_s3_bucket,
    rule_security_group_open_to_world,
    rule_iam_wildcard_policy,
    rule_iam_privesc_patterns,
    rule_root_like_access_keys,
]


def run_all_rules(inv) -> list[Finding]:
    findings: list[Finding] = []
    for rule in ALL_RULES:
        findings.extend(rule(inv))
    return findings
