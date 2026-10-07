"""
Build a resource graph from an Inventory: who can reach what, and through
which path. This is the "cartographie" part -- turning a flat list of
resources into a graph you can walk to find attack paths, the same way
zparty chains findings (SSRF -> cloud metadata -> credentials) instead of
reporting them as isolated bugs.
"""
from __future__ import annotations

import networkx as nx

from .collectors import Inventory


def build_graph(inv: Inventory) -> nx.DiGraph:
    g = nx.DiGraph()

    for b in inv.buckets:
        g.add_node(f"s3:{b['name']}", kind="s3_bucket", data=b)

    for sg in inv.security_groups:
        g.add_node(f"sg:{sg['id']}", kind="security_group", data=sg)

    for inst in inv.instances:
        node = f"ec2:{inst['id']}"
        g.add_node(node, kind="ec2_instance", data=inst)
        for sg_id in inst["security_groups"]:
            g.add_edge(node, f"sg:{sg_id}", relation="protected_by")
        if inst["iam_profile"]:
            g.add_edge(node, f"role:{inst['iam_profile']}", relation="assumes")

    for role in inv.roles:
        node = f"role:{role['arn']}"
        g.add_node(node, kind="iam_role", data=role)
        for arn in role["attached_policy_arns"]:
            g.add_edge(node, f"policy:{arn}", relation="has_policy")
        trust = role.get("trust_policy") or {}
        for stmt in trust.get("Statement", []):
            principal = stmt.get("Principal", {})
            if isinstance(principal, dict):
                for key in ("AWS", "Service"):
                    val = principal.get(key)
                    vals = val if isinstance(val, list) else ([val] if val else [])
                    for v in vals:
                        g.add_edge(f"principal:{v}", node, relation="can_assume")

    for user in inv.users:
        node = f"user:{user['arn']}"
        g.add_node(node, kind="iam_user", data=user)
        for arn in user["attached_policy_arns"]:
            g.add_edge(node, f"policy:{arn}", relation="has_policy")

    for arn, doc in inv.policies.items():
        g.add_node(f"policy:{arn}", kind="iam_policy", data=doc)

    return g


def attack_paths_to(g: nx.DiGraph, target_kind: str, max_paths: int = 20) -> list[list[str]]:
    """Return simple paths from any 'principal:*' node to any node of target_kind.

    Used to answer: starting from an identity, what resources can it eventually
    reach through role assumption and attached policies?
    """
    sources = [n for n in g.nodes if n.startswith("principal:")]
    targets = [n for n, d in g.nodes(data=True) if d.get("kind") == target_kind]
    paths = []
    for s in sources:
        for t in targets:
            try:
                for path in nx.all_simple_paths(g, s, t, cutoff=5):
                    paths.append(path)
                    if len(paths) >= max_paths:
                        return paths
            except nx.NodeNotFound:
                continue
    return paths
