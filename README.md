# CloudCosmo

Read-only AWS resource graph and misconfiguration mapper. Built as a direct,
small-scale answer to the question "how do you cartograph a cloud environment
and find exploitable misconfigurations", using the same pipeline shape and
scoring model as [zparty](https://github.com/Sid00011/zparty) (collect ->
detect -> score -> report), applied to a cloud account's resource graph
instead of a web application's endpoints.

## What it does

1. **Collects** a read-only inventory of S3 buckets, EC2 security groups and
   instances, and IAM roles/users/policies via `boto3` (`List*`/`Describe*`/
   `Get*` calls only -- nothing is ever created, modified or deleted).
2. **Builds a graph** (`networkx`) linking identities to the roles they can
   assume, the policies attached to them, and the resources those policies
   touch -- so a finding isn't just "this bucket is public", it's "this
   principal can reach this bucket through this chain".
3. **Runs detection rules**, each a small independent function:
   - `S3_PUBLIC_BUCKET` -- public ACL or bucket policy without full Block
     Public Access
   - `SG_OPEN_TO_WORLD` -- security group ingress from `0.0.0.0/0`,
     severity raised on sensitive ports (SSH, RDP, databases)
   - `IAM_WILDCARD_POLICY` -- a policy allowing `Action:*` on `Resource:*`
   - `IAM_PRIVESC_PATTERN` -- known IAM privilege-escalation action
     combinations (e.g. `iam:PassRole` + `ec2:RunInstances`,
     `iam:CreatePolicyVersion`, `iam:AttachUserPolicy`)
   - `ADMIN_USER_WITH_ACTIVE_KEYS` -- a user with an admin-level policy and
     active (non-rotated) access keys
4. **Scores and reports**: same severity-penalty / S-to-E grade model as
   zparty's scoring engine, exported as JSON and a single-file HTML report.

## Why it's tested without a real AWS account

The test suite (`tests/test_rules.py`) uses
[`moto`](https://github.com/getmoto/moto) to build a small synthetic AWS
account entirely in memory -- no network calls, no real credentials, no
cost. It plants one deliberate instance of each misconfiguration class plus
two clean control resources, and asserts CloudCosmo catches every planted
bug and flags nothing extra:

```
$ pytest -v
tests/test_rules.py::test_detects_public_s3_bucket PASSED
tests/test_rules.py::test_does_not_flag_protected_bucket PASSED
tests/test_rules.py::test_detects_security_group_open_to_world PASSED
tests/test_rules.py::test_detects_iam_wildcard_policy PASSED
tests/test_rules.py::test_detects_admin_user_with_active_keys PASSED
tests/test_rules.py::test_detects_privesc_pattern_on_role PASSED
tests/test_rules.py::test_clean_user_triggers_nothing PASSED
tests/test_rules.py::test_score_reflects_findings PASSED
======================== 8 passed in 6.52s ========================
```

`demo_run.py` runs the same synthetic environment through the full
collect -> graph -> detect -> score -> report pipeline and writes a real
`results/report.html`, without touching AWS at all.

## Running against a real AWS account

```bash
pip install -r requirements.txt
aws configure --profile mytarget   # read-only credentials, e.g. AWS-managed ReadOnlyAccess
python main.py scan --profile mytarget --region eu-west-1 --output results/
```

This has only been exercised against the synthetic `moto` environment so
far, not against a live multi-account AWS organization -- the collectors use
standard, well-documented API calls, but a real account's scale (pagination,
cross-account roles, SCPs) would surface edge cases this project hasn't hit
yet.

## Project layout

```
cloudcosmo/
  collectors.py   # read-only boto3 inventory (S3, EC2, IAM)
  graph.py        # networkx resource graph + simple attack-path search
  rules.py        # one function per misconfiguration class
  scoring.py      # severity penalties + S-to-E grade (shared model with zparty)
  report.py       # JSON + single-file HTML report
main.py           # CLI entrypoint
tests/
  test_rules.py   # moto-based synthetic vulnerable account + assertions
demo_run.py       # runs the pipeline against the synthetic account, no AWS needed
```

## Scope and limits

Read-only by design. Five rule classes today, chosen because they're the
most common high-impact AWS misconfigurations (public storage, open network
ingress, over-broad IAM, known privilege-escalation paths, stale admin
credentials) -- not an exhaustive cloud security benchmark like CIS AWS
Foundations. Azure and GCP collectors are not implemented yet; the
graph/rules/scoring layers are provider-agnostic by design, so adding them
means writing new collectors, not restructuring the engine.
