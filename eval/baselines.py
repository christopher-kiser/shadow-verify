"""Baselines that share a seeded session. They do not import Shadow Verify."""

from __future__ import annotations

from botocore.exceptions import ClientError


def self_report(_resources) -> dict:
    return _done("PASS", ["self_report"], [])


def always_not_assessed(_resources) -> dict:
    return _done("NOT_ASSESSED", ["always_not_assessed"], [])


def naive_exists(session, resources: list[dict]) -> dict:
    verdicts = []
    reasons = []
    ops = []
    for resource in resources:
        verdict, reason, op = _one(session, resource)
        verdicts.append(verdict)
        reasons.append(reason)
        if op:
            ops.append(op)
    if any(item == "FAIL" for item in verdicts):
        verdict = "FAIL"
    elif any(item != "PASS" for item in verdicts):
        verdict = "NOT_ASSESSED"
    else:
        verdict = "PASS" if verdicts else "NOT_ASSESSED"
    return _done(verdict, reasons, ops)


def _one(session, resource: dict) -> tuple[str, str, str]:
    rtype = resource.get("resource_type")
    region = resource.get("region") or "us-east-1"
    identity = str(resource.get("resource_id") or "")
    if rtype == "s3_bucket":
        return _s3(session, region, identity)
    if rtype == "security_group":
        return _sg(session, region, identity)
    if rtype == "iam_role":
        return _role(session, region, _role_name(identity))
    if rtype == "iam_policy":
        return _policy(session, region, identity)
    return "NOT_ASSESSED", "unsupported_resource", ""


def _s3(session, region: str, bucket: str) -> tuple[str, str, str]:
    client = session.client("s3", region_name=region)
    try:
        client.head_bucket(Bucket=bucket)
    except ClientError as exc:
        return _client_error(exc, "s3:HeadBucket")
    return "PASS", "exists", "s3:HeadBucket"


def _sg(session, region: str, group_id: str) -> tuple[str, str, str]:
    client = session.client("ec2", region_name=region)
    try:
        body = client.describe_security_groups(GroupIds=[group_id])
    except ClientError as exc:
        return _client_error(exc, "ec2:DescribeSecurityGroups")
    groups = body.get("SecurityGroups") or []
    if len(groups) == 1:
        return "PASS", "exists", "ec2:DescribeSecurityGroups"
    return "FAIL", "not_found", "ec2:DescribeSecurityGroups"


def _role(session, region: str, name: str) -> tuple[str, str, str]:
    client = session.client("iam", region_name=region)
    try:
        client.get_role(RoleName=name)
    except ClientError as exc:
        return _client_error(exc, "iam:GetRole")
    return "PASS", "exists", "iam:GetRole"


def _policy(session, region: str, arn: str) -> tuple[str, str, str]:
    if not arn.startswith("arn:"):
        return "NOT_ASSESSED", "unsupported_resource", ""
    client = session.client("iam", region_name=region)
    try:
        client.get_policy(PolicyArn=arn)
    except ClientError as exc:
        return _client_error(exc, "iam:GetPolicy")
    return "PASS", "exists", "iam:GetPolicy"


def _client_error(exc: ClientError, op: str) -> tuple[str, str, str]:
    error = exc.response.get("Error", {}) if isinstance(exc.response, dict) else {}
    code = str(error.get("Code") or "")
    status = 0
    meta = exc.response.get("ResponseMetadata", {}) if isinstance(exc.response, dict) else {}
    if isinstance(meta, dict):
        status = int(meta.get("HTTPStatusCode") or 0)
    if code in {"404", "NoSuchBucket", "NotFound", "NoSuchEntity", "InvalidGroup.NotFound"} or status == 404:
        return "FAIL", "not_found", op
    if code in {"403", "AccessDenied", "AccessDeniedException", "UnauthorizedOperation"} or status == 403:
        return "NOT_ASSESSED", "missing_permission", op
    return "NOT_ASSESSED", "unknown_error", op


def _role_name(identifier: str) -> str:
    marker = ":role/"
    if identifier.startswith("arn:") and marker in identifier:
        name = identifier.split(marker, 1)[1]
        return name.rsplit("/", 1)[-1]
    return identifier


def _done(verdict: str, reasons: list[str], ops: list[str]) -> dict:
    return {"verdict": verdict, "reasons": reasons, "api_ops": [op for op in ops if op]}
