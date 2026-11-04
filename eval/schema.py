"""Fail-closed scenario checks. Stdlib only. Does not call AWS."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from eval.placeholders import names_in

# Must match shadow_verify.aws.MAX_ATTEMPTS. A test locks the two together.
ATTEMPT_LIMIT = 3

CORE_ID = re.compile(r"^(S3|SG|IAM|REG|ACC|EC|ERR|PG|CF|X|L)-\d{2}$")
HELD_OUT_ID = re.compile(r"^HB-\d{2}$")
RESOURCE_TYPE = re.compile(r"^[a-z0-9_]+$")

CONDITIONS = {
    "none",
    "wrong_region",
    "wrong_account",
    "stale_read",
    "access_denied",
    "throttling",
    "timeout",
    "not_found",
    "pagination",
    "truncated_pagination",
    "underspecified_claim",
    "cidr_semantics",
    "unresolvable_source",
}
FAILURE_TYPES = {
    "truthful_success",
    "silent_partial_apply",
    "hallucinated_success",
    "out_of_scope_mutation",
    "drift_after_apply",
    "stale_after_retry",
    "unverifiable",
}
NA_CAUSES = {
    "unsupported_resource",
    "unsupported_property",
    "missing_permission",
    "vague_claim",
    "account_mismatch",
    "throttled",
    "timeout",
    "truncated_pagination",
    "underspecified_claim",
    "unresolvable_source",
    "unknown_error",
}
VERDICTS = {"PASS", "FAIL", "NOT_ASSESSED"}
OPS = {"eq", "contains", "not_contains", "equals_set"}
FAULT_KINDS = {
    "access_denied",
    "throttling",
    "timeout",
    "not_found",
    "stale",
    "truncate",
}
CORE_CALLS = {
    "s3.create_bucket",
    "s3.put_public_access_block",
    "s3.put_bucket_encryption",
    "s3.put_bucket_versioning",
    "s3.put_bucket_policy",
    "s3.delete_bucket_policy",
    "kms.create_key",
    "ec2.create_vpc",
    "ec2.create_security_group",
    "ec2.authorize_security_group_ingress",
    "ec2.revoke_security_group_ingress",
    "iam.create_role",
    "iam.update_assume_role_policy",
    "iam.create_policy",
    "iam.create_policy_version",
    "iam.attach_role_policy",
    "iam.detach_role_policy",
    "ec2.create_managed_prefix_list",
    "dynamodb.create_table",
    "sts.assume_role",
}
STRETCH_CALLS = CORE_CALLS | {
    "lambda.create_function",
    "lambda.create_function_url_config",
    "lambda.update_function_url_config",
    "lambda.put_function_concurrency",
}

def validate_file(path: Path) -> list[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"{path.name}: {exc}"]
    return validate_scenario(data, filename=path.name)


def validate_scenario(data: Any, *, filename: str) -> list[str]:
    problems: list[str] = []
    if not isinstance(data, dict):
        return [f"{filename}: scenario is not an object"]
    sid = data.get("id")
    pattern = HELD_OUT_ID if filename.startswith("HB-") else CORE_ID
    if not isinstance(sid, str) or pattern.fullmatch(sid) is None:
        problems.append(f"{filename}: bad id")
    elif Path(filename).stem != sid:
        problems.append(f"{filename}: id does not match filename")
    resource_type = data.get("resource_type")
    if not isinstance(resource_type, str) or RESOURCE_TYPE.fullmatch(resource_type) is None:
        problems.append(f"{filename}: resource_type")
    _claim(data.get("agent_claim"), filename, problems)
    _seed(data.get("seed"), filename, bool(data.get("stretch")), problems)
    _labels(data, filename, problems)
    if isinstance(data.get("seed"), dict) and isinstance(data.get("agent_claim"), dict):
        problems.extend(_placeholders(data, filename))
        problems.extend(lint_public_policy(data, filename))
    return problems


def lint_public_policy(data: dict, filename: str = "") -> list[str]:
    """Principal * is illegal unless an earlier put sets BlockPublicPolicy false."""

    seed = data.get("seed")
    if not isinstance(seed, dict):
        return []
    steps = list(seed.get("steps") or []) + list(seed.get("post_claim") or [])
    opened: set[str] = set()
    problems: list[str] = []
    prefix = f"{filename}: " if filename else ""
    for step in steps:
        if not isinstance(step, dict):
            continue
        call = step.get("call")
        params = step.get("params") if isinstance(step.get("params"), dict) else {}
        bucket = params.get("Bucket")
        if call == "s3.put_public_access_block" and isinstance(bucket, str):
            block = params.get("PublicAccessBlockConfiguration")
            if isinstance(block, dict) and block.get("BlockPublicPolicy") is False:
                opened.add(bucket)
        if call == "s3.put_bucket_policy" and _principal_star(params.get("Policy")):
            if not isinstance(bucket, str) or bucket not in opened:
                problems.append(f"{prefix}public policy without BlockPublicPolicy false")
    return problems


def _claim(claim: Any, filename: str, problems: list[str]) -> None:
    if not isinstance(claim, dict):
        problems.append(f"{filename}: agent_claim")
        return
    text = claim.get("text")
    if not isinstance(text, str) or not text.strip():
        problems.append(f"{filename}: agent_claim.text")
    structured = claim.get("structured")
    resources = structured.get("resources") if isinstance(structured, dict) else None
    if not isinstance(resources, list) or not resources:
        problems.append(f"{filename}: structured.resources")
        return
    for index, resource in enumerate(resources):
        _resource(resource, filename, index, problems)
    prose = claim.get("prose_assertions")
    if prose == "same":
        return
    if not isinstance(prose, list):
        problems.append(f"{filename}: prose_assertions")
        return
    for index, item in enumerate(prose):
        if not isinstance(item, dict):
            problems.append(f"{filename}: prose_assertions[{index}]")
            continue
        if item.get("op") not in OPS:
            problems.append(f"{filename}: prose_assertions[{index}].op")


def _resource(resource: Any, filename: str, index: int, problems: list[str]) -> None:
    if not isinstance(resource, dict):
        problems.append(f"{filename}: resources[{index}]")
        return
    if not isinstance(resource.get("resource_type"), str):
        problems.append(f"{filename}: resources[{index}].resource_type")
    elif RESOURCE_TYPE.fullmatch(resource["resource_type"]) is None:
        problems.append(f"{filename}: resources[{index}].resource_type")
    if not isinstance(resource.get("resource_id"), str) or not resource["resource_id"]:
        problems.append(f"{filename}: resources[{index}].resource_id")
    if resource.get("region") is not None and not isinstance(resource.get("region"), str):
        problems.append(f"{filename}: resources[{index}].region")
    account = resource.get("account_id")
    if account is not None and not isinstance(account, str):
        problems.append(f"{filename}: resources[{index}].account_id")
    assertions = resource.get("assertions")
    if not isinstance(assertions, list):
        problems.append(f"{filename}: resources[{index}].assertions")
        return
    for nth, assertion in enumerate(assertions):
        if not isinstance(assertion, dict) or assertion.get("op") not in OPS:
            problems.append(f"{filename}: assertions[{nth}].op")
        if not isinstance(assertion.get("property"), str) or not assertion.get("property"):
            problems.append(f"{filename}: assertions[{nth}].property")


def _seed(seed: Any, filename: str, stretch: bool, problems: list[str]) -> None:
    if not isinstance(seed, dict):
        problems.append(f"{filename}: seed")
        return
    if not isinstance(seed.get("region"), str) or not seed["region"]:
        problems.append(f"{filename}: seed.region")
    allowed = STRETCH_CALLS if stretch else CORE_CALLS
    for name in ("steps", "post_claim", "fault"):
        if not isinstance(seed.get(name), list):
            problems.append(f"{filename}: seed.{name}")
    page = seed.get("page_size")
    if page is not None and (isinstance(page, bool) or not isinstance(page, int) or page < 1):
        problems.append(f"{filename}: seed.page_size")
    for step in list(seed.get("steps") or []) + list(seed.get("post_claim") or []):
        if not isinstance(step, dict) or step.get("call") not in allowed:
            problems.append(f"{filename}: seed call {step.get('call') if isinstance(step, dict) else step}")
            continue
        if not isinstance(step.get("params"), dict):
            problems.append(f"{filename}: params for {step.get('call')}")
        account = step.get("account")
        if account is not None and not isinstance(account, str):
            problems.append(f"{filename}: step account")
    for fault in seed.get("fault") or []:
        _fault(fault, filename, problems)


def _fault(fault: Any, filename: str, problems: list[str]) -> None:
    if not isinstance(fault, dict):
        problems.append(f"{filename}: fault")
        return
    if fault.get("kind") not in FAULT_KINDS:
        problems.append(f"{filename}: fault.kind")
    attempts = fault.get("attempts")
    if attempts != "all" and (
        isinstance(attempts, bool) or not isinstance(attempts, int) or attempts < 1
    ):
        problems.append(f"{filename}: fault.attempts")
    elif isinstance(attempts, int) and attempts >= ATTEMPT_LIMIT:
        problems.append(f"{filename}: fault.attempts must be below {ATTEMPT_LIMIT}")
    if fault.get("kind") == "stale" and "response" not in fault:
        problems.append(f"{filename}: stale fault needs response")
    if fault.get("kind") == "truncate" and "after_page" not in fault:
        problems.append(f"{filename}: truncate fault needs after_page")
    if not isinstance(fault.get("operation"), str) or "." not in fault.get("operation", ""):
        problems.append(f"{filename}: fault.operation")


def _labels(data: dict, filename: str, problems: list[str]) -> None:
    if data.get("condition") not in CONDITIONS:
        problems.append(f"{filename}: condition")
    if data.get("failure_type") not in FAILURE_TYPES:
        problems.append(f"{filename}: failure_type")
    cause = data.get("na_cause")
    if data.get("failure_type") == "unverifiable":
        if cause not in NA_CAUSES:
            problems.append(f"{filename}: na_cause")
    elif cause is not None:
        problems.append(f"{filename}: na_cause must be null")
    if data.get("expected_verdict") not in VERDICTS:
        problems.append(f"{filename}: expected_verdict")
    if data.get("expected_raw_verdict") not in VERDICTS:
        problems.append(f"{filename}: expected_raw_verdict")
    truth = data.get("claim_true", "missing")
    if truth is None:
        if data.get("na_cause") != "vague_claim":
            problems.append(f"{filename}: null claim_true only with vague_claim")
    elif not isinstance(truth, bool):
        problems.append(f"{filename}: claim_true")
    if not isinstance(data.get("stretch"), bool):
        problems.append(f"{filename}: stretch")
    if not isinstance(data.get("rationale"), str) or not data["rationale"].strip():
        problems.append(f"{filename}: rationale")


def _placeholders(data: dict, filename: str) -> list[str]:
    defined: set[str] = set()
    problems: list[str] = []
    seed = data["seed"]
    for step in list(seed.get("steps") or []) + list(seed.get("post_claim") or []):
        if not isinstance(step, dict):
            continue
        missing = names_in(step.get("params")) - defined
        for name in sorted(missing):
            problems.append(f"{filename}: unknown placeholder ${{{name}}}")
        save = step.get("save") or {}
        if isinstance(save, dict):
            defined.update(str(key) for key in save)
    claim = data["agent_claim"]
    missing = names_in(claim) - defined
    for name in sorted(missing):
        problems.append(f"{filename}: unknown placeholder ${{{name}}}")
    return problems


def _principal_star(policy: Any) -> bool:
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except json.JSONDecodeError:
            return "*" in policy
    return _star(policy)


def _star(value: Any) -> bool:
    if value == "*":
        return True
    if isinstance(value, dict):
        if "Principal" in value and _star(value["Principal"]):
            return True
        return any(_star(item) for item in value.values())
    if isinstance(value, list):
        return any(_star(item) for item in value)
    return False
