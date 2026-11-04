"""Run Shadow Verify on one claim. Unsupported checks abstain.

v0 reads S3 Block Public Access, bucket-policy publicity, security-group
``not_contains`` forbids, and an IAM role only when trust, attached
policies, and ``no_admin_star`` are all present. Anything else is
NOT_ASSESSED. A property that was not read cannot produce PASS.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import time
from datetime import timezone
from pathlib import Path
from typing import Any, Callable

from shadow_verify.aws import MAX_ATTEMPTS, BotoAws
from shadow_verify.engine import run_checks
from shadow_verify.errors import ClaimsError
from shadow_verify.evidence import EvidenceLog
from shadow_verify.models import Claim

from eval import guard

S3_EQ = {
    "pab.block_public_acls": "block_public_acls",
    "pab.ignore_public_acls": "ignore_public_acls",
    "pab.block_public_policy": "block_public_policy",
    "pab.restrict_public_buckets": "restrict_public_buckets",
    "policy.allows_public": "bucket_policy_public",
}
SUPPORTED_TYPES = {"s3_bucket", "security_group", "iam_role"}
_SV_TYPE = {"security_group": "ec2_security_group"}
_ACCOUNT = re.compile(r"arn:aws:iam::(\d{12}):")


def retry_bound() -> int:
    return MAX_ATTEMPTS


def load_allowlist(policy_path: Path) -> tuple[frozenset[str], frozenset[str]]:
    """API allowlist from the IAM policy, plus ``sts:GetCallerIdentity``."""

    from shadow_verify.aws import DENIED_OPERATIONS, OPERATION_IAM_ACTIONS

    document = json.loads(Path(policy_path).read_text(encoding="utf-8"))
    allowed: set[str] = set()
    denied_iam: set[str] = set()
    for statement in document["Statement"]:
        actions = statement["Action"]
        if isinstance(actions, str):
            actions = [actions]
        bucket = allowed if statement["Effect"] == "Allow" else denied_iam
        bucket.update(actions)
    iam_to_api: dict[str, set[str]] = {}
    for api, iam in OPERATION_IAM_ACTIONS.items():
        iam_to_api.setdefault(iam, set()).add(api)
    ops: set[str] = set()
    for iam in allowed - denied_iam:
        ops.update(iam_to_api.get(iam, set()))
    ops.add("sts:GetCallerIdentity")
    return frozenset(ops), frozenset(DENIED_OPERATIONS)


def verify_evidence(path: Path) -> list[str]:
    from shadow_verify.evidence import bundle_problems

    try:
        bundle = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [str(exc)]
    if not isinstance(bundle, dict):
        return ["evidence file must be a JSON object"]
    return bundle_problems(bundle)


def run_verify(
    claim: dict,
    session,
    clock: Callable,
    sleep: Callable,
    hmac_key: bytes,
    evidence_dir: Path,
) -> dict:
    previous = time.sleep
    time.sleep = lambda seconds: sleep(seconds)
    try:
        return _verify(claim, session, clock, hmac_key, evidence_dir)
    finally:
        time.sleep = previous


def _verify(claim, session, clock, hmac_key: bytes, evidence_dir: Path) -> dict:
    evidence = EvidenceLog()
    per_resource = []
    ops: list[str] = []
    accounts = []
    for index, resource in enumerate(claim["resources"]):
        piece, piece_ops, account = _resource(
            claim, index, resource, session, evidence, hmac_key
        )
        per_resource.append(piece)
        ops.extend(piece_ops)
        accounts.append(account)
    verdict = _combine([item["verdict"] for item in per_resource])
    reasons: list[str] = []
    unchecked: list[str] = []
    for item in per_resource:
        for reason in item["reasons"]:
            if reason not in reasons:
                reasons.append(reason)
        unchecked.extend(item["unchecked"])
    digest = _write_bundle(claim, evidence, per_resource, clock, evidence_dir)
    return {
        "verdict": verdict,
        "reasons": reasons,
        "unchecked": unchecked,
        "checked_account": accounts,
        "evidence_sha256": digest,
        "api_ops": ops,
    }


def _resource(claim, index, resource, session, evidence, hmac_key: bytes):
    identity = str(resource.get("resource_id") or "")
    region = resource.get("region") if isinstance(resource.get("region"), str) else "us-east-1"
    if not region:
        region = "us-east-1"
    assertions = list(resource.get("assertions") or [])
    if not assertions:
        return _na(claim, resource, "vague_claim", []), [], _account_field(identity, "NOT_ASSESSED")
    if resource.get("resource_type") not in SUPPORTED_TYPES:
        return (
            _na(claim, resource, "unsupported_resource", [a.get("property", "") for a in assertions]),
            [],
            _account_field(identity, "NOT_ASSESSED"),
        )
    account_id = resource.get("account_id")
    ops: list[str] = []
    if isinstance(account_id, str) and account_id:
        caller = _caller(session, region)
        ops.append("sts:GetCallerIdentity")
        if caller != account_id:
            return (
                _na(claim, resource, "account_mismatch", []),
                ops,
                _account_field(identity, _hmac(hmac_key, caller)),
            )
    expected, unchecked, sv_type = _translate(resource)
    if expected is None:
        return (
            _na(claim, resource, "unsupported_property", unchecked),
            ops,
            _account_field(identity, "NOT_ASSESSED"),
        )
    owner = account_id if resource["resource_type"] == "s3_bucket" and account_id else None
    guard.set_bucket_owner(owner)
    before = len(evidence.items)
    try:
        aws = BotoAws.from_session(session, region, evidence)
        sv_claim = Claim(
            id=f"{claim['id']}-{index}",
            statement=claim.get("text") or claim["id"],
            resource_type=sv_type,
            identifier=identity,
            expected=expected,
            agent_note=claim.get("text"),
        )
        try:
            result = run_checks([sv_claim], aws)[0]
        except ClaimsError:
            ops.extend(_new_ops(evidence, before))
            return (
                _na(claim, resource, "unsupported_property", unchecked or list(expected)),
                ops,
                _account_field(identity, "NOT_ASSESSED"),
            )
    finally:
        guard.set_bucket_owner(None)
    ops.extend(_new_ops(evidence, before))
    verdict = result.verdict.value
    reasons = list(result.reasons)
    if unchecked and verdict != "FAIL":
        verdict = "NOT_ASSESSED"
        if "unsupported_property" not in reasons:
            reasons.insert(0, "unsupported_property")
    if owner and verdict == "NOT_ASSESSED" and _owner_denied(reasons):
        reasons = ["owner_mismatch_or_denied"]
    observed = _observed_account(evidence.items[before:])
    token = "NOT_ASSESSED"
    if isinstance(account_id, str) and account_id:
        token = _hmac(hmac_key, account_id)
    elif observed:
        token = _hmac(hmac_key, observed)
    return (
        {
            "verdict": verdict,
            "reasons": reasons,
            "unchecked": unchecked,
            "result": result.to_dict(),
            "resource": resource,
        },
        ops,
        _account_field(identity, token),
    )


def _translate(resource: dict) -> tuple[dict | None, list[str], str]:
    rtype = resource["resource_type"]
    sv_type = _SV_TYPE.get(rtype, rtype)
    unchecked: list[str] = []
    if rtype == "s3_bucket":
        expected: dict[str, Any] = {}
        for assertion in resource["assertions"]:
            key = S3_EQ.get(assertion.get("property"))
            if key and assertion.get("op") == "eq" and isinstance(assertion.get("value"), bool):
                expected[key] = assertion["value"]
            else:
                unchecked.append(str(assertion.get("property")))
        return (expected or None), unchecked, sv_type
    if rtype == "security_group":
        rules = []
        for assertion in resource["assertions"]:
            rule = _forbid(assertion)
            if rule is None:
                unchecked.append(str(assertion.get("property")))
            else:
                rules.append(rule)
        if not rules:
            return None, unchecked, sv_type
        return {"ingress_forbidden": rules}, unchecked, sv_type
    expected, missing = _iam(resource["assertions"])
    unchecked.extend(missing)
    if expected is None:
        return None, unchecked or [str(a.get("property")) for a in resource["assertions"]], sv_type
    return expected, unchecked, sv_type


def _iam(assertions: list[dict]) -> tuple[dict | None, list[str]]:
    """Call the role checker only when all three v0 keys are present."""

    expected: dict[str, Any] = {}
    unchecked: list[str] = []
    for assertion in assertions:
        prop = assertion.get("property")
        if prop == "trust.principals" and assertion.get("op") == "equals_set":
            expected["trust_principals"] = list(assertion.get("value") or [])
        elif prop == "attached_policy_arns" and assertion.get("op") == "equals_set":
            expected["attached_policy_arns"] = list(assertion.get("value") or [])
        elif prop == "no_admin_star" and assertion.get("op") == "eq" and assertion.get("value") is True:
            expected["no_admin_star"] = True
        else:
            unchecked.append(str(prop))
    required = {"trust_principals", "attached_policy_arns", "no_admin_star"}
    if required - set(expected):
        return None, unchecked or [str(a.get("property")) for a in assertions]
    return expected, unchecked


def _forbid(assertion: dict) -> dict | None:
    if assertion.get("property") != "ingress" or assertion.get("op") != "not_contains":
        return None
    value = assertion.get("value")
    if not isinstance(value, dict):
        return None
    needed = {"protocol", "from_port", "to_port", "cidr"}
    if not needed <= set(value):
        return None
    return {
        "protocol": value["protocol"],
        "from_port": value["from_port"],
        "to_port": value["to_port"],
        "cidr": value["cidr"],
    }


def _na(claim, resource, reason: str, unchecked: list[str]) -> dict:
    return {
        "verdict": "NOT_ASSESSED",
        "reasons": [reason],
        "unchecked": [item for item in unchecked if item],
        "result": {
            "id": claim["id"],
            "statement": claim.get("text") or claim["id"],
            "resource_type": resource.get("resource_type"),
            "identifier": resource.get("resource_id"),
            "verdict": "NOT_ASSESSED",
            "reasons": [reason],
            "evidence_item_ids": [],
            "agent_note": claim.get("text"),
        },
        "resource": resource,
    }


def _combine(verdicts: list[str]) -> str:
    if any(item == "FAIL" for item in verdicts):
        return "FAIL"
    if any(item != "PASS" for item in verdicts):
        return "NOT_ASSESSED"
    return "PASS" if verdicts else "NOT_ASSESSED"


def _new_ops(evidence: EvidenceLog, before: int) -> list[str]:
    return [f"{item.service}:{item.operation}" for item in evidence.items[before:]]


def _caller(session, region: str) -> str:
    identity = session.client("sts", region_name=region).get_caller_identity()
    return str(identity["Account"])


def _owner_denied(reasons: list[str]) -> bool:
    text = " ".join(reasons)
    return "403" in text or "AccessDenied" in text


def _observed_account(items) -> str | None:
    for item in items:
        found = _walk_account(item.response)
        if found:
            return found
    return None


def _walk_account(value: Any) -> str | None:
    if isinstance(value, dict):
        owner = value.get("OwnerId")
        if isinstance(owner, str) and owner.isdigit() and len(owner) == 12:
            return owner
        arn = value.get("Arn")
        if isinstance(arn, str):
            match = _ACCOUNT.search(arn)
            if match:
                return match.group(1)
        for item in value.values():
            found = _walk_account(item)
            if found:
                return found
    elif isinstance(value, list):
        for item in value:
            found = _walk_account(item)
            if found:
                return found
    return None


def _account_field(resource_id: str, token: str) -> dict:
    return {"resource_id": resource_id, "checked_account": token}


def _hmac(key: bytes, account: str) -> str:
    return hmac.new(key, account.encode("utf-8"), hashlib.sha256).hexdigest()


def _write_bundle(claim, evidence, pieces, clock, evidence_dir: Path) -> str:
    evidence_dir.mkdir(parents=True, exist_ok=True)
    claims_path = evidence_dir / f"{claim['id']}.claims.json"
    body = json.dumps({"id": claim["id"], "resources": claim["resources"]}, sort_keys=True)
    claims_path.write_text(body + "\n", encoding="utf-8", newline="\n")
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    moment = clock()
    if getattr(moment, "tzinfo", None) is None:
        moment = moment.replace(tzinfo=timezone.utc)
    generated = moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    region = "us-east-1"
    for piece in pieces:
        candidate = piece["resource"].get("region")
        if isinstance(candidate, str) and candidate:
            region = candidate
            break
    bundle = evidence.bundle(
        generated_at=generated,
        claims_file=f"{claim['id']}.claims.json",
        claims_sha256=digest,
        region=region,
        results=[piece["result"] for piece in pieces],
        plan_notes=[],
        mode="MOCKED",
        tool_commit=os.environ.get("SV_TOOL_COMMIT") or "shadow-verify==0.1.0",
    )
    path = evidence_dir / f"{claim['id']}.json"
    path.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8", newline="\n")
    return str(bundle["bundle_sha256"])
