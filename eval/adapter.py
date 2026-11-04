"""Run Shadow Verify on one claim. Unsupported checks abstain.

v0 reads S3 Block Public Access, bucket-policy publicity, security-group
``not_contains`` forbids, and an IAM role only when trust, attached
policies, and ``no_admin_star`` are all present. Anything else is
NOT_ASSESSED. A property that was not read cannot produce PASS.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from datetime import timezone
from pathlib import Path
from typing import Any, Callable

from shadow_verify.aws import MAX_ATTEMPTS, BotoAws
from shadow_verify.engine import run_checks
from shadow_verify.errors import ClaimsError
from shadow_verify.evidence import EvidenceLog
from shadow_verify.models import Claim

from eval import guard
from eval.accounts import account_field, hmac_account, observed_account
from eval.translate import translate

SUPPORTED_TYPES = {"s3_bucket", "security_group", "iam_role"}


@dataclass
class _Ctx:
    claim: dict
    index: int
    resource: dict
    session: Any
    evidence: EvidenceLog
    hmac_key: bytes
    identity: str
    region: str
    account_id: str | None
    ops: list[str] = field(default_factory=list)
    unchecked: list[str] = field(default_factory=list)
    expected: dict | None = None
    sv_type: str = ""
    owner: str | None = None
    before: int = 0


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


def run_verify(claim, session, clock: Callable, sleep: Callable, hmac_key: bytes, evidence_dir: Path) -> dict:
    previous = time.sleep
    time.sleep = lambda seconds: sleep(seconds)
    try:
        return _verify(claim, session, clock, hmac_key, evidence_dir)
    finally:
        time.sleep = previous


def _verify(claim, session, clock, hmac_key: bytes, evidence_dir: Path) -> dict:
    evidence = EvidenceLog()
    pieces, ops, accounts = [], [], []
    for index, resource in enumerate(claim["resources"]):
        piece, piece_ops, account = _resource(claim, index, resource, session, evidence, hmac_key)
        pieces.append(piece)
        ops.extend(piece_ops)
        accounts.append(account)
    reasons: list[str] = []
    unchecked: list[str] = []
    for piece in pieces:
        for reason in piece["reasons"]:
            if reason not in reasons:
                reasons.append(reason)
        unchecked.extend(piece["unchecked"])
    return {
        "verdict": _combine([piece["verdict"] for piece in pieces]),
        "reasons": reasons,
        "unchecked": unchecked,
        "checked_account": accounts,
        "evidence_sha256": _write_bundle(claim, evidence, pieces, clock, evidence_dir),
        "api_ops": ops,
    }


def _resource(claim, index, resource, session, evidence, hmac_key: bytes):
    ctx = _Ctx(
        claim=claim,
        index=index,
        resource=resource,
        session=session,
        evidence=evidence,
        hmac_key=hmac_key,
        identity=str(resource.get("resource_id") or ""),
        region=_region(resource),
        account_id=resource.get("account_id") if isinstance(resource.get("account_id"), str) else None,
    )
    stopped = _account_check(ctx)
    if stopped is not None:
        return stopped
    ctx.expected, ctx.unchecked, ctx.sv_type = translate(resource)
    result = _run_checker(ctx)
    if isinstance(result, tuple):
        return result
    return _post_gate(ctx, result)


def _account_check(ctx: _Ctx):
    assertions = list(ctx.resource.get("assertions") or [])
    if not assertions:
        return _done(ctx, "vague_claim", [])
    if ctx.resource.get("resource_type") not in SUPPORTED_TYPES:
        names = [item.get("property", "") for item in assertions]
        return _done(ctx, "unsupported_resource", names, ops=[])
    if ctx.account_id:
        caller = _caller(ctx.session, ctx.region)
        ctx.ops.append("sts:GetCallerIdentity")
        if caller != ctx.account_id:
            token = hmac_account(ctx.hmac_key, caller)
            return _done(ctx, "account_mismatch", [], token=token)
    return None


def _run_checker(ctx: _Ctx):
    if ctx.expected is None:
        return _done(ctx, "unsupported_property", ctx.unchecked)
    ctx.owner = ctx.account_id if ctx.resource["resource_type"] == "s3_bucket" else None
    guard.set_bucket_owner(ctx.owner)
    ctx.before = len(ctx.evidence.items)
    try:
        aws = BotoAws.from_session(ctx.session, ctx.region, ctx.evidence)
        sv_claim = Claim(
            id=f"{ctx.claim['id']}-{ctx.index}",
            statement=ctx.claim.get("text") or ctx.claim["id"],
            resource_type=ctx.sv_type,
            identifier=ctx.identity,
            expected=ctx.expected,
            agent_note=ctx.claim.get("text"),
        )
        try:
            return run_checks([sv_claim], aws)[0]
        except ClaimsError:
            ctx.ops.extend(_new_ops(ctx.evidence, ctx.before))
            names = ctx.unchecked or list(ctx.expected)
            return _done(ctx, "unsupported_property", names)
    finally:
        guard.set_bucket_owner(None)


def _post_gate(ctx: _Ctx, result) -> tuple:
    ctx.ops.extend(_new_ops(ctx.evidence, ctx.before))
    verdict = result.verdict.value
    reasons = list(result.reasons)
    if ctx.unchecked and verdict != "FAIL":
        verdict = "NOT_ASSESSED"
        if "unsupported_property" not in reasons:
            reasons.insert(0, "unsupported_property")
    if ctx.owner and verdict == "NOT_ASSESSED" and _owner_denied(reasons):
        reasons = ["owner_mismatch_or_denied"]
    token = "NOT_ASSESSED"
    if ctx.account_id:
        token = hmac_account(ctx.hmac_key, ctx.account_id)
    else:
        seen = observed_account(ctx.evidence.items[ctx.before :])
        if seen:
            token = hmac_account(ctx.hmac_key, seen)
    piece = {
        "verdict": verdict,
        "reasons": reasons,
        "unchecked": ctx.unchecked,
        "result": result.to_dict(),
        "resource": ctx.resource,
    }
    return piece, ctx.ops, account_field(ctx.identity, token)


def _done(ctx: _Ctx, reason: str, unchecked: list, ops: list | None = None, token: str = "NOT_ASSESSED"):
    used = ctx.ops if ops is None else ops
    return _na(ctx.claim, ctx.resource, reason, unchecked), used, account_field(ctx.identity, token)


def _region(resource: dict) -> str:
    region = resource.get("region")
    if isinstance(region, str) and region:
        return region
    return "us-east-1"


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
    return str(session.client("sts", region_name=region).get_caller_identity()["Account"])


def _owner_denied(reasons: list[str]) -> bool:
    text = " ".join(reasons)
    return "403" in text or "AccessDenied" in text


def _write_bundle(claim, evidence, pieces, clock, evidence_dir: Path) -> str:
    evidence_dir.mkdir(parents=True, exist_ok=True)
    body = json.dumps({"id": claim["id"], "resources": claim["resources"]}, sort_keys=True)
    (evidence_dir / f"{claim['id']}.claims.json").write_text(body + "\n", encoding="utf-8", newline="\n")
    moment = clock()
    if getattr(moment, "tzinfo", None) is None:
        moment = moment.replace(tzinfo=timezone.utc)
    region = "us-east-1"
    for piece in pieces:
        candidate = piece["resource"].get("region")
        if isinstance(candidate, str) and candidate:
            region = candidate
            break
    bundle = evidence.bundle(
        generated_at=moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        claims_file=f"{claim['id']}.claims.json",
        claims_sha256=hashlib.sha256(body.encode("utf-8")).hexdigest(),
        region=region,
        results=[piece["result"] for piece in pieces],
        plan_notes=[],
        mode="MOCKED",
        tool_commit=os.environ.get("SV_TOOL_COMMIT") or "shadow-verify==0.1.0",
    )
    path = evidence_dir / f"{claim['id']}.json"
    path.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8", newline="\n")
    return str(bundle["bundle_sha256"])
