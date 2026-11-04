"""Read inline and attached IAM policy documents and look for star admin.

A document that cannot be read is NOT ASSESSED. An unconditional admin
Allow is FAIL even if another document could not be read and even if
another statement is Deny.
"""

from __future__ import annotations

from shadow_verify.aws import BotoAws
from shadow_verify.checkers.base import call_failure
from shadow_verify.checkers.iam_documents import admin_finding, decode_policy_document
from shadow_verify.models import PropertyResult, Verdict


def scan_role_admin(
    aws: BotoAws,
    role_name: str,
    trust_doc: dict | None,
    attached_arns: list[str] | None,
    inline_names: list[str] | None,
    inline_problem: str | None,
) -> tuple[PropertyResult, list[str]]:
    evidence_ids: list[str] = []
    unclear: str | None = None
    if trust_doc is None:
        unclear = "trust policy was not readable, so the admin scan is incomplete"
    else:
        kind, detail = admin_finding(trust_doc)
        if kind == "admin":
            return (
                PropertyResult(name="no_admin_star", verdict=Verdict.FAIL, reason=f"trust policy {detail}"),
                evidence_ids,
            )
        if kind == "not_assessed":
            unclear = f"trust policy {detail}"

    if inline_problem or inline_names is None:
        unclear = unclear or inline_problem or "inline policy list was incomplete"
    else:
        for policy_name in inline_names:
            item = aws.get_role_policy(role_name, policy_name)
            evidence_ids.append(item.id)
            found, unclear = _one_document(
                item.ok,
                None if not item.ok else item.response.get("PolicyDocument"),
                call_failure("GetRolePolicy", item) if not item.ok else "",
                f"inline policy {policy_name}",
                unclear,
            )
            if found is not None:
                return found, evidence_ids

    if attached_arns is None:
        unclear = unclear or "attached policy list was incomplete, so policy documents were not scanned"
    else:
        for arn in attached_arns:
            found, extra_ids, unclear = _attached_document(aws, arn, unclear)
            evidence_ids.extend(extra_ids)
            if found is not None:
                return found, evidence_ids

    if unclear:
        return (
            PropertyResult(name="no_admin_star", verdict=Verdict.NOT_ASSESSED, reason=unclear),
            evidence_ids,
        )
    return (
        PropertyResult(
            name="no_admin_star",
            verdict=Verdict.PASS,
            reason="no Allow statement grants Action * or *:* on all resources",
        ),
        evidence_ids,
    )


def _one_document(
    ok: bool,
    raw_document: object,
    error_reason: str,
    label: str,
    unclear: str | None,
) -> tuple[PropertyResult | None, str | None]:
    if not ok:
        return None, error_reason or unclear
    document = decode_policy_document(raw_document)
    if document is None:
        return None, f"{label} document could not be read"
    kind, detail = admin_finding(document)
    if kind == "admin":
        return (
            PropertyResult(name="no_admin_star", verdict=Verdict.FAIL, reason=f"{label} {detail}"),
            unclear,
        )
    if kind == "not_assessed":
        return None, f"{label}: {detail}"
    return None, unclear


def _attached_document(
    aws: BotoAws,
    arn: str,
    unclear: str | None,
) -> tuple[PropertyResult | None, list[str], str | None]:
    ids: list[str] = []
    meta = aws.get_policy(arn)
    ids.append(meta.id)
    if not meta.ok:
        return None, ids, call_failure("GetPolicy", meta)
    policy = meta.response.get("Policy")
    version_id = policy.get("DefaultVersionId") if isinstance(policy, dict) else None
    if not isinstance(version_id, str) or not version_id:
        return None, ids, f"GetPolicy for {arn} has no DefaultVersionId"
    version = aws.get_policy_version(arn, version_id)
    ids.append(version.id)
    if not version.ok:
        return None, ids, call_failure("GetPolicyVersion", version)
    version_body = version.response.get("PolicyVersion")
    raw_doc = version_body.get("Document") if isinstance(version_body, dict) else None
    found, unclear = _one_document(True, raw_doc, "", f"attached policy {arn}", unclear)
    return found, ids, unclear
