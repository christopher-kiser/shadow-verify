"""Shared checker helpers. Verdict text is produced here so checkers stay consistent."""

from __future__ import annotations

from shadow_verify.evidence import EvidenceItem
from shadow_verify.models import CheckResult, Claim, PropertyResult, Verdict
from shadow_verify.verdict import decide

DENIED_CODES = frozenset(
    {
        "AccessDenied",
        "AccessDeniedException",
        "UnauthorizedOperation",
        "UnauthorizedException",
        "NotAuthorized",
        "Forbidden",
        "NoCredentialsError",
        "PartialCredentialsError",
        "CredentialRetrievalError",
    }
)


def finish(
    claim: Claim,
    properties: list[PropertyResult],
    evidence_ids: list[str],
) -> CheckResult:
    verdict, reasons = decide(properties)
    return CheckResult(
        claim_id=claim.id,
        statement=claim.statement,
        resource_type=claim.resource_type,
        identifier=claim.identifier,
        verdict=verdict,
        reasons=reasons,
        evidence_item_ids=tuple(evidence_ids),
        agent_note=claim.agent_note,
    )


def blocked(claim: Claim, reason: str, evidence_ids: list[str]) -> CheckResult:
    return finish(
        claim,
        [PropertyResult(name="read", verdict=Verdict.NOT_ASSESSED, reason=reason)],
        evidence_ids,
    )


def call_failure(operation: str, item: EvidenceItem) -> str:
    code = item.error_code or "error"
    message = item.error_message.strip()
    if message:
        return f"{operation} failed: {code}: {message}"
    return f"{operation} failed: {code}"


def compare_bool(name: str, actual: bool, expected: bool, *, note: str = "") -> PropertyResult:
    suffix = f" ({note})" if note else ""
    if actual == expected:
        return PropertyResult(
            name=name,
            verdict=Verdict.PASS,
            reason=f"{name} is {str(actual).lower()}{suffix}",
        )
    return PropertyResult(
        name=name,
        verdict=Verdict.FAIL,
        reason=(
            f"{name} is {str(actual).lower()}; expected {str(expected).lower()}{suffix}"
        ),
    )
