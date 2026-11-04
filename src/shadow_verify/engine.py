"""Run registered checkers. This module does not import a model client."""

from __future__ import annotations

from shadow_verify.aws import BotoAws
from shadow_verify.checkers import get_checker
from shadow_verify.models import CheckResult, Claim, Verdict


def run_checks(claims: list[Claim], aws: BotoAws) -> list[CheckResult]:
    results: list[CheckResult] = []
    for claim in claims:
        checker = get_checker(claim.resource_type)
        if checker is None:
            results.append(
                CheckResult(
                    claim_id=claim.id,
                    statement=claim.statement,
                    resource_type=claim.resource_type,
                    identifier=claim.identifier,
                    verdict=Verdict.NOT_ASSESSED,
                    reasons=(
                        f"unsupported resource_type {claim.resource_type}; no checker is registered",
                    ),
                    evidence_item_ids=(),
                    agent_note=claim.agent_note,
                )
            )
            continue
        results.append(checker.check(claim, aws))
    return results
