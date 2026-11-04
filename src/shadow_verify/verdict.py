"""Combine property results. Contradiction wins; missing evidence never passes."""

from __future__ import annotations

from shadow_verify.models import PropertyResult, Verdict


def decide(properties: list[PropertyResult]) -> tuple[Verdict, tuple[str, ...]]:
    """Return the claim verdict and every property reason.

    A single FAIL makes the claim FAIL, even if another property could not
    be read. NOT ASSESSED is used only when nothing contradicted the claim
    and at least one required observation is missing or not understood.
    An empty property list is NOT ASSESSED: a checker with no observation
    must not pass.
    """

    if not properties:
        return Verdict.NOT_ASSESSED, ("checker produced no property results",)
    if any(item.verdict == Verdict.FAIL for item in properties):
        verdict = Verdict.FAIL
    elif any(item.verdict == Verdict.NOT_ASSESSED for item in properties):
        verdict = Verdict.NOT_ASSESSED
    else:
        verdict = Verdict.PASS
    return verdict, tuple(item.reason for item in properties)
