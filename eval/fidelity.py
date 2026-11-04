"""Prose coverage and the eval-only fidelity gate. No model and no AWS."""

from __future__ import annotations

from typing import Any

# Properties a checker in the spec vocabulary can name. A prose property
# outside this set is never covered, even if the structured claim repeats it.
VOCABULARY = frozenset(
    {
        "meta.region",
        "pab.block_public_acls",
        "pab.ignore_public_acls",
        "pab.block_public_policy",
        "pab.restrict_public_buckets",
        "encryption.sse_algorithm",
        "encryption.kms_key_id",
        "versioning.status",
        "policy.allows_public",
        "ingress",
        "trust.principals",
        "attached_policy_arns",
        "default_version.actions",
        "default_version.has_wildcard_action",
        "runtime",
        "function_url.auth_type",
        "reserved_concurrency",
    }
)


def canonical(value: Any) -> Any:
    if isinstance(value, dict):
        return tuple(sorted((key, canonical(item)) for key, item in value.items()))
    if isinstance(value, list):
        items = [canonical(item) for item in value]
        try:
            return tuple(sorted(items))
        except TypeError:
            return tuple(items)
    return value


def assertion_key(resource_id: str, prop: str, op: str, value: Any) -> tuple:
    return (resource_id, prop, op, canonical(value))


def structured_keys(resources: list[dict]) -> list[tuple]:
    keys = []
    for resource in resources:
        for assertion in resource.get("assertions") or []:
            keys.append(
                assertion_key(
                    resource["resource_id"],
                    assertion["property"],
                    assertion["op"],
                    assertion.get("value"),
                )
            )
    return keys


def prose_keys(claim: dict) -> list[tuple]:
    prose = claim.get("prose_assertions")
    if prose == "same":
        return structured_keys(claim["structured"]["resources"])
    keys = []
    for item in prose or []:
        keys.append(
            assertion_key(item["resource_id"], item["property"], item["op"], item.get("value"))
        )
    return keys


def coverage(claim: dict) -> float | None:
    prose = prose_keys(claim)
    if not prose:
        return None
    structured = set(structured_keys(claim["structured"]["resources"]))
    covered = 0
    for key in prose:
        if key[1] not in VOCABULARY:
            continue
        if key in structured:
            covered += 1
    return covered / len(prose)


def gate(raw_verdict: str, claim: dict) -> str:
    """PASS becomes NOT_ASSESSED when any prose assertion is uncovered.

    FAIL stays FAIL. The gate is not part of Shadow Verify.
    """

    if raw_verdict != "PASS":
        return raw_verdict
    ratio = coverage(claim)
    if ratio is None or ratio < 1:
        return "NOT_ASSESSED"
    return "PASS"
