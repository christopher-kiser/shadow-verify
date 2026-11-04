"""IAM role trust principals, attached policy ARNs, and star admin.

A claim must set all three:

* ``trust_principals``: the set of Allow principal values (ARN, service
  host, or ``*``). Principal type keys are not part of the comparison.
  Conditions are not compared in v0; the GetRole response in the evidence
  bundle still contains them.
* ``attached_policy_arns``: the exact set of attached managed policy ARNs.
  Inline policy names are not part of this set.
* ``no_admin_star: true``: no Allow statement in the trust policy, an
  inline policy, or an attached policy's default version has Action
  ``*`` or ``*:*`` and Resource ``*``. ``NotAction`` or ``NotResource``
  makes this property NOT ASSESSED. v0 does not try to interpret them.

An unreadable policy document is NOT ASSESSED, never a pass. An attached
ARN mismatch is FAIL even when the admin scan is also incomplete, because
a contradiction was observed. Inline policies that are not admin do not
by themselves fail the ARN comparison.
"""

from __future__ import annotations

from typing import Any

from shadow_verify.aws import ApiResult, BotoAws
from shadow_verify.checkers.base import blocked, call_failure, finish
from shadow_verify.checkers.iam_admin import scan_role_admin
from shadow_verify.checkers.iam_documents import (
    admin_finding,
    allow_principals,
    decode_policy_document,
)
from shadow_verify.errors import ClaimsError
from shadow_verify.models import CheckResult, Claim, PropertyResult, Verdict

_CONDITION_NOTE = "conditions are not compared in v0"

__all__ = [
    "IamRoleChecker",
    "admin_finding",
    "allow_principals",
    "decode_policy_document",
    "role_name_from_identifier",
]


class IamRoleChecker:
    resource_type = "iam_role"

    def check(self, claim: Claim, aws: BotoAws) -> CheckResult:
        expected = _validate(claim)
        role_name = role_name_from_identifier(claim.identifier)
        evidence_ids: list[str] = []
        role_item = aws.get_role(role_name)
        evidence_ids.append(role_item.id)
        if not role_item.ok:
            return blocked(claim, call_failure("GetRole", role_item), evidence_ids)

        properties: list[PropertyResult] = []
        trust_doc, trust_error = _trust_document(role_item.response)
        if trust_error:
            properties.append(
                PropertyResult(name="trust_principals", verdict=Verdict.NOT_ASSESSED, reason=trust_error)
            )
            actual_principals: set[str] | None = None
        else:
            actual_principals, principal_error = allow_principals(trust_doc)
            if principal_error:
                properties.append(
                    PropertyResult(
                        name="trust_principals",
                        verdict=Verdict.NOT_ASSESSED,
                        reason=principal_error,
                    )
                )
            else:
                properties.append(_compare_set("trust_principals", actual_principals or set(), expected["trust_principals"], _CONDITION_NOTE))

        attached = aws.list_attached_role_policies(role_name)
        evidence_ids.extend(attached.item_ids)
        inline = aws.list_role_policies(role_name)
        evidence_ids.extend(inline.item_ids)
        attached_arns, attached_problem = _collect_strings(attached, "AttachedPolicies", "PolicyArn", "ListAttachedRolePolicies")
        inline_names, inline_problem = _collect_strings(inline, "PolicyNames", None, "ListRolePolicies")

        if attached_problem or attached_arns is None:
            properties.append(
                PropertyResult(
                    name="attached_policy_arns",
                    verdict=Verdict.NOT_ASSESSED,
                    reason=attached_problem or "attached policy list was incomplete",
                )
            )
            scanned_arns = None
        else:
            scanned_arns = list(dict.fromkeys(attached_arns))
            properties.append(
                _compare_set(
                    "attached_policy_arns",
                    set(scanned_arns),
                    expected["attached_policy_arns"],
                    "",
                )
            )

        admin_result, admin_ids = scan_role_admin(
            aws,
            role_name,
            trust_doc if trust_error is None else None,
            scanned_arns,
            None if inline_names is None else list(dict.fromkeys(inline_names)),
            inline_problem,
        )
        evidence_ids.extend(admin_ids)
        properties.append(admin_result)
        return finish(claim, properties, evidence_ids)


def _validate(claim: Claim) -> dict[str, Any]:
    expected = claim.expected
    required = {"trust_principals", "attached_policy_arns", "no_admin_star"}
    unknown = sorted(set(expected) - required)
    if unknown:
        raise ClaimsError(f"iam_role claim {claim.id!r} has unknown expected keys: {unknown}")
    missing = sorted(required - set(expected))
    if missing:
        raise ClaimsError(
            f"iam_role claim {claim.id!r} must set {sorted(required)}; missing {missing}"
        )
    if expected["no_admin_star"] is not True:
        raise ClaimsError(
            f"iam_role claim {claim.id!r} no_admin_star must be true in v0"
        )
    principals = _string_list(expected["trust_principals"], claim.id, "trust_principals")
    arns = _string_list(expected["attached_policy_arns"], claim.id, "attached_policy_arns")
    for arn in arns:
        if not arn.startswith("arn:") or ":policy/" not in arn:
            raise ClaimsError(
                f"iam_role claim {claim.id!r} attached_policy_arns entry is not a policy ARN: {arn}"
            )
    role_name_from_identifier(claim.identifier)
    return {
        "trust_principals": principals,
        "attached_policy_arns": arns,
        "no_admin_star": True,
    }


def _string_list(value: object, claim_id: str, name: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
        raise ClaimsError(f"iam_role claim {claim_id!r} expected.{name} must be a list of strings")
    if len(value) != len(set(value)):
        raise ClaimsError(f"iam_role claim {claim_id!r} expected.{name} contains duplicates")
    return list(value)


def role_name_from_identifier(identifier: str) -> str:
    if not isinstance(identifier, str) or not identifier.strip():
        raise ClaimsError("iam_role identifier must be a role name or role ARN")
    if identifier.startswith("arn:"):
        marker = ":role/"
        if marker not in identifier:
            raise ClaimsError("IAM role ARN must contain :role/")
        name = identifier.split(marker, 1)[1]
        if "/" in name:
            name = name.rsplit("/", 1)[1]
        if not name:
            raise ClaimsError("IAM role ARN has an empty role name")
        return name
    if "/" in identifier:
        raise ClaimsError("iam_role identifier is a role name, not a path; pass a role ARN for paths")
    return identifier


def _trust_document(response: dict) -> tuple[dict | None, str | None]:
    role = response.get("Role")
    if not isinstance(role, dict):
        return None, "GetRole response has no Role object"
    decoded = decode_policy_document(role.get("AssumeRolePolicyDocument"))
    if decoded is None:
        return None, "AssumeRolePolicyDocument could not be read as a JSON object"
    return decoded, None


def _compare_set(name: str, actual: set[str], expected: list[str], note: str) -> PropertyResult:
    expected_set = set(expected)
    missing = sorted(expected_set - actual)
    extra = sorted(actual - expected_set)
    suffix = f"; {note}" if note else ""
    if not missing and not extra:
        return PropertyResult(name=name, verdict=Verdict.PASS, reason=f"{name} match{suffix}")
    parts: list[str] = []
    if missing:
        parts.append("missing " + ", ".join(missing))
    if extra:
        parts.append("unexpected " + ", ".join(extra))
    return PropertyResult(
        name=name,
        verdict=Verdict.FAIL,
        reason=f"{name} do not match: {'; '.join(parts)}{suffix}",
    )


def _collect_strings(
    result: ApiResult,
    key: str,
    field: str | None,
    operation: str,
) -> tuple[list[str] | None, str | None]:
    if not result.complete or result.error is not None:
        item = result.error
        if item is not None:
            return None, call_failure(operation, item)
        return None, f"{operation} was truncated and could not be read completely"
    values: list[str] = []
    for page in result.pages:
        body = page.response.get(key, [])
        if field is None:
            if not isinstance(body, list) or not all(isinstance(item, str) for item in body):
                return None, f"{operation} response {key} was not a list of strings"
            values.extend(body)
            continue
        if not isinstance(body, list):
            return None, f"{operation} response {key} was not a list"
        for entry in body:
            if not isinstance(entry, dict) or not isinstance(entry.get(field), str):
                return None, f"{operation} response was missing {field}"
            values.append(entry[field])
    return values, None

