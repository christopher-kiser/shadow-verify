"""Map an eval assertion onto a v0 expected block. Unknown keys stay unchecked."""

from __future__ import annotations

from typing import Any

S3_EQ = {
    "pab.block_public_acls": "block_public_acls",
    "pab.ignore_public_acls": "ignore_public_acls",
    "pab.block_public_policy": "block_public_policy",
    "pab.restrict_public_buckets": "restrict_public_buckets",
    "policy.allows_public": "bucket_policy_public",
}
_SV_TYPE = {"security_group": "ec2_security_group"}


def translate(resource: dict) -> tuple[dict | None, list[str], str]:
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
        names = unchecked or [str(item.get("property")) for item in resource["assertions"]]
        return None, names, sv_type
    return expected, unchecked, sv_type


def _iam(assertions: list[dict]) -> tuple[dict | None, list[str]]:
    """The role checker runs only when trust, attached policies, and no_admin_star are set."""

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
        return None, unchecked or [str(item.get("property")) for item in assertions]
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
