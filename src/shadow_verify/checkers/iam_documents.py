"""Pure IAM document rules. No AWS calls.

Trust comparison uses principal values and ignores conditions.
An unconditional Allow of ``*`` or ``*:*``, or NotAction on every ARN in
a partition, is admin. The same Allow with a Condition is not a pass.
Privilege-escalation actions on those resources are ``may_grant_admin``.
"""

from __future__ import annotations

import json
import re
import urllib.parse

_ADMIN_ACTIONS = {"*", "*:*"}
# Witnesses for the named IAM-write wildcards. Matching is case-insensitive.
_PRIVESC_ACTIONS = (
    "iam:CreatePolicyVersion",
    "iam:PassRole",
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
    "iam:PutGroupPolicy",
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:AttachGroupPolicy",
    "iam:UpdateAssumeRolePolicy",
)
_PARTITIONS = ("aws", "aws-us-gov", "aws-cn")
_SEARCH_LIMIT = 20000
_NOT_ACTION = "not_action_unsupported: NotAction or NotResource is not evaluated in v0"
_CONDITION = "condition_unsupported: Condition is not evaluated on an admin Allow"


def allow_principals(document: dict) -> tuple[set[str] | None, str | None]:
    statements = document.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return None, "trust policy Statement is missing or not a list"
    found: set[str] = set()
    for statement in statements:
        if not isinstance(statement, dict):
            return None, "trust policy statement is not a mapping"
        if statement.get("Effect", "Allow") != "Allow":
            continue
        if "Principal" not in statement:
            return None, "Allow statement has no Principal"
        values = _principal_values(statement["Principal"])
        if values is None:
            return None, "unsupported Principal shape"
        found.update(values)
    return found, None


def _principal_values(principal: object) -> set[str] | None:
    if principal == "*":
        return {"*"}
    if isinstance(principal, str) and principal:
        return {principal}
    if not isinstance(principal, dict) or not principal:
        return None
    values: set[str] = set()
    for key, val in principal.items():
        if key not in {"AWS", "Service", "Federated", "CanonicalUser"}:
            return None
        if isinstance(val, str) and val:
            values.add(val)
        elif isinstance(val, list) and val and all(isinstance(item, str) and item for item in val):
            values.update(val)
        else:
            return None
    return values


def admin_finding(document: dict) -> tuple[str, str]:
    """Return (admin|clear|not_assessed, detail)."""

    statements = document.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return "not_assessed", "policy Statement is missing or not a list"
    may_grant = False
    unclear: str | None = None
    for statement in statements:
        if not isinstance(statement, dict):
            return "not_assessed", "policy statement is not a mapping"
        if statement.get("Effect", "Allow") != "Allow":
            continue
        kind, detail = _allow_statement(statement)
        if kind == "admin":
            return "admin", detail
        if kind == "may_grant":
            may_grant = True
        elif kind == "not_assessed":
            unclear = unclear or detail
    if unclear:
        return "not_assessed", unclear
    if may_grant:
        return (
            "not_assessed",
            "may_grant_admin: Allow action can grant admin on all resources",
        )
    return "clear", "no Allow statement grants Action * or *:* on Resource *"


def _allow_statement(statement: dict) -> tuple[str, str]:
    conditioned = "Condition" in statement
    if "NotAction" in statement or "NotResource" in statement:
        return _not_elements(statement, conditioned)
    actions = _as_strings(statement.get("Action"))
    resources = _as_strings(statement.get("Resource"))
    if actions is None or resources is None:
        return "not_assessed", "Action or Resource shape was not understood"
    covers = _resources_cover_all(resources)
    if covers is None:
        return "not_assessed", "Resource pattern was not understood"
    if not covers:
        return "clear", ""
    if any(action.casefold() in _ADMIN_ACTIONS for action in actions):
        if conditioned:
            return "not_assessed", _CONDITION
        return "admin", "Allow statement grants Action * or *:* on Resource *"
    if any(_may_grant_admin(action) for action in actions):
        if conditioned:
            return "not_assessed", _CONDITION
        return "may_grant", ""
    return "clear", ""


def _not_elements(statement: dict, conditioned: bool) -> tuple[str, str]:
    if "NotResource" in statement or "NotAction" not in statement:
        return "not_assessed", _NOT_ACTION
    excluded = _as_strings(statement.get("NotAction"))
    resources = _as_strings(statement.get("Resource"))
    if excluded is None or resources is None:
        return "not_assessed", _NOT_ACTION
    covers = _resources_cover_all(resources)
    if covers is None:
        return "not_assessed", "Resource pattern was not understood"
    if not covers:
        return "not_assessed", _NOT_ACTION
    if conditioned:
        return "not_assessed", _CONDITION
    return "admin", "Allow statement grants NotAction on all resources"


def decode_policy_document(document: object) -> dict | None:
    if isinstance(document, dict):
        return document
    if not isinstance(document, str):
        return None
    candidates = [document]
    if "%" in document:
        candidates.insert(0, urllib.parse.unquote(document))
    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def _resources_cover_all(resources: list[str]) -> bool | None:
    unknown = False
    for resource in resources:
        covered = _matches_all_resources(resource)
        if covered is True:
            return True
        if covered is None:
            unknown = True
    if unknown:
        return None
    return False


def _may_grant_admin(action: str) -> bool:
    folded = action.casefold()
    if folded == "iam:*":
        return True
    return any(_glob_match(folded, concrete.casefold()) for concrete in _PRIVESC_ACTIONS)


def _glob_match(pattern: str, value: str) -> bool:
    """IAM action glob: ``*`` is any sequence and ``?`` is one character."""

    escaped = re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".")
    return re.fullmatch(escaped, value) is not None


def _matches_all_resources(pattern: str) -> bool | None:
    """True when the pattern matches every ARN in at least one partition.

    ``*`` matches any character, including ``:`` and ``/``. ``None`` means
    the pattern was too large to decide. That must not become a pass.
    """

    if pattern and set(pattern) == {"*"}:
        return True
    if len(pattern) > 180:
        return None
    for partition in _partitions_for(pattern):
        covered = _covers_partition(pattern, f"arn:{partition}:")
        if covered is None:
            return None
        if covered:
            return True
    return False


def _partitions_for(pattern: str) -> tuple[str, ...]:
    parts = pattern.split(":")
    if len(parts) < 2 or parts[0] != "arn":
        return _PARTITIONS
    segment = parts[1]
    if segment and "*" not in segment and "?" not in segment and segment not in _PARTITIONS:
        return _PARTITIONS + (segment,)
    return _PARTITIONS


def _covers_partition(pattern: str, prefix: str) -> bool | None:
    literals = {char for char in pattern if char not in "*?"}
    alphabet = set(prefix) | literals | {":", "\x01"}
    start = _epsilon(pattern, frozenset({0}))
    seen = {(0, start)}
    queue = [(0, start)]
    steps = 0
    accept = len(pattern)
    resource_state = len(prefix) + 3
    while queue:
        state, positions = queue.pop()
        steps += 1
        if steps > _SEARCH_LIMIT:
            return None
        if state == resource_state and accept not in positions:
            return False
        for char in alphabet:
            nxt = _arn_step(state, char, prefix)
            if nxt is None:
                continue
            moved = _epsilon(pattern, _consume(pattern, positions, char))
            key = (nxt, moved)
            if key not in seen:
                seen.add(key)
                queue.append(key)
    return True


def _arn_step(state: int, char: str, prefix: str) -> int | None:
    if state < len(prefix):
        if char == prefix[state]:
            return state + 1
        return None
    if state == len(prefix):
        return len(prefix) + 1 if char == ":" else len(prefix)
    if state == len(prefix) + 1:
        return len(prefix) + 2 if char == ":" else len(prefix) + 1
    if state == len(prefix) + 2:
        return len(prefix) + 3 if char == ":" else len(prefix) + 2
    return len(prefix) + 3


def _epsilon(pattern: str, positions: frozenset[int]) -> frozenset[int]:
    found = set(positions)
    grew = True
    while grew:
        grew = False
        for index in list(found):
            if index < len(pattern) and pattern[index] == "*" and (index + 1) not in found:
                found.add(index + 1)
                grew = True
    return frozenset(found)


def _consume(pattern: str, positions: frozenset[int], char: str) -> frozenset[int]:
    nxt: set[int] = set()
    for index in positions:
        if index >= len(pattern):
            continue
        token = pattern[index]
        if token == "*":
            nxt.add(index)
        elif token == "?" or token == char:
            nxt.add(index + 1)
    return frozenset(nxt)


def _as_strings(value: object) -> list[str] | None:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return list(value)
    if value is None:
        return []
    return None
