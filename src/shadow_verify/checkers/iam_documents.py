"""Pure IAM document rules. No AWS calls.

Trust comparison uses principal values and ignores conditions.
Admin means an Allow of ``*`` or ``*:*`` on a resource pattern that matches
every ``arn:aws:`` ARN. A privilege-escalation action on those resources
is ``may_grant_admin`` (not a pass) unless the action is that admin star.
"""

from __future__ import annotations

import json
import re
import urllib.parse

_ADMIN_ACTIONS = {"*", "*:*"}
# Concrete actions covered by iam:*, iam:Put*Policy, iam:Attach*Policy,
# iam:CreatePolicyVersion, and iam:PassRole. A wildcard that matches one
# of these is the same class. iam:* is included by matching every iam action.
_PRIVESC_ACTIONS = (
    "iam:CreatePolicyVersion",
    "iam:PassRole",
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
    "iam:PutGroupPolicy",
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:AttachGroupPolicy",
)
_AWS_ARN_PREFIX = "arn:aws:"
_SERVICE = len(_AWS_ARN_PREFIX)
_REGION = _SERVICE + 1
_ACCOUNT = _REGION + 1
_RESOURCE = _ACCOUNT + 1
_SEARCH_LIMIT = 20000


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
    for statement in statements:
        if not isinstance(statement, dict):
            return "not_assessed", "policy statement is not a mapping"
        if statement.get("Effect", "Allow") != "Allow":
            continue
        if "NotAction" in statement or "NotResource" in statement:
            return "not_assessed", "NotAction or NotResource is not evaluated in v0"
        actions = _as_strings(statement.get("Action"))
        resources = _as_strings(statement.get("Resource"))
        if actions is None or resources is None:
            return "not_assessed", "Action or Resource shape was not understood"
        covers_all = _resources_cover_all(resources)
        if covers_all is None:
            return "not_assessed", "Resource pattern was not understood"
        if not covers_all:
            continue
        if any(action in _ADMIN_ACTIONS for action in actions):
            return "admin", "Allow statement grants Action * or *:* on Resource *"
        if any(_may_grant_admin(action) for action in actions):
            may_grant = True
    if may_grant:
        return (
            "not_assessed",
            "may_grant_admin: Allow action can grant admin on all resources",
        )
    return "clear", "no Allow statement grants Action * or *:* on Resource *"


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
    if action == "iam:*":
        return True
    return any(_glob_match(action, concrete) for concrete in _PRIVESC_ACTIONS)


def _glob_match(pattern: str, value: str) -> bool:
    """IAM action glob: ``*`` is any sequence and ``?`` is one character."""

    escaped = re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".")
    return re.fullmatch(escaped, value) is not None


def _matches_all_resources(pattern: str) -> bool | None:
    """True when every ``arn:aws:`` ARN matches this resource pattern.

    ``*`` matches any character, including ``:`` and ``/``. ``None`` means
    the pattern was too large to decide. That must not become a pass.
    """

    if pattern and set(pattern) == {"*"}:
        return True
    if len(pattern) > 180:
        return None
    return _covers_every_aws_arn(pattern)


def _covers_every_aws_arn(pattern: str) -> bool | None:
    literals = {char for char in pattern if char not in "*?"}
    other = "\x01"
    alphabet = set(_AWS_ARN_PREFIX) | literals | {":", other}
    start = _epsilon(pattern, frozenset({0}))
    seen = {(0, start)}
    queue = [(0, start)]
    steps = 0
    accept = len(pattern)
    while queue:
        state, positions = queue.pop()
        steps += 1
        if steps > _SEARCH_LIMIT:
            return None
        if state == _RESOURCE and accept not in positions:
            return False
        for char in alphabet:
            nxt = _arn_step(state, char)
            if nxt is None:
                continue
            moved = _epsilon(pattern, _consume(pattern, positions, char))
            key = (nxt, moved)
            if key not in seen:
                seen.add(key)
                queue.append(key)
    return True


def _arn_step(state: int, char: str) -> int | None:
    if state < len(_AWS_ARN_PREFIX):
        if char == _AWS_ARN_PREFIX[state]:
            return state + 1
        return None
    if state == _SERVICE:
        return _REGION if char == ":" else _SERVICE
    if state == _REGION:
        return _ACCOUNT if char == ":" else _REGION
    if state == _ACCOUNT:
        return _RESOURCE if char == ":" else _ACCOUNT
    return _RESOURCE


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
