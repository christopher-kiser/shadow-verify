"""Pure IAM document rules. No AWS calls.

Trust comparison uses principal values and ignores conditions.
Admin means an Allow statement with Action ``*`` or ``*:*`` and Resource ``*``.
"""

from __future__ import annotations

import json
import urllib.parse

_ADMIN_ACTIONS = {"*", "*:*"}


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
        if any(action in _ADMIN_ACTIONS for action in actions) and any(resource == "*" for resource in resources):
            return "admin", "Allow statement grants Action * or *:* on Resource *"
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


def _as_strings(value: object) -> list[str] | None:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return list(value)
    if value is None:
        return []
    return None
