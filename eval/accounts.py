"""HMAC an account id. The raw id is not stored on a result row."""

from __future__ import annotations

import hashlib
import hmac
import re
from typing import Any

_ACCOUNT = re.compile(r"arn:aws:iam::(\d{12}):")


def hmac_account(key: bytes, account: str) -> str:
    return hmac.new(key, account.encode("utf-8"), hashlib.sha256).hexdigest()


def account_field(resource_id: str, token: str) -> dict:
    return {"resource_id": resource_id, "checked_account": token}


def observed_account(items) -> str | None:
    for item in items:
        found = _walk(item.response)
        if found:
            return found
    return None


def _walk(value: Any) -> str | None:
    if isinstance(value, dict):
        owner = value.get("OwnerId")
        if isinstance(owner, str) and owner.isdigit() and len(owner) == 12:
            return owner
        arn = value.get("Arn")
        if isinstance(arn, str):
            match = _ACCOUNT.search(arn)
            if match:
                return match.group(1)
        for item in value.values():
            found = _walk(item)
            if found:
                return found
    elif isinstance(value, list):
        for item in value:
            found = _walk(item)
            if found:
                return found
    return None
