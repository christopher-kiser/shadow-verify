"""Frozen evidence bundles.

Each AWS call becomes one item. The item sha256 covers the id, service,
operation, parameters, and body. The bundle sha256 covers the bundle with
the bundle_sha256 field removed. Canonical JSON is UTF-8, object keys
sorted, and no insignificant whitespace.

The hash makes a bundle tamper-evident when the digest is stored somewhere
else (for example a pull request comment). v0 does not sign the bundle.
Rehashing a modified bundle produces a new digest; it will not match a
digest that was copied out at run time.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
from typing import Any

import rfc8785

from shadow_verify import __version__

CANONICALIZATION = "rfc8785"
_ACCOUNT_ID = re.compile(r"(?<!\d)(\d{12})(?!\d)")
REDACTED = "***REDACTED***"

# Normalized by lowercasing and dropping non-alphanumeric characters.
_REDACT_KEYS = frozenset(
    {
        "secretstring",
        "secretbinary",
        "password",
        "passworddata",
        "privatekey",
        "privatekeymaterial",
        "secretaccesskey",
        "sessiontoken",
        "accesstoken",
        "authorization",
        "securitytoken",
        "xamzsecuritytoken",
    }
)


def to_jsonable(value: Any) -> Any:
    """Copy a boto3 response into JSON-safe values without dropping fields."""

    if value is None or isinstance(value, (str, int, bool)):
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise TypeError("cannot freeze a non-finite float into evidence")
        return value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Decimal):
        if value == value.to_integral_value():
            return int(value)
        return str(value)
    if isinstance(value, bytes):
        return {"__bytes_base64": base64.b64encode(value).decode("ascii")}
    if isinstance(value, dict):
        return {str(key): to_jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_jsonable(item) for item in value]
    raise TypeError(f"cannot freeze {type(value).__name__} into evidence")


def _normal_key(key: str) -> str:
    return "".join(char for char in key.lower() if char.isalnum())


def redact(value: Any) -> Any:
    """Replace secret-bearing fields before they are stored or hashed."""

    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            name = str(key)
            if _normal_key(name) in _REDACT_KEYS:
                redacted[name] = REDACTED
            else:
                redacted[name] = redact(item)
        return redacted
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


class AccountIdIndex:
    """Replace AWS account ids with stable labels for one bundle.

    The mapping is not a hash. A per-bundle index cannot be reversed to the
    account id, and the same id in one run always gets the same label, so
    two identical runs hash the same. The index itself is not stored.
    """

    def __init__(self) -> None:
        self._labels: dict[str, str] = {}

    def rewrite(self, value: Any) -> Any:
        if isinstance(value, str):
            return _ACCOUNT_ID.sub(self._replace, value)
        if isinstance(value, dict):
            return {key: self.rewrite(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self.rewrite(item) for item in value]
        return value

    def _replace(self, match: re.Match[str]) -> str:
        account_id = match.group(1)
        if account_id not in self._labels:
            self._labels[account_id] = f"account-{len(self._labels) + 1}"
        return self._labels[account_id]


def strip_response_metadata(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: strip_response_metadata(item)
            for key, item in value.items()
            if key != "ResponseMetadata"
        }
    if isinstance(value, list):
        return [strip_response_metadata(item) for item in value]
    return value


def canonical_bytes(value: Any) -> bytes:
    """RFC 8785 JSON. The bytes are what SHA-256 covers."""

    return rfc8785.dumps(value)


def canonical_dumps(value: Any) -> str:
    return canonical_bytes(value).decode("utf-8")


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


@dataclass(frozen=True)
class EvidenceItem:
    id: str
    service: str
    operation: str
    params: dict[str, Any]
    body: dict[str, Any]
    sha256: str
    view: dict[str, Any]

    @property
    def ok(self) -> bool:
        return "response" in self.view

    @property
    def response(self) -> dict[str, Any]:
        """Unredacted response for checkers. The stored body is redacted."""

        response = self.view.get("response")
        if isinstance(response, dict):
            return response
        return {}

    @property
    def error_code(self) -> str | None:
        error = self.body.get("error")
        if isinstance(error, dict):
            code = error.get("code")
            if isinstance(code, str):
                return code
        return None

    @property
    def error_message(self) -> str:
        error = self.body.get("error")
        if isinstance(error, dict) and error.get("message") is not None:
            return str(error["message"])
        return ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "service": self.service,
            "operation": self.operation,
            "params": self.params,
            "body": self.body,
            "sha256": self.sha256,
        }


class EvidenceLog:
    def __init__(self) -> None:
        self.items: list[EvidenceItem] = []
        self._accounts = AccountIdIndex()

    def record(
        self,
        service: str,
        operation: str,
        params: dict[str, Any],
        *,
        response: Any = None,
        error_code: str | None = None,
        error_message: str | None = None,
        error_response: Any = None,
    ) -> EvidenceItem:
        item_id = f"{service}.{operation}#{len(self.items) + 1}"
        view_params = strip_response_metadata(to_jsonable(params))
        if error_code is not None:
            view = {
                "error": {
                    "code": error_code,
                    "message": (error_message or "")[:500],
                    "response": strip_response_metadata(to_jsonable(error_response))
                    if error_response is not None
                    else None,
                }
            }
        else:
            view = {"response": strip_response_metadata(to_jsonable(response))}
        stored_params = self._accounts.rewrite(redact(view_params))
        stored_body = self._accounts.rewrite(redact(view))
        payload = {
            "id": item_id,
            "service": service,
            "operation": operation,
            "params": stored_params,
            "body": stored_body,
        }
        item = EvidenceItem(
            id=item_id,
            service=service,
            operation=operation,
            params=stored_params,
            body=stored_body,
            sha256=sha256_json(payload),
            view=view,
        )
        self.items.append(item)
        return item

    def bundle(
        self,
        *,
        generated_at: str,
        claims_file: str,
        claims_sha256: str,
        region: str,
        results: list[dict[str, Any]],
        plan_notes: list[dict[str, Any]],
        mode: str,
        tool_commit: str,
    ) -> dict[str, Any]:
        document: dict[str, Any] = {
            "shadow_verify": __version__,
            "mode": mode,
            "tool_commit": tool_commit,
            "generated_at": generated_at,
            "claims_file": claims_file,
            "claims_sha256": claims_sha256,
            "region": region,
            "hash_algorithm": "sha256",
            "canonicalization": CANONICALIZATION,
            "items": [item.as_dict() for item in self.items],
            "results": self._accounts.rewrite(results),
            "plan_notes": self._accounts.rewrite(plan_notes),
            "rules": {
                "agent_note": "untrusted; never an input to the verdict",
                "plan_notes": "informational in v0; never an input to the verdict",
            },
        }
        document["bundle_sha256"] = sha256_json(
            {key: value for key, value in document.items() if key != "bundle_sha256"}
        )
        return document


def item_payload(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": item["id"],
        "service": item["service"],
        "operation": item["operation"],
        "params": item["params"],
        "body": item["body"],
    }


def bundle_problems(bundle: dict[str, Any]) -> list[str]:
    """Return internal consistency problems. Empty means the hashes match."""

    problems: list[str] = []
    items = bundle.get("items")
    if not isinstance(items, list):
        return ["evidence items is not a list"]
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            problems.append(f"item {index} is not an object")
            continue
        try:
            expected = sha256_json(item_payload(item))
        except (KeyError, TypeError) as exc:
            problems.append(f"item {index} cannot be hashed: {exc}")
            continue
        if item.get("sha256") != expected:
            problems.append(f"item {item.get('id', index)} hash mismatch")
    without_bundle_hash = {key: value for key, value in bundle.items() if key != "bundle_sha256"}
    if bundle.get("bundle_sha256") != sha256_json(without_bundle_hash):
        problems.append("bundle hash mismatch")
    return problems
