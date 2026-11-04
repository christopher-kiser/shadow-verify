"""Faults injected on the verify path. Seed calls do not pass through here.

``attempts`` counts ``_make_api_call`` entries. v0's botocore retry loop
lives inside that method, so a replaced call is one observation (ADR 027).
"""

from __future__ import annotations

from botocore.exceptions import ClientError, ReadTimeoutError

_NOT_FOUND = {
    "GetRole": "NoSuchEntity",
    "GetPolicy": "NoSuchEntity",
    "DescribeSecurityGroups": "InvalidGroup.NotFound",
}


class FaultPlan:
    def __init__(self, faults: list[dict] | None, page_size: int | None) -> None:
        self._faults = list(faults or [])
        self.page_size = page_size
        self.seen: dict[tuple[str, str, str], int] = {}

    def intercept(self, service: str, operation: str, params: dict, call):
        params = self._page(service, operation, params)
        fault = self._match(service, operation)
        if fault is None or not self._consume(fault, service, operation):
            return call(params)
        kind = fault["kind"]
        if kind == "stale":
            return fault["response"]
        if kind == "truncate":
            response = call(params)
            return _truncate(response)
        raise _error(kind, operation)

    def _match(self, service: str, operation: str) -> dict | None:
        needle = f"{service}.{operation}"
        for fault in self._faults:
            if fault.get("operation") == needle:
                return fault
        return None

    def _consume(self, fault: dict, service: str, operation: str) -> bool:
        key = (service, operation, fault["kind"])
        count = self.seen.get(key, 0) + 1
        self.seen[key] = count
        attempts = fault["attempts"]
        if attempts == "all":
            return True
        return count <= int(attempts)

    def _page(self, service: str, operation: str, params: dict) -> dict:
        if not self.page_size:
            return params
        if not (operation.startswith("List") or operation.startswith("Describe")):
            return params
        updated = dict(params)
        if service == "iam" and "MaxItems" not in updated:
            updated["MaxItems"] = self.page_size
        elif service != "iam" and "MaxResults" not in updated:
            updated["MaxResults"] = self.page_size
        return updated


def truncation_effect(op: str, item_seen: bool) -> str:
    """Spec rule for a truncated list. v0 does not apply this per assertion.

    A ``contains`` whose item was already seen is observed. ``not_contains``,
    ``equals_set``, and an unseen ``contains`` are NOT_ASSESSED. The adapter
    does not use this to change a Shadow Verify verdict.
    """

    if op == "contains" and item_seen:
        return "observed"
    if op in {"contains", "not_contains", "equals_set"}:
        return "NOT_ASSESSED"
    raise ValueError(op)


def _truncate(response: dict) -> dict:
    copied = dict(response)
    copied["IsTruncated"] = True
    copied.pop("Marker", None)
    copied.pop("NextMarker", None)
    return copied


def _error(kind: str, operation: str) -> Exception:
    if kind == "timeout":
        return ReadTimeoutError(endpoint_url="https://eval.invalid")
    code = {
        "access_denied": "AccessDenied",
        "throttling": "Throttling",
        "not_found": _NOT_FOUND.get(operation, "NoSuchBucket"),
    }[kind]
    return ClientError(
        {"Error": {"Code": code, "Message": kind}, "ResponseMetadata": {"HTTPStatusCode": 400}},
        operation,
    )
