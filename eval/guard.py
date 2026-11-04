"""Block subprocess and sockets during verify, and refuse non-allowlisted calls.

The audit hook is installed once per process. A flag limits it to verify.
Denied operations are refused before the IAM allowlist. ``sts:GetCallerIdentity``
is the one documented exception: it needs no IAM permission and is not in
``docs/iam-policy.json``.
"""

from __future__ import annotations

import sys
from contextlib import contextmanager

import botocore.client
import botocore.session

_ORIGINAL_CALL = botocore.client.BaseClient._make_api_call
_ORIGINAL_CREATE = botocore.session.Session.create_client
_HOOKED = False

_AUDIT = (
    "subprocess.Popen",
    "os.system",
    "os.exec",
    "os.spawn",
    "os.posix_spawn",
    "socket.connect",
    "socket.getaddrinfo",
)


class GuardViolation(RuntimeError):
    def __init__(self, kind: str) -> None:
        super().__init__(kind)
        self.kind = kind


class GuardState:
    def __init__(self) -> None:
        self.active = False
        self.enforce_api = False
        self.session_core = None
        self.faults = None
        self.allow: frozenset[str] = frozenset()
        self.denied: frozenset[str] = frozenset()
        self.owner: str | None = None
        self.ops: list[str] = []
        self.violations: list[str] = []


STATE = GuardState()


def set_bucket_owner(owner: str | None) -> None:
    STATE.owner = owner


def _ensure_hook() -> None:
    global _HOOKED
    if not _HOOKED:
        sys.addaudithook(_audit)
        _HOOKED = True


def _audit(event: str, args) -> None:
    if not STATE.active:
        return
    if event in _AUDIT or any(event.startswith(name) for name in _AUDIT):
        _fail(event)


def _fail(kind: str) -> None:
    STATE.violations.append(kind)
    raise GuardViolation(kind)


def _wrapped_create(self, service_name, *args, **kwargs):
    if STATE.active and STATE.enforce_api and self is not STATE.session_core:
        _fail("foreign_session")
    return _ORIGINAL_CREATE(self, service_name, *args, **kwargs)


def _wrapped_call(self, operation_name, api_params):
    if not (STATE.active and STATE.enforce_api):
        return _ORIGINAL_CALL(self, operation_name, api_params)
    service = self._service_model.service_name
    pair = f"{service}:{operation_name}"
    if pair in STATE.denied or pair not in STATE.allow:
        _fail(pair)
    params = dict(api_params)
    if service == "s3" and STATE.owner and "ExpectedBucketOwner" not in params:
        params["ExpectedBucketOwner"] = STATE.owner
    STATE.ops.append(pair)

    def call(updated):
        return _ORIGINAL_CALL(self, operation_name, updated)

    if STATE.faults is not None:
        return STATE.faults.intercept(service, operation_name, params, call)
    return call(params)


@contextmanager
def protect(session, faults, allow: frozenset[str], denied: frozenset[str]):
    """Allowlist, foreign-session check, and the audit hook."""

    _ensure_hook()
    _arm(session, faults, allow, denied, enforce_api=True)
    botocore.client.BaseClient._make_api_call = _wrapped_call
    botocore.session.Session.create_client = _wrapped_create
    try:
        yield STATE
    finally:
        _disarm()


@contextmanager
def audit_only():
    """Block subprocess and sockets without the API allowlist.

    Existence-read baselines call ``head_bucket``, which is outside the
    Shadow Verify allowlist. They still cannot open a socket or a process.
    """

    _ensure_hook()
    previous = STATE.active
    STATE.active = True
    STATE.enforce_api = False
    try:
        yield STATE
    finally:
        STATE.active = previous


def _arm(session, faults, allow: frozenset[str], denied: frozenset[str], *, enforce_api: bool) -> None:
    STATE.active = True
    STATE.enforce_api = enforce_api
    STATE.session_core = session._session
    STATE.faults = faults
    STATE.owner = None
    STATE.ops = []
    STATE.violations = []
    STATE.allow = allow
    STATE.denied = denied


def _disarm() -> None:
    botocore.client.BaseClient._make_api_call = _ORIGINAL_CALL
    botocore.session.Session.create_client = _ORIGINAL_CREATE
    STATE.active = False
    STATE.enforce_api = False
    STATE.owner = None
    STATE.faults = None
