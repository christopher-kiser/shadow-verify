"""Guard violations exit 1. sts:GetCallerIdentity stays allowed."""

from __future__ import annotations

import socket
import subprocess
import urllib.request
from pathlib import Path

import boto3
from moto import mock_aws

from eval.adapter import load_allowlist
from eval.guard import GuardViolation, protect

ROOT = Path(__file__).resolve().parents[1]
_REAL_CONNECT = socket.create_connection
_REAL_SOCKET = socket.socket


def _allow():
    return load_allowlist(ROOT / "docs" / "iam-policy.json")


def _run(session, fn) -> int:
    allow, denied = _allow()
    try:
        with protect(session, None, allow, denied):
            fn()
        return 0
    except GuardViolation:
        return 1


def test_policy_allowlist_includes_caller_identity_only_as_exception():
    allow, denied = _allow()
    assert "sts:GetCallerIdentity" in allow
    assert "s3:GetObject" in denied
    assert "s3:PutBucketPolicy" not in allow
    policy = (ROOT / "docs" / "iam-policy.json").read_text(encoding="utf-8")
    assert "GetCallerIdentity" not in policy


def test_put_bucket_policy_exits_1():
    with mock_aws():
        session = boto3.Session(region_name="us-east-1")
        code = _run(
            session,
            lambda: boto3.client("s3").put_bucket_policy(Bucket="b", Policy="{}"),
        )
    assert code == 1


def test_foreign_session_read_exits_1():
    with mock_aws():
        session = boto3.Session(region_name="us-east-1")
        code = _run(session, lambda: boto3.Session().client("s3").list_buckets())
    assert code == 1


def test_get_object_on_the_injected_session_exits_1():
    with mock_aws():
        session = boto3.Session(region_name="us-east-1")
        code = _run(session, lambda: session.client("s3").get_object(Bucket="b", Key="k"))
    assert code == 1


def test_subprocess_exits_1():
    with mock_aws():
        session = boto3.Session(region_name="us-east-1")
        code = _run(session, lambda: subprocess.run(["aws", "s3", "ls"], check=False))
    assert code == 1


def test_socket_and_urllib_exit_1():
    # The suite replaces socket with a blocker. Restore the real calls so the
    # audit hook is what stops them.
    socket.socket = _REAL_SOCKET
    socket.create_connection = _REAL_CONNECT
    with mock_aws():
        session = boto3.Session(region_name="us-east-1")
        socket_code = _run(session, lambda: _REAL_CONNECT(("example.invalid", 443), timeout=1))
        url_code = _run(session, lambda: urllib.request.urlopen("http://example.invalid"))
    assert socket_code == 1
    assert url_code == 1


def test_caller_identity_is_allowed():
    with mock_aws():
        session = boto3.Session(region_name="us-east-1")
        assert _run(session, lambda: session.client("sts").get_caller_identity()) == 0
