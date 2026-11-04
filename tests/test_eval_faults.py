"""Fault kinds, attempt bounds, and the per-assertion truncation rule."""

from __future__ import annotations

import pytest
from botocore.exceptions import ClientError, ReadTimeoutError

from eval.faults import FaultPlan, truncation_effect


def _plan(kind, attempts, **extra):
    fault = {"operation": "s3.GetPublicAccessBlock", "kind": kind, "attempts": attempts}
    fault.update(extra)
    return FaultPlan([fault], page_size=None)


def test_integer_attempts_stop_and_all_does_not():
    limited = _plan("access_denied", 1)
    seen = []

    def call(params):
        seen.append(params)
        return {"ok": True}

    with pytest.raises(ClientError):
        limited.intercept("s3", "GetPublicAccessBlock", {}, call)
    assert limited.intercept("s3", "GetPublicAccessBlock", {"Bucket": "b"}, call) == {"ok": True}
    assert seen == [{"Bucket": "b"}]
    always = _plan("throttling", "all")
    with pytest.raises(ClientError):
        always.intercept("s3", "GetPublicAccessBlock", {}, call)
    with pytest.raises(ClientError):
        always.intercept("s3", "GetPublicAccessBlock", {}, call)


def test_each_kind_raises_or_returns():
    with pytest.raises(ClientError) as denied:
        _plan("access_denied", "all").intercept("s3", "GetPublicAccessBlock", {}, lambda p: None)
    assert denied.value.response["Error"]["Code"] == "AccessDenied"
    with pytest.raises(ClientError) as throttled:
        _plan("throttling", 1).intercept("s3", "GetPublicAccessBlock", {}, lambda p: None)
    assert throttled.value.response["Error"]["Code"] == "Throttling"
    with pytest.raises(ReadTimeoutError):
        FaultPlan(
            [{"operation": "ec2.DescribeSecurityGroups", "kind": "timeout", "attempts": 1}],
            None,
        ).intercept("ec2", "DescribeSecurityGroups", {}, lambda p: None)
    with pytest.raises(ClientError) as missing:
        FaultPlan(
            [{"operation": "iam.GetRole", "kind": "not_found", "attempts": "all"}],
            None,
        ).intercept("iam", "GetRole", {}, lambda p: None)
    assert missing.value.response["Error"]["Code"] == "NoSuchEntity"
    stale = FaultPlan(
        [
            {
                "operation": "s3.GetBucketVersioning",
                "kind": "stale",
                "attempts": 1,
                "response": {"Status": "Off"},
            }
        ],
        None,
    )
    assert stale.intercept("s3", "GetBucketVersioning", {}, lambda p: {"Status": "Enabled"}) == {
        "Status": "Off"
    }


def test_truncate_strips_the_marker():
    plan = FaultPlan(
        [{"operation": "iam.ListAttachedRolePolicies", "kind": "truncate", "attempts": "all", "after_page": 1}],
        page_size=1,
    )

    def call(params):
        assert params["MaxItems"] == 1
        return {"IsTruncated": True, "Marker": "next", "AttachedPolicies": []}

    body = plan.intercept("iam", "ListAttachedRolePolicies", {}, call)
    assert body["IsTruncated"] is True
    assert "Marker" not in body


def test_truncation_per_assertion():
    assert truncation_effect("contains", True) == "observed"
    assert truncation_effect("contains", False) == "NOT_ASSESSED"
    assert truncation_effect("equals_set", True) == "NOT_ASSESSED"
    assert truncation_effect("not_contains", False) == "NOT_ASSESSED"
