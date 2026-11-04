"""ExpectedBucketOwner is sent, and a stubbed 403 is NOT ASSESSED."""

from __future__ import annotations

from pathlib import Path

import boto3
from botocore.stub import Stubber
from moto import mock_aws

from eval.adapter import load_allowlist, run_verify
from eval.guard import protect
from eval.run import HMAC_KEY, _sleep, clock
from eval.seed import install_fake_env
from shadow_verify.aws import BotoAws

ROOT = Path(__file__).resolve().parents[1]


def _pab():
    return [
        {"property": f"pab.{name}", "op": "eq", "value": True}
        for name in (
            "block_public_acls",
            "ignore_public_acls",
            "block_public_policy",
            "restrict_public_buckets",
        )
    ]


def test_s3_owner_header_and_stubbed_403(tmp_path, monkeypatch):
    install_fake_env(str(tmp_path))
    flags = {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }
    with mock_aws():
        session = boto3.Session(region_name="us-east-1")
        s3 = session.client("s3", region_name="us-east-1")
        stub = Stubber(s3)
        expected = {"Bucket": "logs", "ExpectedBucketOwner": "123456789012"}
        stub.add_response("get_public_access_block", {"PublicAccessBlockConfiguration": flags}, expected)
        stub.activate()

        def fake_from_session(bound, region, evidence):
            return BotoAws(
                s3=s3,
                ec2=bound.client("ec2", region_name=region),
                iam=bound.client("iam", region_name=region),
                evidence=evidence,
            )

        monkeypatch.setattr("eval.adapter.BotoAws.from_session", fake_from_session)
        allow, denied = load_allowlist(ROOT / "docs" / "iam-policy.json")
        claim = {
            "id": "owner",
            "text": "pab",
            "resources": [
                {
                    "resource_type": "s3_bucket",
                    "resource_id": "logs",
                    "region": "us-east-1",
                    "account_id": "123456789012",
                    "assertions": _pab(),
                }
            ],
        }
        with protect(session, None, allow, denied):
            passed = run_verify(claim, session, clock, _sleep, HMAC_KEY, tmp_path / "p")
        stub.assert_no_pending_responses()
        assert passed["verdict"] == "PASS"
        stub.add_client_error(
            "get_public_access_block",
            service_error_code="403",
            service_message="Forbidden",
            http_status_code=403,
            expected_params=expected,
        )
        with protect(session, None, allow, denied):
            denied_out = run_verify(claim, session, clock, _sleep, HMAC_KEY, tmp_path / "d")
        assert denied_out["verdict"] == "NOT_ASSESSED"
        assert "owner_mismatch_or_denied" in denied_out["reasons"]
