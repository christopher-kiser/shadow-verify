"""S3 bucket region. MOCKED. A wrong or unread region must not PASS."""

import json

import boto3
import pytest
from botocore.stub import Stubber
from moto import mock_aws

from shadow_verify.aws import BotoAws
from shadow_verify.checkers.s3_bucket import S3BucketChecker
from shadow_verify.cli import run
from shadow_verify.evidence import EvidenceLog
from shadow_verify.models import Verdict
from tests.helpers import REGION, aws_stack, claim

CHECKER = S3BucketChecker()
_PAB = {
    "PublicAccessBlockConfiguration": {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }
}
_LOCKED = {
    "block_public_acls": True,
    "ignore_public_acls": True,
    "block_public_policy": True,
    "restrict_public_buckets": True,
}


def _lock(name: str, region: str) -> None:
    s3 = boto3.client("s3", region_name=region)
    params: dict = {"Bucket": name}
    if region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": region}
    s3.create_bucket(**params)
    s3.put_public_access_block(Bucket=name, PublicAccessBlockConfiguration=_PAB["PublicAccessBlockConfiguration"])


def _stub(bucket: str, *, constraint, error: str | None = None):
    s3 = boto3.client("s3", region_name=REGION)
    stubber = Stubber(s3)
    if error:
        stubber.add_client_error(
            "get_bucket_location",
            service_error_code=error,
            service_message="denied",
            expected_params={"Bucket": bucket},
        )
    else:
        stubber.add_response(
            "get_bucket_location",
            {"LocationConstraint": constraint},
            {"Bucket": bucket},
        )
    stubber.add_response("get_public_access_block", _PAB, {"Bucket": bucket})
    stubber.activate()
    aws, evidence = aws_stack()
    aws._s3 = s3
    return aws, evidence, stubber


def test_us_west_2_bucket_against_us_east_1_is_fail():
    """REG-01. GetPublicAccessBlock follows the redirect and used to PASS."""

    with mock_aws():
        _lock("sv-eval-logs", "us-west-2")
        aws, evidence = aws_stack()
        result = CHECKER.check(claim("s3_bucket", "sv-eval-logs", dict(_LOCKED)), aws)
    assert result.verdict == Verdict.FAIL
    assert result.verdict != Verdict.PASS
    assert any(
        "region_mismatch" in reason and "us-west-2" in reason and "us-east-1" in reason
        for reason in result.reasons
    )
    location = next(item for item in evidence.items if item.operation == "GetBucketLocation")
    assert location.id in result.evidence_item_ids
    assert location.response.get("LocationConstraint") == "us-west-2"
    public = next(item for item in evidence.items if item.operation == "GetPublicAccessBlock")
    assert public.ok


def test_matching_region_stays_pass():
    with mock_aws():
        _lock("logs-prod", "us-east-1")
        aws, evidence = aws_stack()
        result = CHECKER.check(claim("s3_bucket", "logs-prod", {"block_public_acls": True}), aws)
    assert result.verdict == Verdict.PASS
    location = next(item for item in evidence.items if item.operation == "GetBucketLocation")
    assert location.response.get("LocationConstraint") is None
    assert any("region is us-east-1" in reason for reason in result.reasons)


def test_claim_region_matches_when_the_run_region_differs():
    with mock_aws():
        _lock("logs-west", "us-west-2")
        aws, _evidence = aws_stack()
        result = CHECKER.check(
            claim("s3_bucket", "logs-west", {"block_public_acls": True}, region="us-west-2"),
            aws,
        )
    assert result.verdict == Verdict.PASS
    assert any("region is us-west-2" in reason for reason in result.reasons)


def test_none_location_constraint_is_us_east_1():
    class Location:
        def get_bucket_location(self, **kwargs):
            return {"LocationConstraint": None}

        def get_public_access_block(self, **kwargs):
            return _PAB

    aws, evidence = aws_stack()
    aws._s3 = Location()
    result = CHECKER.check(claim("s3_bucket", "logs-prod", {"block_public_acls": True}), aws)
    assert result.verdict == Verdict.PASS
    location = next(item for item in evidence.items if item.operation == "GetBucketLocation")
    assert location.response.get("LocationConstraint") is None
    assert any("region is us-east-1" in reason for reason in result.reasons)


def test_empty_location_constraint_is_us_east_1():
    aws, _evidence, stubber = _stub("logs-prod", constraint="")
    result = CHECKER.check(claim("s3_bucket", "logs-prod", {"block_public_acls": True}), aws)
    assert result.verdict == Verdict.PASS
    assert any("region is us-east-1" in reason for reason in result.reasons)
    stubber.assert_no_pending_responses()


def test_legacy_eu_location_is_eu_west_1():
    aws, evidence, stubber = _stub("logs-prod", constraint="EU")
    result = CHECKER.check(
        claim("s3_bucket", "logs-prod", {"block_public_acls": True}, region="eu-west-1"),
        aws,
    )
    assert result.verdict == Verdict.PASS
    assert any("region is eu-west-1" in reason for reason in result.reasons)
    location = next(item for item in evidence.items if item.operation == "GetBucketLocation")
    assert location.response.get("LocationConstraint") == "EU"
    stubber.assert_no_pending_responses()


def test_location_access_denied_is_not_assessed():
    aws, evidence, stubber = _stub("logs-prod", constraint=None, error="AccessDenied")
    result = CHECKER.check(claim("s3_bucket", "logs-prod", {"block_public_acls": True}), aws)
    assert result.verdict == Verdict.NOT_ASSESSED
    assert result.verdict != Verdict.PASS
    assert any(
        "GetBucketLocation" in reason and "AccessDenied" in reason for reason in result.reasons
    )
    location = next(item for item in evidence.items if item.operation == "GetBucketLocation")
    assert location.ok is False
    assert location.id in result.evidence_item_ids
    stubber.assert_no_pending_responses()


def test_omitted_region_defaults_to_the_run_region(tmp_path, capsys):
    claims = tmp_path / "claims.json"
    claims.write_text(
        json.dumps(
            {
                "version": 1,
                "claims": [
                    {
                        "id": "logs",
                        "statement": "bucket in the run region",
                        "resource_type": "s3_bucket",
                        "identifier": "logs-prod",
                        "expected": {"block_public_acls": True},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    evidence = tmp_path / "evidence.json"
    with mock_aws():
        _lock("logs-prod", "us-west-2")
        code = run(
            [
                "run",
                "--claims",
                str(claims),
                "--evidence",
                str(evidence),
                "--region",
                "us-east-1",
                "--json",
                "--mode",
                "MOCKED",
            ]
        )
    report = json.loads(capsys.readouterr().out)
    assert code == 1
    assert report["results"][0]["verdict"] == "FAIL"
    assert any("region_mismatch" in reason for reason in report["results"][0]["reasons"])
    bundle = json.loads(evidence.read_text(encoding="utf-8"))
    assert any(item["operation"] == "GetBucketLocation" for item in bundle["items"])


def test_from_session_stores_the_run_region():
    class Session:
        def client(self, name, **kwargs):
            return object()

    aws = BotoAws.from_session(Session(), "us-west-2", EvidenceLog())
    assert aws.region == "us-west-2"
