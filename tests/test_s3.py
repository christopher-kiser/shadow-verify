import boto3
import pytest
from botocore.stub import Stubber
from moto import mock_aws

from shadow_verify.checkers.s3_bucket import S3BucketChecker
from shadow_verify.evidence import EvidenceLog
from shadow_verify.models import Verdict
from tests.helpers import REGION, S3_LOCKED, aws_stack, claim

CHECKER = S3BucketChecker()


def _bucket(name: str, *, block_public_policy: bool = True) -> None:
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket=name)
    s3.put_public_access_block(
        Bucket=name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": block_public_policy,
            "RestrictPublicBuckets": True,
        },
    )


def test_pass_when_all_flags_are_true_and_policy_is_not_public():
    with mock_aws():
        _bucket("logs-prod")
        aws, evidence = aws_stack()
        result = CHECKER.check(claim("s3_bucket", "logs-prod", dict(S3_LOCKED)), aws)
    assert result.verdict == Verdict.PASS, result.reasons
    assert any(item.operation == "GetPublicAccessBlock" for item in evidence.items)
    assert any(item.operation == "GetBucketPolicyStatus" for item in evidence.items)


def test_fail_when_one_public_access_flag_is_false():
    with mock_aws():
        _bucket("agent-claimed-locked", block_public_policy=False)
        aws, _evidence = aws_stack()
        result = CHECKER.check(
            claim(
                "s3_bucket",
                "agent-claimed-locked",
                dict(S3_LOCKED),
                statement="S3 bucket locked down",
                agent_note="Done. Public access is fully blocked.",
            ),
            aws,
        )
    assert result.verdict == Verdict.FAIL
    assert any("block_public_policy is false; expected true" in reason for reason in result.reasons)
    assert result.agent_note.startswith("Done.")


def test_fail_when_bucket_policy_status_is_public():
    s3 = boto3.client("s3", region_name=REGION)
    stubber = Stubber(s3)
    stubber.add_response(
        "get_public_access_block",
        {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        },
        {"Bucket": "logs"},
    )
    stubber.add_response(
        "get_bucket_policy_status",
        {"PolicyStatus": {"IsPublic": True}},
        {"Bucket": "logs"},
    )
    stubber.activate()
    aws, _evidence = aws_stack()
    aws._s3 = s3
    result = CHECKER.check(claim("s3_bucket", "logs", dict(S3_LOCKED)), aws)
    assert result.verdict == Verdict.FAIL
    assert any("bucket_policy_public is true; expected false" in reason for reason in result.reasons)
    stubber.assert_no_pending_responses()


def test_missing_public_access_block_is_observed_as_false():
    with mock_aws():
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket="open-by-default")
        aws, _evidence = aws_stack()
        result = CHECKER.check(
            claim("s3_bucket", "open-by-default", {"block_public_acls": True}),
            aws,
        )
    assert result.verdict == Verdict.FAIL
    assert any("no public access block configuration" in reason for reason in result.reasons)


def test_not_assessed_when_access_is_denied():
    s3 = boto3.client("s3", region_name=REGION)
    stubber = Stubber(s3)
    stubber.add_client_error(
        "get_public_access_block",
        service_error_code="AccessDenied",
        service_message="denied",
        expected_params={"Bucket": "logs"},
    )
    stubber.add_client_error(
        "get_bucket_policy_status",
        service_error_code="AccessDenied",
        service_message="denied",
        expected_params={"Bucket": "logs"},
    )
    stubber.activate()
    aws, evidence = aws_stack()
    aws._s3 = s3
    result = CHECKER.check(claim("s3_bucket", "logs", dict(S3_LOCKED)), aws)
    assert result.verdict == Verdict.NOT_ASSESSED
    assert any("AccessDenied" in reason for reason in result.reasons)
    assert all(item.ok is False for item in evidence.items)
    stubber.assert_no_pending_responses()


def test_fail_wins_when_a_flag_contradicts_and_policy_status_is_denied():
    s3 = boto3.client("s3", region_name=REGION)
    stubber = Stubber(s3)
    stubber.add_response(
        "get_public_access_block",
        {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": True,
            }
        },
        {"Bucket": "logs"},
    )
    stubber.add_client_error(
        "get_bucket_policy_status",
        service_error_code="AccessDenied",
        service_message="denied",
        expected_params={"Bucket": "logs"},
    )
    stubber.activate()
    aws, _evidence = aws_stack()
    aws._s3 = s3
    result = CHECKER.check(claim("s3_bucket", "logs", dict(S3_LOCKED)), aws)
    assert result.verdict == Verdict.FAIL
    assert any("AccessDenied" in reason for reason in result.reasons)
    stubber.assert_no_pending_responses()


def test_not_assessed_when_bucket_does_not_exist():
    with mock_aws():
        aws, _evidence = aws_stack()
        result = CHECKER.check(claim("s3_bucket", "missing-bucket", dict(S3_LOCKED)), aws)
    assert result.verdict == Verdict.NOT_ASSESSED
    assert any("NoSuchBucket" in reason for reason in result.reasons)


def test_throttling_is_not_assessed():
    s3 = boto3.client("s3", region_name=REGION)
    stubber = Stubber(s3)
    stubber.add_client_error(
        "get_public_access_block",
        service_error_code="Throttling",
        service_message="slow down",
        expected_params={"Bucket": "logs"},
    )
    stubber.activate()
    aws, _evidence = aws_stack()
    aws._s3 = s3
    result = CHECKER.check(claim("s3_bucket", "logs", {"block_public_acls": True}), aws)
    assert result.verdict == Verdict.NOT_ASSESSED
    assert any("Throttling" in reason for reason in result.reasons)
    stubber.assert_no_pending_responses()


def test_timeout_is_not_assessed():
    s3 = boto3.client("s3", region_name=REGION)
    stubber = Stubber(s3)
    stubber.add_client_error(
        "get_public_access_block",
        service_error_code="RequestTimeout",
        service_message="timed out",
        expected_params={"Bucket": "logs"},
    )
    stubber.activate()
    aws, _evidence = aws_stack()
    aws._s3 = s3
    result = CHECKER.check(claim("s3_bucket", "logs", {"block_public_acls": True}), aws)
    assert result.verdict == Verdict.NOT_ASSESSED
    assert result.verdict != Verdict.PASS
    assert any("RequestTimeout" in reason for reason in result.reasons)
    stubber.assert_no_pending_responses()


def test_missing_credentials_are_not_assessed():
    from botocore.exceptions import NoCredentialsError

    class NoCreds:
        def get_public_access_block(self, **kwargs):
            raise NoCredentialsError()

    aws, _evidence = aws_stack()
    aws._s3 = NoCreds()
    result = CHECKER.check(claim("s3_bucket", "logs", {"block_public_acls": True}), aws)
    assert result.verdict == Verdict.NOT_ASSESSED
    assert any("NoCredentialsError" in reason for reason in result.reasons)


def test_unknown_expected_key_is_rejected():
    from shadow_verify.errors import ClaimsError

    with pytest.raises(ClaimsError, match="unknown expected"):
        CHECKER.check(claim("s3_bucket", "logs", {"public": True}), aws_stack()[0])
