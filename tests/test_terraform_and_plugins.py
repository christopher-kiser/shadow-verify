import json
from pathlib import Path

from moto import mock_aws

from shadow_verify.aws import ALLOWED_OPERATIONS, BotoAws
from shadow_verify.checkers import CHECKERS, get_checker, register
from shadow_verify.engine import run_checks
from shadow_verify.errors import ShadowVerifyError
from shadow_verify.evidence import EvidenceLog
from shadow_verify.models import CheckResult, Verdict
from shadow_verify.terraform import plan_notes, read_plan
from tests.helpers import S3_LOCKED, aws_stack, claim


def test_plan_note_does_not_change_a_pass_verdict(tmp_path):
    plan_path = Path(__file__).resolve().parents[1] / "examples" / "terraform-plan.sample.json"
    plan = read_plan(plan_path)
    item = claim(
        "s3_bucket",
        "logs-prod",
        {"block_public_acls": True},
        terraform_address="aws_s3_bucket.logs",
    )
    notes = plan_notes([item], plan)
    assert notes[0]["status"] == "found"
    assert notes[0]["actions"] == ["update"]
    with mock_aws():
        import boto3

        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="logs-prod")
        s3.put_public_access_block(
            Bucket="logs-prod",
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        aws, _evidence = aws_stack()
        results = run_checks([item], aws)
    assert results[0].verdict == Verdict.PASS
    assert "informational" in notes[0]["detail"] or "does not compare" in notes[0]["detail"]


def test_plan_missing_address_is_reported(tmp_path):
    path = tmp_path / "plan.json"
    path.write_text(json.dumps({"resource_changes": []}), encoding="utf-8")
    notes = plan_notes(
        [claim("s3_bucket", "logs", dict(S3_LOCKED), terraform_address="aws_s3_bucket.missing")],
        read_plan(path),
    )
    assert notes[0]["status"] == "not_found"


def test_allowlist_is_read_only():
    for service, operation in ALLOWED_OPERATIONS:
        assert operation.startswith(("Get", "List", "Describe")), (service, operation)
    aws = BotoAws(s3=object(), ec2=object(), iam=object(), evidence=EvidenceLog())
    try:
        aws._invoke("s3", "PutObject", aws._s3, Bucket="logs")
    except ShadowVerifyError as exc:
        assert "refusing" in str(exc)
    else:
        raise AssertionError("write call was not refused")


def test_custom_checker_can_be_registered():
    class AlwaysPass:
        resource_type = "custom_test_resource"

        def check(self, item, aws):
            return CheckResult(
                claim_id=item.id,
                statement=item.statement,
                resource_type=item.resource_type,
                identifier=item.identifier,
                verdict=Verdict.PASS,
                reasons=("custom checker ran",),
                evidence_item_ids=(),
                agent_note=item.agent_note,
            )

    register(AlwaysPass())
    try:
        assert get_checker("custom_test_resource") is not None
        result = run_checks(
            [
                claim(
                    "custom_test_resource",
                    "anything",
                    {"unused": True},
                )
            ],
            BotoAws(s3=object(), ec2=object(), iam=object(), evidence=EvidenceLog()),
        )[0]
        assert result.verdict == Verdict.PASS
    finally:
        CHECKERS.pop("custom_test_resource", None)
