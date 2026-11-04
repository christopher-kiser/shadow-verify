"""Baselines, including the one that always abstains."""

from __future__ import annotations

import boto3
from moto import mock_aws

from eval.baselines import always_not_assessed, naive_exists, self_report


def test_constant_baselines_make_no_calls():
    resources = [{"resource_type": "s3_bucket", "resource_id": "b", "region": "us-east-1"}]
    report = self_report(resources)
    abstain = always_not_assessed(resources)
    assert report["verdict"] == "PASS" and report["api_ops"] == []
    assert abstain["verdict"] == "NOT_ASSESSED" and abstain["api_ops"] == []


def test_naive_exists_reads_once():
    with mock_aws():
        session = boto3.Session(region_name="us-east-1")
        session.client("s3").create_bucket(Bucket="present")
        found = naive_exists(
            session,
            [{"resource_type": "s3_bucket", "resource_id": "present", "region": "us-east-1"}],
        )
        missing = naive_exists(
            session,
            [{"resource_type": "s3_bucket", "resource_id": "absent", "region": "us-east-1"}],
        )
        unknown = naive_exists(
            session,
            [{"resource_type": "rds_instance", "resource_id": "db", "region": "us-east-1"}],
        )
    assert found["verdict"] == "PASS" and found["api_ops"] == ["s3:HeadBucket"]
    assert missing["verdict"] == "FAIL"
    assert unknown["verdict"] == "NOT_ASSESSED" and unknown["api_ops"] == []
