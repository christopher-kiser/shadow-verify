"""Seeder defaults, overrides, and the second moto account."""

from __future__ import annotations

import json
from pathlib import Path

import boto3
from moto import mock_aws

from eval.seed import apply, install_fake_env

ROOT = Path(__file__).resolve().parents[1]


def _scenario(steps):
    return {
        "stretch": False,
        "seed": {"region": "us-east-1", "steps": steps, "post_claim": []},
    }


def test_default_emulation_after_create_bucket(tmp_path):
    install_fake_env(str(tmp_path))
    with mock_aws():
        session = boto3.Session(region_name="us-east-1")
        apply(session, _scenario([{"call": "s3.create_bucket", "params": {"Bucket": "sv-eval-logs"}}]))
        s3 = session.client("s3", region_name="us-east-1")
        block = s3.get_public_access_block(Bucket="sv-eval-logs")["PublicAccessBlockConfiguration"]
        assert block == {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
        rules = s3.get_bucket_encryption(Bucket="sv-eval-logs")["ServerSideEncryptionConfiguration"]["Rules"]
        assert rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"] == "AES256"


def test_s3_04_09_10_put_their_overrides():
    for sid, needle in (
        ("S3-04", "BlockPublicPolicy"),
        ("S3-09", "BlockPublicAcls"),
        ("S3-10", "BlockPublicPolicy"),
    ):
        scenario = json.loads((ROOT / "eval" / "scenarios" / f"{sid}.json").read_text(encoding="utf-8"))
        text = json.dumps(scenario["seed"])
        assert needle in text
        assert "false" in text


def test_account_step_seeds_a_second_moto_account(tmp_path):
    install_fake_env(str(tmp_path))
    scenario = json.loads((ROOT / "eval" / "scenarios" / "ACC-01.json").read_text(encoding="utf-8"))
    with mock_aws():
        session = boto3.Session(region_name="us-east-1")
        apply(session, scenario)
        iam = session.client("iam", region_name="us-east-1")
        local = iam.get_role(RoleName="sv-deploy")["Role"]["Arn"]
        assert local.startswith("arn:aws:iam::123456789012:")
        sts = session.client("sts", region_name="us-east-1")
        creds = sts.assume_role(
            RoleArn="arn:aws:iam::111122223333:role/sv-eval-seed",
            RoleSessionName="read",
        )["Credentials"]
        other = boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        ).client("iam")
        doc = other.get_role(RoleName="sv-deploy")["Role"]["AssumeRolePolicyDocument"]
        if isinstance(doc, str):
            doc = json.loads(doc)
        blob = json.dumps(doc)
        assert "lambda.amazonaws.com" in blob


def test_seed_refuses_a_real_looking_key(tmp_path, monkeypatch):
    install_fake_env(str(tmp_path))
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAREALKEY12")
    from eval.seed import SeedError, assert_mocked_env

    try:
        assert_mocked_env()
    except SeedError as exc:
        assert "AWS_ACCESS_KEY_ID" in str(exc)
    else:
        raise AssertionError("expected SeedError")
