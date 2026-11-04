"""Seed one scenario into moto. Writes are allowlisted. MOCKED only.

After every ``s3.create_bucket`` this applies the AWS defaults moto 5.2.5
omits: SSE-S3 AES256 (since 2023-01-05) and all four Block Public Access
flags (since April 2023). A scenario that needs either off puts it next.
"""

from __future__ import annotations

import json
import os

import boto3

from eval.placeholders import dig, substitute

MODE = "MOCKED"
AWS_DEFAULT_EMULATION = True

SEED_ALLOWLIST = frozenset(
    {
        "s3.create_bucket",
        "s3.put_public_access_block",
        "s3.put_bucket_encryption",
        "s3.put_bucket_versioning",
        "s3.put_bucket_policy",
        "s3.delete_bucket_policy",
        "kms.create_key",
        "ec2.create_vpc",
        "ec2.create_security_group",
        "ec2.authorize_security_group_ingress",
        "ec2.revoke_security_group_ingress",
        "iam.create_role",
        "iam.update_assume_role_policy",
        "iam.create_policy",
        "iam.create_policy_version",
        "iam.attach_role_policy",
        "iam.detach_role_policy",
        "ec2.create_managed_prefix_list",
        "dynamodb.create_table",
        "sts.assume_role",
    }
)
STRETCH_ALLOWLIST = SEED_ALLOWLIST | {
    "lambda.create_function",
    "lambda.create_function_url_config",
    "lambda.update_function_url_config",
    "lambda.put_function_concurrency",
}

_POLICY_FIELDS = ("Policy", "PolicyDocument", "AssumeRolePolicyDocument")
_PAB_ON = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


class SeedError(Exception):
    pass


# `testing` is the harness value. moto replaces the key pair with FOOBAR* inside mock_aws.
_FAKE_PAIRS = {("testing", "testing"), ("FOOBARKEY", "FOOBARSECRET")}


def assert_mocked_env() -> None:
    pair = (os.environ.get("AWS_ACCESS_KEY_ID"), os.environ.get("AWS_SECRET_ACCESS_KEY"))
    if pair not in _FAKE_PAIRS:
        raise SeedError("AWS_ACCESS_KEY_ID is not the MOCKED test value")
    if os.environ.get("AWS_SESSION_TOKEN") != "testing":
        raise SeedError("AWS_SESSION_TOKEN is not the MOCKED test value")
    if os.environ.get("AWS_DEFAULT_REGION") != "us-east-1":
        raise SeedError("AWS_DEFAULT_REGION is not us-east-1")
    if os.environ.get("AWS_PROFILE"):
        raise SeedError("AWS_PROFILE must be unset for a MOCKED seed")
    for key in ("AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"):
        path = os.environ.get(key)
        if not path or os.path.exists(path):
            raise SeedError(f"{key} must point at a path that does not exist")


def install_fake_env(directory: str) -> None:
    """Point credential files at a directory that has no AWS config."""

    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
    os.environ["AWS_EC2_METADATA_DISABLED"] = "true"
    os.environ.pop("AWS_PROFILE", None)
    os.environ["AWS_CONFIG_FILE"] = os.path.join(directory, "no-aws-config")
    os.environ["AWS_SHARED_CREDENTIALS_FILE"] = os.path.join(directory, "no-aws-credentials")


def seed_random() -> None:
    """In-process stand-in for the moto seed URL. Sockets stay closed."""

    from moto.moto_api._internal import mock_random

    mock_random.seed(1337)


def apply(session, scenario: dict, *, post: bool = False, saved: dict[str, str] | None = None) -> dict[str, str]:
    assert_mocked_env()
    if scenario.get("mode", MODE) != MODE:
        raise SeedError("seed refuses a non-MOCKED mode")
    stretch = bool(scenario.get("stretch"))
    saved = dict(saved or {})
    steps = scenario["seed"]["post_claim"] if post else scenario["seed"]["steps"]
    default_region = scenario["seed"]["region"]
    for step in steps:
        _run(session, step, saved, default_region, stretch)
    return saved


def _run(session, step: dict, saved: dict[str, str], default_region: str, stretch: bool) -> None:
    call = step["call"]
    allowed = STRETCH_ALLOWLIST if stretch else SEED_ALLOWLIST
    if call not in allowed:
        raise SeedError(f"seed call {call} is not allowlisted")
    if call == "sts.assume_role" and not step.get("account"):
        raise SeedError("sts.assume_role is only the account switch")
    region = step.get("region") or default_region
    params = _prepare(substitute(step["params"], saved))
    client = _client(session, call.split(".", 1)[0], region, step.get("account"))
    method = getattr(client, call.split(".", 1)[1])
    try:
        response = method(**params)
    except Exception as exc:
        raise SeedError(f"{call} failed: {exc}") from exc
    if call == "s3.create_bucket":
        _emulate_bucket_defaults(client, params["Bucket"])
    for name, path in (step.get("save") or {}).items():
        try:
            saved[name] = str(dig(response, path))
        except KeyError as exc:
            raise SeedError(f"{call} did not return {path}") from exc


def _emulate_bucket_defaults(client, bucket: str) -> None:
    client.put_bucket_encryption(
        Bucket=bucket,
        ServerSideEncryptionConfiguration={
            "Rules": [
                {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
            ]
        },
    )
    client.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration=dict(_PAB_ON),
    )


def _prepare(params: dict) -> dict:
    prepared = dict(params)
    for key in _POLICY_FIELDS:
        if isinstance(prepared.get(key), (dict, list)):
            prepared[key] = json.dumps(prepared[key])
    code = prepared.get("Code")
    if isinstance(code, dict) and isinstance(code.get("ZipFile"), str):
        code = dict(code)
        code["ZipFile"] = code["ZipFile"].encode("utf-8")
        prepared["Code"] = code
    return prepared


def _client(session, service: str, region: str, account: str | None):
    if not account:
        return session.client(service, region_name=region)
    sts = session.client("sts", region_name=region)
    creds = sts.assume_role(
        RoleArn=f"arn:aws:iam::{account}:role/sv-eval-seed",
        RoleSessionName="sv-eval-seed",
    )["Credentials"]
    switched = boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )
    return switched.client(service, region_name=region)
