"""Reproduce an agent's false "done" against moto. No AWS account required.

The claim says the bucket is locked down. The mocked bucket has three
public-access flags true and BlockPublicPolicy false. Shadow Verify must
exit 1 and report FAIL.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_SESSION_TOKEN", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ["AWS_EC2_METADATA_DISABLED"] = "true"

import boto3  # noqa: E402
from moto import mock_aws  # noqa: E402

from shadow_verify.cli import run  # noqa: E402

BUCKET = "agent-claimed-locked"
CLAIMS = Path(__file__).resolve().parent / "claims.yaml"


def seed() -> None:
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket=BUCKET)
    s3.put_public_access_block(
        Bucket=BUCKET,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": True,
        },
    )


def main() -> int:
    print("Demo: an agent reported this S3 bucket as locked down.", file=sys.stderr)
    print("Mocked live state: BlockPublicPolicy is false. No AWS account is used.", file=sys.stderr)
    out_dir = Path(tempfile.mkdtemp(prefix="shadow-verify-demo-"))
    evidence = out_dir / "evidence.json"
    with mock_aws():
        seed()
        code = run(
            [
                "--claims",
                str(CLAIMS),
                "--region",
                "us-east-1",
                "--evidence",
                str(evidence),
            ]
        )
    print(f"evidence bundle: {evidence}", file=sys.stderr)
    if code != 1:
        print("demo did not catch the false claim", file=sys.stderr)
        return code if code != 0 else 2
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
