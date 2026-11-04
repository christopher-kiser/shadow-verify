import boto3

from shadow_verify.aws import BotoAws
from shadow_verify.evidence import EvidenceLog
from shadow_verify.models import Claim

REGION = "us-east-1"

# Moto's S3 router returns 404 for the bucket name "logs". Tests use logs-prod.


def aws_stack(evidence: EvidenceLog | None = None) -> tuple[BotoAws, EvidenceLog]:
    evidence = evidence or EvidenceLog()
    aws = BotoAws(
        s3=boto3.client("s3", region_name=REGION),
        ec2=boto3.client("ec2", region_name=REGION),
        iam=boto3.client("iam", region_name=REGION),
        evidence=evidence,
    )
    return aws, evidence


def claim(
    resource_type: str,
    identifier: str,
    expected: dict,
    *,
    claim_id: str = "claim-1",
    statement: str = "stated by the agent",
    agent_note: str | None = None,
    terraform_address: str | None = None,
) -> Claim:
    return Claim(
        id=claim_id,
        statement=statement,
        resource_type=resource_type,
        identifier=identifier,
        expected=expected,
        agent_note=agent_note,
        terraform_address=terraform_address,
    )


# Spec section 2. Shared by the core eval tests and the legacy scenario tests.
CONDITIONS = {
    "none",
    "wrong_region",
    "wrong_account",
    "stale_read",
    "access_denied",
    "throttling",
    "timeout",
    "not_found",
    "pagination",
    "truncated_pagination",
    "underspecified_claim",
    "cidr_semantics",
    "unresolvable_source",
}

SEED_ALLOWLIST = {
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

S3_LOCKED = {
    "block_public_acls": True,
    "ignore_public_acls": True,
    "block_public_policy": True,
    "restrict_public_buckets": True,
    "bucket_policy_public": False,
}
