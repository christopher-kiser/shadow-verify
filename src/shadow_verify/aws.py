"""Read-only AWS calls.

Every operation is checked against ALLOWED_OPERATIONS before it is sent.
The wrapper stores the request parameters and the response, or the error,
on the evidence log. Checkers never call boto3 themselves.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from shadow_verify.errors import ShadowVerifyError
from shadow_verify.evidence import EvidenceItem, EvidenceLog

# API operations this process calls. Not a verb prefix.
ALLOWED_OPERATIONS: frozenset[str] = frozenset(
    {
        "s3:GetPublicAccessBlock",
        "s3:GetBucketPolicyStatus",
        "ec2:DescribeSecurityGroups",
        "iam:GetRole",
        "iam:ListAttachedRolePolicies",
        "iam:ListRolePolicies",
        "iam:GetRolePolicy",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
    }
)

# IAM action required to call each API operation. These names differ when
# the API name is not the IAM action (GetPublicAccessBlock is
# s3:GetBucketPublicAccessBlock; ListObjectsV2 and HeadBucket are s3:ListBucket).
OPERATION_IAM_ACTIONS: dict[str, str] = {
    "s3:GetPublicAccessBlock": "s3:GetBucketPublicAccessBlock",
    "s3:GetBucketPolicyStatus": "s3:GetBucketPolicyStatus",
    "ec2:DescribeSecurityGroups": "ec2:DescribeSecurityGroups",
    "iam:GetRole": "iam:GetRole",
    "iam:ListAttachedRolePolicies": "iam:ListAttachedRolePolicies",
    "iam:ListRolePolicies": "iam:ListRolePolicies",
    "iam:GetRolePolicy": "iam:GetRolePolicy",
    "iam:GetPolicy": "iam:GetPolicy",
    "iam:GetPolicyVersion": "iam:GetPolicyVersion",
}

# Data and secret reads. Refused even if someone later adds them to the allowlist.
DENIED_OPERATIONS: frozenset[str] = frozenset(
    {
        "secretsmanager:GetSecretValue",
        "s3:GetObject",
        "s3:GetObjectVersion",
        "ssm:GetParameter",
        "ssm:GetParameters",
        "ssm:GetParametersByPath",
        "ssm:GetParameterHistory",
        "kms:Decrypt",
        "dynamodb:GetItem",
        "dynamodb:BatchGetItem",
        "dynamodb:Query",
        "dynamodb:Scan",
        "dynamodb:ExecuteStatement",
        "lambda:GetFunction",
        "ec2:GetPasswordData",
    }
)

# standard mode, max_attempts includes the first try. Two later tries wait
# at most min(scale * 2^(n-1), 20) seconds, plus up to 5s of retry-after.
# Throttling scale is 1, so the two gaps are at most 1+5 and 2+5 seconds.
# Each attempt can also spend connect_timeout + read_timeout.
# Worst case: 3 * (3 + 10) + 13 = 52 seconds per call.
CONNECT_TIMEOUT_SECONDS = 3
READ_TIMEOUT_SECONDS = 10
MAX_ATTEMPTS = 3
WORST_CASE_WAIT_SECONDS = 52
CLIENT_CONFIG = Config(
    retries={"mode": "standard", "max_attempts": MAX_ATTEMPTS},
    connect_timeout=CONNECT_TIMEOUT_SECONDS,
    read_timeout=READ_TIMEOUT_SECONDS,
)

_MAX_PAGES = 50
_SNAKE = re.compile(r"(?<!^)(?=[A-Z])")


def operation_method_name(operation: str) -> str:
    return _SNAKE.sub("_", operation).lower()


def operation_pair(service: str, operation: str) -> str:
    return f"{service}:{operation}"


def refusal(service: str, operation: str) -> str | None:
    """Return a refusal reason, or None when the call may be sent.

    Denied pairs are refused first, then anything absent from the exact
    allowlist. The client method is not looked up until this returns None.
    """

    pair = operation_pair(service, operation)
    if pair in DENIED_OPERATIONS:
        return f"refusing denied AWS call {pair}"
    if pair not in ALLOWED_OPERATIONS:
        return f"refusing non-allowlisted AWS call {pair}"
    return None


@dataclass
class ApiResult:
    pages: list[EvidenceItem]
    complete: bool
    item_ids: list[str] = field(init=False)

    def __post_init__(self) -> None:
        self.item_ids = [page.id for page in self.pages]

    @property
    def error(self) -> EvidenceItem | None:
        for page in self.pages:
            if not page.ok:
                return page
        return None


class BotoAws:
    def __init__(self, *, s3, ec2, iam, evidence: EvidenceLog) -> None:
        self._s3 = s3
        self._ec2 = ec2
        self._iam = iam
        self.evidence = evidence

    @classmethod
    def from_session(cls, session, region: str, evidence: EvidenceLog) -> BotoAws:
        """Build clients from a boto3 Session, or any object with client().

        An eval harness can pass its own session to count calls or to raise
        AccessDenied. region_name is forwarded on every client() call.
        """

        return cls(
            s3=session.client("s3", region_name=region, config=CLIENT_CONFIG),
            ec2=session.client("ec2", region_name=region, config=CLIENT_CONFIG),
            iam=session.client("iam", region_name=region, config=CLIENT_CONFIG),
            evidence=evidence,
        )

    def get_public_access_block(self, bucket: str) -> EvidenceItem:
        return self._invoke("s3", "GetPublicAccessBlock", self._s3, Bucket=bucket)

    def get_bucket_policy_status(self, bucket: str) -> EvidenceItem:
        return self._invoke("s3", "GetBucketPolicyStatus", self._s3, Bucket=bucket)

    def describe_security_group(self, group_id: str) -> EvidenceItem:
        return self._invoke(
            "ec2",
            "DescribeSecurityGroups",
            self._ec2,
            GroupIds=[group_id],
        )

    def get_role(self, role_name: str) -> EvidenceItem:
        return self._invoke("iam", "GetRole", self._iam, RoleName=role_name)

    def list_attached_role_policies(self, role_name: str) -> ApiResult:
        return self._pages("iam", "ListAttachedRolePolicies", self._iam, RoleName=role_name)

    def list_role_policies(self, role_name: str) -> ApiResult:
        return self._pages("iam", "ListRolePolicies", self._iam, RoleName=role_name)

    def get_role_policy(self, role_name: str, policy_name: str) -> EvidenceItem:
        return self._invoke(
            "iam",
            "GetRolePolicy",
            self._iam,
            RoleName=role_name,
            PolicyName=policy_name,
        )

    def get_policy(self, policy_arn: str) -> EvidenceItem:
        return self._invoke("iam", "GetPolicy", self._iam, PolicyArn=policy_arn)

    def get_policy_version(self, policy_arn: str, version_id: str) -> EvidenceItem:
        return self._invoke(
            "iam",
            "GetPolicyVersion",
            self._iam,
            PolicyArn=policy_arn,
            VersionId=version_id,
        )

    def _pages(self, service: str, operation: str, client, **params) -> ApiResult:
        pages: list[EvidenceItem] = []
        marker: str | None = None
        complete = True
        while True:
            call_params = dict(params)
            if marker:
                call_params["Marker"] = marker
            item = self._invoke(service, operation, client, **call_params)
            pages.append(item)
            if not item.ok:
                complete = False
                break
            if not item.response.get("IsTruncated"):
                break
            marker = item.response.get("Marker")
            if not isinstance(marker, str) or not marker:
                complete = False
                break
            if len(pages) >= _MAX_PAGES:
                complete = False
                break
        return ApiResult(pages=pages, complete=complete)

    def _invoke(self, service: str, operation: str, client, **params) -> EvidenceItem:
        reason = refusal(service, operation)
        if reason is not None:
            raise ShadowVerifyError(reason)
        method = getattr(client, operation_method_name(operation))
        try:
            response = method(**params)
        except ClientError as exc:
            error = {}
            if isinstance(exc.response, dict):
                raw = exc.response.get("Error", {})
                if isinstance(raw, dict):
                    error = raw
            code = str(error.get("Code") or "ClientError")
            message = str(error.get("Message") or "")
            return self.evidence.record(
                service,
                operation,
                params,
                error_code=code,
                error_message=message,
                error_response=exc.response,
            )
        except BotoCoreError as exc:
            return self.evidence.record(
                service,
                operation,
                params,
                error_code=exc.__class__.__name__,
                error_message=str(exc),
            )
        return self.evidence.record(service, operation, params, response=response)
