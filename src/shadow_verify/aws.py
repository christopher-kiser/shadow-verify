"""Read-only AWS calls.

Every operation is checked against ALLOWED_OPERATIONS before it is sent.
The wrapper stores the request parameters and the response, or the error,
on the evidence log. Checkers never call boto3 themselves.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from shadow_verify.errors import ShadowVerifyError
from shadow_verify.evidence import EvidenceItem, EvidenceLog

ALLOWED_OPERATIONS: frozenset[tuple[str, str]] = frozenset(
    {
        ("s3", "GetPublicAccessBlock"),
        ("s3", "GetBucketPolicyStatus"),
        ("ec2", "DescribeSecurityGroups"),
        ("iam", "GetRole"),
        ("iam", "ListAttachedRolePolicies"),
        ("iam", "ListRolePolicies"),
        ("iam", "GetRolePolicy"),
        ("iam", "GetPolicy"),
        ("iam", "GetPolicyVersion"),
    }
)

_MAX_PAGES = 50
_SNAKE = re.compile(r"(?<!^)(?=[A-Z])")


def operation_method_name(operation: str) -> str:
    return _SNAKE.sub("_", operation).lower()


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
    def from_session(cls, session: boto3.Session, region: str, evidence: EvidenceLog) -> BotoAws:
        return cls(
            s3=session.client("s3", region_name=region),
            ec2=session.client("ec2", region_name=region),
            iam=session.client("iam", region_name=region),
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
        if (service, operation) not in ALLOWED_OPERATIONS:
            raise ShadowVerifyError(f"refusing non-allowlisted AWS call {service}:{operation}")
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
