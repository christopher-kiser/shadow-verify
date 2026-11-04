"""Checker registry. Add a checker by implementing ``check`` and calling ``register``."""

from __future__ import annotations

from shadow_verify.checkers.iam_role import IamRoleChecker
from shadow_verify.checkers.s3_bucket import S3BucketChecker
from shadow_verify.checkers.security_group import SecurityGroupChecker

CHECKERS: dict = {}


def register(checker):
    CHECKERS[checker.resource_type] = checker
    return checker


def get_checker(resource_type: str):
    return CHECKERS.get(resource_type)


def known_resource_types() -> list[str]:
    return sorted(CHECKERS)


register(S3BucketChecker())
register(SecurityGroupChecker())
register(IamRoleChecker())
