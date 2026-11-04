"""S3 public access block and bucket policy publicity.

Rules, in order, for each key present under ``expected``:

* ``block_public_acls``, ``ignore_public_acls``, ``block_public_policy``,
  ``restrict_public_buckets`` come from ``GetPublicAccessBlock``. A
  ``NoSuchPublicAccessBlockConfiguration`` error is the observation that no
  configuration exists. AWS treats those four settings as false in that
  case, so the checker compares false. It does not treat the error as
  "unknown".
* ``bucket_policy_public`` comes only from ``GetBucketPolicyStatus``
  ``PolicyStatus.IsPublic``. ``NoSuchBucketPolicy`` is observed as not
  public. The policy document is not parsed. A second publicity algorithm
  would be a guess.
* ``region`` is always read from ``GetBucketLocation``. The claim's
  ``region`` is the expected value, or the run region when the claim omits
  it. ``LocationConstraint`` ``None`` or ``""`` is ``us-east-1``. ``EU`` is
  ``eu-west-1``. A difference is FAIL (``region_mismatch``). Any error
  reading the location is NOT ASSESSED and is not skipped.

``NoSuchBucket`` stops the check: the bucket is not there to read.
Any other error on a requested property is NOT ASSESSED for that property.
"""

from __future__ import annotations

from shadow_verify.aws import BotoAws
from shadow_verify.checkers.base import call_failure, compare_bool, finish
from shadow_verify.errors import ClaimsError
from shadow_verify.models import CheckResult, Claim, PropertyResult, Verdict

_PAB_FIELDS = (
    ("block_public_acls", "BlockPublicAcls"),
    ("ignore_public_acls", "IgnorePublicAcls"),
    ("block_public_policy", "BlockPublicPolicy"),
    ("restrict_public_buckets", "RestrictPublicBuckets"),
)
_KNOWN = {name for name, _field in _PAB_FIELDS} | {"bucket_policy_public"}
_MISSING_PAB = "NoSuchPublicAccessBlockConfiguration"
_NO_POLICY = "NoSuchBucketPolicy"
_NO_BUCKET = "NoSuchBucket"


class S3BucketChecker:
    resource_type = "s3_bucket"

    def check(self, claim: Claim, aws: BotoAws) -> CheckResult:
        expected = _validate(claim)
        expected_region = _expected_region(claim, aws)
        evidence_ids: list[str] = []
        properties: list[PropertyResult] = []
        location = aws.get_bucket_location(claim.identifier)
        evidence_ids.append(location.id)
        properties.append(_region_result(location, expected_region))
        if location.error_code == _NO_BUCKET:
            return finish(claim, properties, evidence_ids)
        wants_pab = any(name in expected for name, _field in _PAB_FIELDS)
        if wants_pab:
            item = aws.get_public_access_block(claim.identifier)
            evidence_ids.append(item.id)
            if item.error_code == _NO_BUCKET:
                properties.append(
                    PropertyResult(
                        name="read",
                        verdict=Verdict.NOT_ASSESSED,
                        reason=f"GetPublicAccessBlock failed: {_NO_BUCKET}: bucket is not visible",
                    )
                )
                return finish(claim, properties, evidence_ids)
            properties.extend(_public_access_block(item, expected))
        if "bucket_policy_public" in expected:
            item = aws.get_bucket_policy_status(claim.identifier)
            evidence_ids.append(item.id)
            properties.append(_policy_public(item, bool(expected["bucket_policy_public"])))
        return finish(claim, properties, evidence_ids)


def _expected_region(claim: Claim, aws: BotoAws) -> str:
    if claim.region is not None:
        return claim.region
    return aws.region


def _normalize_location(value: object) -> str | None:
    """Map a GetBucketLocation constraint to a region name.

    ``None`` and ``""`` are the legacy us-east-1 values. ``EU`` is eu-west-1.
    Any other non-string is not understood.
    """

    if value is None or value == "":
        return "us-east-1"
    if not isinstance(value, str):
        return None
    if value == "EU":
        return "eu-west-1"
    return value


def _region_result(item, expected: str) -> PropertyResult:
    if not item.ok:
        return PropertyResult(
            name="region",
            verdict=Verdict.NOT_ASSESSED,
            reason=call_failure("GetBucketLocation", item),
        )
    actual = _normalize_location(item.response.get("LocationConstraint"))
    if actual is None:
        return PropertyResult(
            name="region",
            verdict=Verdict.NOT_ASSESSED,
            reason="GetBucketLocation response has no usable LocationConstraint",
        )
    if actual == expected:
        return PropertyResult(name="region", verdict=Verdict.PASS, reason=f"region is {actual}")
    return PropertyResult(
        name="region",
        verdict=Verdict.FAIL,
        reason=f"region_mismatch: region is {actual}; expected {expected}",
    )


def _validate(claim: Claim) -> dict:
    expected = claim.expected
    unknown = sorted(set(expected) - _KNOWN)
    if unknown:
        raise ClaimsError(f"s3_bucket claim {claim.id!r} has unknown expected keys: {unknown}")
    if not expected:
        raise ClaimsError(f"s3_bucket claim {claim.id!r} has an empty expected block")
    for key, value in expected.items():
        if not isinstance(value, bool):
            raise ClaimsError(f"s3_bucket claim {claim.id!r} expected.{key} must be a boolean")
    if not isinstance(claim.identifier, str) or not claim.identifier.strip():
        raise ClaimsError(f"s3_bucket claim {claim.id!r} identifier must be a bucket name")
    return expected


def _public_access_block(item, expected: dict) -> list[PropertyResult]:
    if item.ok:
        config = item.response.get("PublicAccessBlockConfiguration")
        if not isinstance(config, dict):
            return [
                PropertyResult(
                    name="public_access_block",
                    verdict=Verdict.NOT_ASSESSED,
                    reason="GetPublicAccessBlock response has no PublicAccessBlockConfiguration",
                )
            ]
        results: list[PropertyResult] = []
        for name, field in _PAB_FIELDS:
            if name not in expected:
                continue
            if field not in config or not isinstance(config[field], bool):
                results.append(
                    PropertyResult(
                        name=name,
                        verdict=Verdict.NOT_ASSESSED,
                        reason=f"GetPublicAccessBlock response has no boolean {field}",
                    )
                )
                continue
            results.append(compare_bool(name, config[field], expected[name]))
        return results
    if item.error_code == _MISSING_PAB:
        note = "no public access block configuration; AWS treats unset flags as false"
        return [
            compare_bool(name, False, expected[name], note=note)
            for name, _field in _PAB_FIELDS
            if name in expected
        ]
    return [
        PropertyResult(
            name="public_access_block",
            verdict=Verdict.NOT_ASSESSED,
            reason=call_failure("GetPublicAccessBlock", item),
        )
    ]


def _policy_public(item, expected_public: bool) -> PropertyResult:
    if item.ok:
        status = item.response.get("PolicyStatus")
        if not isinstance(status, dict) or not isinstance(status.get("IsPublic"), bool):
            return PropertyResult(
                name="bucket_policy_public",
                verdict=Verdict.NOT_ASSESSED,
                reason="GetBucketPolicyStatus response has no boolean PolicyStatus.IsPublic",
            )
        return compare_bool("bucket_policy_public", status["IsPublic"], expected_public)
    if item.error_code == _NO_POLICY:
        return compare_bool(
            "bucket_policy_public",
            False,
            expected_public,
            note="no bucket policy",
        )
    if item.error_code == _NO_BUCKET:
        return PropertyResult(
            name="bucket_policy_public",
            verdict=Verdict.NOT_ASSESSED,
            reason=f"GetBucketPolicyStatus failed: {_NO_BUCKET}: bucket is not visible",
        )
    return PropertyResult(
        name="bucket_policy_public",
        verdict=Verdict.NOT_ASSESSED,
        reason=call_failure("GetBucketPolicyStatus", item),
    )
