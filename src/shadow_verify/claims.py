"""Load a claims file. Unknown fields and unknown checkers are errors, not passes."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from shadow_verify.checkers import get_checker, known_resource_types
from shadow_verify.errors import ClaimsError
from shadow_verify.models import Claim
from shadow_verify.yaml_subset import load_yaml_subset

_CLAIM_FIELDS = {
    "id",
    "statement",
    "resource_type",
    "identifier",
    "expected",
    "agent_note",
    "terraform_address",
}


def load_claims_file(path: Path) -> tuple[list[Claim], str]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ClaimsError(f"cannot read claims file: {exc}") from exc
    digest = hashlib.sha256(raw).hexdigest()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ClaimsError(f"claims file is not UTF-8: {exc}") from exc
    return load_claims(text, path.suffix), digest


def load_claims(text: str, suffix: str) -> list[Claim]:
    suffix = suffix.lower()
    if suffix == ".json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ClaimsError(f"claims JSON is invalid: {exc}") from exc
    elif suffix in {".yaml", ".yml"}:
        data = load_yaml_subset(text)
    else:
        raise ClaimsError("claims file must end in .json, .yaml, or .yml")
    return parse_document(data)


def parse_document(data: object) -> list[Claim]:
    if not isinstance(data, dict):
        raise ClaimsError("claims document must be a mapping")
    unknown = sorted(set(data) - {"version", "claims"})
    if unknown:
        raise ClaimsError(f"unknown top-level fields: {unknown}")
    if data.get("version") != 1:
        raise ClaimsError("version must be the integer 1")
    entries = data.get("claims")
    if not isinstance(entries, list) or not entries:
        raise ClaimsError("claims must be a non-empty list")
    parsed: list[Claim] = []
    seen: set[str] = set()
    for entry in entries:
        parsed.append(_parse_claim(entry, seen))
    return parsed


def _parse_claim(entry: object, seen: set[str]) -> Claim:
    if not isinstance(entry, dict):
        raise ClaimsError("each claim must be a mapping")
    extra = sorted(set(entry) - _CLAIM_FIELDS)
    if extra:
        raise ClaimsError(f"unknown claim fields: {extra}")
    claim_id = entry.get("id")
    if not isinstance(claim_id, str) or not claim_id.strip():
        raise ClaimsError("claim id must be a non-empty string")
    if claim_id in seen:
        raise ClaimsError(f"duplicate claim id {claim_id!r}")
    seen.add(claim_id)
    statement = entry.get("statement", "")
    if not isinstance(statement, str):
        raise ClaimsError(f"claim {claim_id!r} statement must be a string")
    resource_type = entry.get("resource_type")
    if not isinstance(resource_type, str) or not resource_type:
        raise ClaimsError(f"claim {claim_id!r} resource_type must be a string")
    if get_checker(resource_type) is None:
        known = ", ".join(known_resource_types())
        raise ClaimsError(
            f"claim {claim_id!r} has no checker for resource_type {resource_type!r}. Known: {known}"
        )
    identifier = entry.get("identifier")
    if not isinstance(identifier, str) or not identifier.strip():
        raise ClaimsError(f"claim {claim_id!r} identifier must be a non-empty string")
    expected = entry.get("expected")
    if not isinstance(expected, dict) or not expected:
        raise ClaimsError(f"claim {claim_id!r} expected must be a non-empty mapping")
    agent_note = entry.get("agent_note")
    if agent_note is not None and not isinstance(agent_note, str):
        raise ClaimsError(f"claim {claim_id!r} agent_note must be a string")
    address = entry.get("terraform_address")
    if address is not None and not isinstance(address, str):
        raise ClaimsError(f"claim {claim_id!r} terraform_address must be a string")
    return Claim(
        id=claim_id,
        statement=statement,
        resource_type=resource_type,
        identifier=identifier,
        expected=dict(expected),
        agent_note=agent_note,
        terraform_address=address,
    )
