"""Claim and verdict types shared by the CLI, checkers, and evidence bundle."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_ASSESSED = "NOT_ASSESSED"

    @property
    def label(self) -> str:
        if self is Verdict.NOT_ASSESSED:
            return "NOT ASSESSED"
        return self.value


@dataclass(frozen=True)
class Claim:
    id: str
    statement: str
    resource_type: str
    identifier: str
    expected: dict[str, Any]
    agent_note: str | None = None
    terraform_address: str | None = None
    region: str | None = None


@dataclass(frozen=True)
class PropertyResult:
    """One explicit expected property. Checkers do not invent extras."""

    name: str
    verdict: Verdict
    reason: str


@dataclass(frozen=True)
class CheckResult:
    claim_id: str
    statement: str
    resource_type: str
    identifier: str
    verdict: Verdict
    reasons: tuple[str, ...]
    evidence_item_ids: tuple[str, ...]
    agent_note: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.claim_id,
            "statement": self.statement,
            "resource_type": self.resource_type,
            "identifier": self.identifier,
            "verdict": self.verdict.value,
            "reasons": list(self.reasons),
            "evidence_item_ids": list(self.evidence_item_ids),
            "agent_note": self.agent_note,
        }
