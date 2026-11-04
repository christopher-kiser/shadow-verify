"""Optional Terraform plan notes.

TODO: compare planned after-values with the claim and with the observed
AWS state, and let a real mismatch affect the verdict. v0 only reports
whether each claim's terraform_address appears in ``terraform show -json``
resource_changes, plus the planned actions. Plan notes are untrusted with
respect to PASS: they are copied into the report and the evidence bundle
and are not read by the checkers.
"""

from __future__ import annotations

import json
from pathlib import Path

from shadow_verify.errors import ClaimsError
from shadow_verify.models import Claim


def read_plan(path: Path) -> dict:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ClaimsError(f"cannot read terraform plan: {exc}") from exc
    try:
        data = json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ClaimsError(f"terraform plan is not UTF-8: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ClaimsError(f"terraform plan is not JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ClaimsError("terraform plan JSON must be an object")
    if "resource_changes" not in data:
        raise ClaimsError(
            "terraform plan JSON has no resource_changes; expected output from `terraform show -json`"
        )
    changes = data["resource_changes"]
    if not isinstance(changes, list):
        raise ClaimsError("resource_changes must be a list")
    return data


def plan_notes(claims: list[Claim], plan: dict | None) -> list[dict]:
    if plan is None:
        return []
    index: dict[str, list[str]] = {}
    for change in plan["resource_changes"]:
        if not isinstance(change, dict):
            continue
        address = change.get("address")
        if not isinstance(address, str):
            continue
        body = change.get("change")
        actions = body.get("actions", []) if isinstance(body, dict) else []
        if not isinstance(actions, list):
            actions = []
        index[address] = [str(action) for action in actions]
    notes: list[dict] = []
    for claim in claims:
        address = claim.terraform_address
        if not address:
            notes.append(
                {
                    "claim_id": claim.id,
                    "address": None,
                    "status": "not_requested",
                    "actions": [],
                    "detail": "claim has no terraform_address",
                }
            )
            continue
        if address not in index:
            notes.append(
                {
                    "claim_id": claim.id,
                    "address": address,
                    "status": "not_found",
                    "actions": [],
                    "detail": "address not in plan resource_changes",
                }
            )
            continue
        notes.append(
            {
                "claim_id": claim.id,
                "address": address,
                "status": "found",
                "actions": index[address],
                "detail": "present in the plan; v0 does not compare planned values to the claim or to AWS",
            }
        )
    return notes
