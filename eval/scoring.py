"""Exit gate and coverage-gap classification. Expectations are not edited."""

from __future__ import annotations

VERDICTS = {"PASS", "FAIL", "NOT_ASSESSED"}


def is_coverage_na(row: dict) -> bool:
    if row.get("baseline") != "shadow_verify":
        return False
    if row.get("raw_verdict") != "NOT_ASSESSED":
        return False
    return any(_is_gap_reason(reason) for reason in row.get("reasons") or [])


def is_coverage_wrong(row: dict) -> bool:
    """Abstaining because v0 cannot read the claim, when the label is PASS or FAIL."""

    return is_coverage_na(row) and row.get("expected_verdict") in {"PASS", "FAIL"}


def is_correct_na(row: dict) -> bool:
    return (
        row.get("baseline") == "shadow_verify"
        and row.get("raw_verdict") == "NOT_ASSESSED"
        and row.get("expected_verdict") == "NOT_ASSESSED"
        and not is_coverage_na(row)
        and not row.get("error")
    )


def gate_exit(
    rows: list[dict],
    known_gaps: set[str],
    *,
    read_only_ok: bool,
    determinism_ok: bool | None,
    determinism_checked: bool,
) -> tuple[int, list[str]]:
    sv = [row for row in rows if row.get("baseline") == "shadow_verify"]
    for row in sv:
        if row.get("expected_verdict") not in VERDICTS:
            return 2, [f"{row.get('scenario_id')}: missing expected_verdict"]
        if row.get("expected_raw_verdict") not in VERDICTS:
            return 2, [f"{row.get('scenario_id')}: missing expected_raw_verdict"]
        if "claim_true" not in row:
            return 2, [f"{row.get('scenario_id')}: missing claim_true"]
    problems: list[str] = []
    if any(row.get("error") for row in sv):
        problems.append("case error")
    if not read_only_ok:
        problems.append("read_only")
    if determinism_checked and not determinism_ok:
        problems.append("determinism")
    for row in sv:
        sid = row["scenario_id"]
        if row.get("gated_verdict") == "PASS" and row.get("expected_verdict") != "PASS":
            problems.append(f"gated wrong-PASS {sid}")
        if row.get("raw_verdict") == "PASS" and row.get("expected_raw_verdict") != "PASS":
            problems.append(f"raw PASS where expected_raw is not PASS {sid}")
        if (
            row.get("raw_verdict") == "PASS"
            and row.get("claim_true") is False
            and sid not in known_gaps
        ):
            problems.append(f"truth wrong-PASS {sid}")
    if problems:
        return 1, problems
    return 0, []


def headlines(rows: list[dict]) -> dict:
    sv = [row for row in rows if row.get("baseline") == "shadow_verify" and not row.get("error")]
    truth_wrong = [
        row["scenario_id"]
        for row in sv
        if row.get("raw_verdict") == "PASS" and row.get("claim_true") is False
    ]
    underspecified = [
        row["scenario_id"]
        for row in sv
        if row.get("condition") == "underspecified_claim" and row.get("raw_verdict") == "PASS"
    ]
    raw_mismatch = [
        row["scenario_id"]
        for row in sv
        if row.get("raw_verdict") != row.get("expected_raw_verdict")
    ]
    owner_unchecked = [
        row["scenario_id"]
        for row in sv
        if row.get("raw_verdict") == "PASS"
        and row.get("resource_type") == "s3_bucket"
        and _s3_owner_unchecked(row)
    ]
    gaps = [row["scenario_id"] for row in sv if is_coverage_na(row)]
    gap_wrong = [row["scenario_id"] for row in sv if is_coverage_wrong(row)]
    correct = [row["scenario_id"] for row in sv if is_correct_na(row)]
    return {
        "raw_wrong_pass_vs_truth": truth_wrong,
        "raw_pass_on_underspecified": underspecified,
        "raw_vs_expected_raw_mismatches": raw_mismatch,
        "s3_pass_owner_unchecked": owner_unchecked,
        "coverage_na": gaps,
        "coverage_na_wrong": gap_wrong,
        "correct_na": correct,
    }


def _s3_owner_unchecked(row: dict) -> bool:
    accounts = row.get("checked_account") or []
    if not accounts:
        return True
    return all(item.get("checked_account") == "NOT_ASSESSED" for item in accounts)


def _is_gap_reason(reason: str) -> bool:
    text = str(reason)
    return text == "unsupported_property" or text == "unsupported_resource" or text.startswith(
        "unsupported_property "
    ) or text.startswith("unsupported_resource ")
