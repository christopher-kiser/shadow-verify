"""Human and machine reports. Both come from the same result objects."""

from __future__ import annotations

from shadow_verify import __version__


def summary_counts(results: list[dict]) -> dict[str, int]:
    return {
        "pass": sum(1 for item in results if item["verdict"] == "PASS"),
        "fail": sum(1 for item in results if item["verdict"] == "FAIL"),
        "not_assessed": sum(1 for item in results if item["verdict"] == "NOT_ASSESSED"),
    }


def build_report(
    results: list[dict],
    *,
    evidence_path: str,
    bundle_sha256: str,
    plan_notes: list[dict],
    mode: str,
    tool_commit: str,
) -> dict:
    """``results`` are the same relabelled dicts stored in the evidence bundle."""

    return {
        "shadow_verify": __version__,
        "mode": mode,
        "tool_commit": tool_commit,
        "summary": summary_counts(results),
        "results": results,
        "plan_notes": plan_notes,
        "evidence_path": evidence_path,
        "bundle_sha256": bundle_sha256,
        "rules": {
            "agent_note": "untrusted; never an input to the verdict",
            "plan_notes": "informational in v0; never an input to the verdict",
        },
    }


def render_human(report: dict) -> str:
    counts = report["summary"]
    lines = [
        "Shadow Verify",
        (
            f"pass: {counts['pass']}  fail: {counts['fail']}  "
            f"not_assessed: {counts['not_assessed']}"
        ),
        "",
    ]
    for result in report["results"]:
        verdict = "NOT ASSESSED" if result["verdict"] == "NOT_ASSESSED" else result["verdict"]
        statement = result["statement"] or "(no statement)"
        lines.append(f"{verdict}  {result['id']}  {statement}")
        lines.append(f"  {result['resource_type']}  {result['identifier']}")
        for reason in result["reasons"]:
            lines.append(f"  - {reason}")
        if result.get("agent_note"):
            note = " ".join(str(result["agent_note"]).split())
            lines.append(f"  agent_note (untrusted, ignored): {note}")
    if report["plan_notes"]:
        lines.append("")
        lines.append("Terraform plan (informational, does not affect verdicts):")
        for note in report["plan_notes"]:
            actions = ",".join(note.get("actions") or []) or "-"
            lines.append(
                f"  - {note['claim_id']}: {note['status']} {note.get('address') or '-'} actions={actions}"
            )
    lines.append("")
    lines.append(f"evidence: {report['evidence_path']}")
    lines.append(f"bundle_sha256: {report['bundle_sha256']}")
    return "\n".join(lines) + "\n"


def render_summary(report: dict) -> str:
    """Job-summary text. It uses the same relabelled results as ``--json``."""

    counts = report["summary"]
    lines = [
        "Shadow Verify",
        f"pass {counts['pass']} · fail {counts['fail']} · not assessed {counts['not_assessed']}",
        "",
        f"bundle {report['bundle_sha256']}",
        "",
    ]
    for result in report["results"]:
        lines.append(f"{result['verdict']} {result['id']} {result['statement']}")
        for reason in result["reasons"]:
            lines.append(f"  {reason}")
    return "\n".join(lines) + "\n"
