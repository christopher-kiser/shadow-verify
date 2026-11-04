"""Read results.jsonl and summary.json. Write the MOCKED tables.

Raw Shadow Verify numbers come first. The fidelity-gate table is second
and is labeled as not the product. Coverage abstentions are listed apart
from NOT ASSESSED verdicts v0 actually earned.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from eval.manifest import repo_root
from eval.scoring import headlines, is_correct_na, is_coverage_na, is_coverage_wrong

CLASSES = ("PASS", "FAIL", "NOT_ASSESSED")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render a MOCKED eval report from result files.")
    parser.add_argument("--out", default=None)
    args = parser.parse_args(argv)
    out = Path(args.out) if args.out else repo_root() / "eval" / "results" / "mocked"
    jsonl = out / "results.jsonl"
    summary_path = out / "summary.json"
    if not jsonl.is_file() or not summary_path.is_file():
        print("missing results.jsonl or summary.json", file=sys.stderr)
        return 2
    rows = [json.loads(line) for line in jsonl.read_text(encoding="utf-8").splitlines() if line.strip()]
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    text = render(rows, summary)
    (out / "report.md").write_text(text, encoding="utf-8", newline="\n")
    sys.stdout.write(text)
    _plot(out)
    return 0


def render(rows: list[dict], summary: dict) -> str:
    lines = [
        "# Shadow Verify eval (MOCKED)",
        "",
        "author-designed scenarios, not real agent traces.",
        "",
        f"Mode: MOCKED. moto {summary.get('versions', {}).get('moto', 'unknown')}.",
        f"tool_commit: {summary.get('tool_commit')}",
        f"freeze: {summary.get('freeze_tag')} @ {summary.get('freeze_commit')}",
        f"set_sha256: {summary.get('set_sha256')}",
        f"held-out pin: {summary.get('heldout_pin_sha256')} (not run)",
        "",
    ]
    for set_name in ("core", "stretch"):
        lines.extend(_set_section(rows, summary, set_name))
    lines.append("plot skipped")
    lines.append("")
    return "\n".join(lines)


def _set_section(rows: list[dict], summary: dict, set_name: str) -> list[str]:
    sv = [
        row
        for row in rows
        if row.get("baseline") == "shadow_verify" and row.get("set") == set_name
    ]
    if not sv:
        return []
    lines = [f"## MOCKED {set_name} — raw Shadow Verify", ""]
    lines.extend(_headlines(sv))
    lines.extend(_gaps(sv))
    raw = summary.get("metrics_raw") if set_name == "core" else summary.get("stretch_metrics_raw")
    lines.extend(_matrix("raw", raw))
    lines.extend(_baselines(rows, summary, set_name))
    lines.extend(["", f"## MOCKED {set_name} — SV + eval fidelity gate (not the product)", ""])
    gated = summary.get("metrics_gated") if set_name == "core" else None
    if gated:
        lines.extend(_matrix("gated", gated))
    else:
        lines.append("Stretch gated metrics are not a separate product score.")
        lines.append("")
    return lines


def _headlines(sv: list[dict]) -> list[str]:
    data = headlines(sv)
    lines = [
        f"raw wrong-PASS vs truth = {len(data['raw_wrong_pass_vs_truth'])} ({_ids(data['raw_wrong_pass_vs_truth'])})",
        f"raw PASS on under-specified = {len(data['raw_pass_on_underspecified'])} ({_ids(data['raw_pass_on_underspecified'])})",
        f"raw vs expected_raw mismatches = {len(data['raw_vs_expected_raw_mismatches'])} ({_ids(data['raw_vs_expected_raw_mismatches'])})",
        f"S3 PASSes with owner unchecked = {len(data['s3_pass_owner_unchecked'])} ({_ids(data['s3_pass_owner_unchecked'])})",
    ]
    wrong = [
        row["scenario_id"]
        for row in sv
        if row.get("gated_verdict") == "PASS" and row.get("expected_verdict") != "PASS"
    ]
    lines.append(f"gated wrong-PASS = {len(wrong)} ({_ids(wrong)})")
    lines.append("")
    return lines


def _gaps(sv: list[dict]) -> list[str]:
    coverage = [row for row in sv if is_coverage_na(row)]
    wrong = [row for row in coverage if is_coverage_wrong(row)]
    same = [row for row in coverage if not is_coverage_wrong(row)]
    correct = [row for row in sv if is_correct_na(row)]
    lines = [
        "### Coverage NOT ASSESSED",
        "",
        "v0 had no checker for the property or resource. These are not correct abstentions.",
        f"Count where the label is PASS or FAIL (misses): {len(wrong)}.",
        "",
    ]
    lines.extend(_gap_lines(wrong, "miss"))
    lines.append("")
    lines.append(f"Coverage NOT ASSESSED whose label is already NOT ASSESSED: {len(same)}.")
    lines.append("")
    lines.extend(_gap_lines(same, "label NA"))
    lines.append("")
    lines.append(f"### Correct NOT ASSESSED ({len(correct)})")
    lines.append("")
    lines.append("v0 read what it could and abstained for an observed reason.")
    lines.append("")
    for row in correct:
        reason = ", ".join(row.get("reasons") or [])
        lines.append(f"- {row['scenario_id']}: {reason}")
    lines.append("")
    return lines


def _gap_lines(rows: list[dict], kind: str) -> list[str]:
    if not rows:
        return [f"(none — {kind})"]
    lines = []
    for row in rows:
        reason = ", ".join(row.get("reasons") or [])
        unchecked = ", ".join(row.get("unchecked") or [])
        extra = f" [{unchecked}]" if unchecked else ""
        lines.append(
            f"- {row['scenario_id']}: expected {row.get('expected_verdict')} got NOT_ASSESSED ({kind}){extra} {reason}"
        )
    return lines


def _matrix(label: str, metrics: dict | None) -> list[str]:
    if not metrics:
        return []
    matrix = metrics.get("confusion") or {}
    lines = [f"Confusion ({label}), rows are labels:", ""]
    lines.append("| label | " + " | ".join(CLASSES) + " |")
    lines.append("| --- | " + " | ".join("---" for _ in CLASSES) + " |")
    for gold in CLASSES:
        cells = [str(matrix.get(gold, {}).get(pred, 0)) for pred in CLASSES]
        lines.append(f"| {gold} | " + " | ".join(cells) + " |")
    lines.append("")
    det = metrics.get("detection")
    ff = metrics.get("false_fail")
    na = metrics.get("na_rate")
    lines.append(f"Catch rate (detection): {_fmt(det)} Wilson {_fmt_w(metrics.get('detection_wilson'))}")
    lines.append(f"False FAIL: {_fmt(ff)} Wilson {_fmt_w(metrics.get('false_fail_wilson'))}")
    lines.append(f"NOT ASSESSED rate: {_fmt(na)} Wilson {_fmt_w(metrics.get('na_rate_wilson'))}")
    lines.append(f"Wrong PASS: {metrics.get('wrong_pass')} ({_ids(metrics.get('wrong_pass_ids') or [])})")
    truth = metrics.get("truth") or {}
    lines.append(
        f"Truth wrong-PASS: {truth.get('wrong_pass')} ({_ids(truth.get('wrong_pass_ids') or [])})"
    )
    lines.append(f"Agreement: {_fmt(metrics.get('agreement'))} kappa {_fmt(metrics.get('kappa'))}")
    lines.append("")
    return lines


def _baselines(rows: list[dict], summary: dict, set_name: str) -> list[str]:
    if set_name != "core":
        return []
    lines = ["### Baselines (core, raw)", ""]
    lines.append("| baseline | detection | false FAIL | NA rate | wrong PASS |")
    lines.append("| --- | --- | --- | --- | --- |")
    table = summary.get("baselines") or {}
    for name in ("self_report", "naive_exists", "always_not_assessed", "shadow_verify"):
        metrics = table.get(name) or {}
        lines.append(
            "| {name} | {det} | {ff} | {na} | {wrong} |".format(
                name=name,
                det=_fmt(metrics.get("detection")),
                ff=_fmt(metrics.get("false_fail")),
                na=_fmt(metrics.get("na_rate")),
                wrong=metrics.get("wrong_pass"),
            )
        )
    lines.append("")
    return lines


def _ids(values: list[str]) -> str:
    return ", ".join(values) if values else "none"


def _fmt(value) -> str:
    if value is None:
        return "n/a"
    return f"{value:.3f}"


def _fmt_w(bound) -> str:
    if not bound:
        return "n/a"
    return f"[{bound['low']:.3f}, {bound['high']:.3f}]"


def _plot(_out: Path) -> None:
    try:
        import matplotlib  # noqa: F401
    except ImportError:
        print("plot skipped")
        return
    print("plot skipped")


if __name__ == "__main__":
    sys.exit(main())
