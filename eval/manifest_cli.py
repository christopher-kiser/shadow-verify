"""Argument parsing for the eval manifest.

The set hash and the freeze record stay in ``manifest.py``. This module decides
which directory a ``--files`` run may read or write.
"""

from __future__ import annotations

import argparse
import datetime
import re
import sys
from collections.abc import Iterable
from pathlib import Path

_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
# Compared after resolve and casefold, so EVAL and eval\ are the same directory.
_CORE_OUT = frozenset(
    {
        "eval",
        "eval/scenarios",
        "eval/labels",
        "eval/heldout",
    }
)
_CORE_MANIFEST_FILES = frozenset(
    {
        "eval/manifest.json",
        "eval/manifest.sha256",
    }
)

from eval.manifest import (
    _rel_escapes,
    check,
    heldout_problems,
    repo_root,
    write_manifest,
)


def cli_path_problems(root: Path, files: Iterable[str] | None) -> list[str]:
    """Reject --root and --files values that leave the repository root."""
    problems: list[str] = []
    repo = repo_root().resolve()
    try:
        root.resolve().relative_to(repo)
    except ValueError:
        problems.append(f"root escapes repository: {root}")
    if not files:
        return problems
    for rel in files:
        if _rel_escapes(rel):
            problems.append(f"path escapes repository: {rel}")
            continue
        if problems and not root.resolve().is_relative_to(repo):
            continue
        try:
            (root.resolve() / rel).resolve().relative_to(repo)
        except ValueError:
            problems.append(f"path escapes repository: {rel}")
    return problems


def cli_out_problems(root: Path, out: str) -> list[str]:
    """Reject an --out directory that leaves the repository root."""
    text = out.replace("\\", "/")
    if text.strip("/") in {"", "."} or _rel_escapes(text):
        return [f"path escapes repository: {out}"]
    repo = repo_root().resolve()
    try:
        root.resolve().relative_to(repo)
    except ValueError:
        return [f"path escapes repository: {out}"]
    try:
        (root.resolve() / text).resolve().relative_to(repo)
    except ValueError:
        return [f"path escapes repository: {out}"]
    return []


def _resolved_under(base: Path, text: str) -> Path:
    """Resolve ``text`` against ``base``. Separators are normalized first."""
    normalized = text.replace("\\", "/")
    return (base.resolve() / normalized).resolve()


def _rel_key(base: Path, target: Path) -> str | None:
    try:
        relative = target.resolve().relative_to(base.resolve())
    except ValueError:
        return None
    return relative.as_posix().strip("/").casefold()


def core_output_problems(root: Path, out: str) -> list[str]:
    """Refuse a --files run whose --out is a core directory.

    The comparison is the resolved relative path, casefolded. ``eval``,
    ``./eval/``, ``EVAL``, ``eval\\\\``, and an absolute path to that directory
    match. ``eval/scenarios``, ``eval/labels``, and ``eval/heldout`` match too.
    """
    try:
        target = _resolved_under(root, out)
    except OSError:
        return ["refuses to overwrite the core manifest"]
    bases = {root.resolve(), repo_root().resolve()}
    for base in bases:
        key = _rel_key(base, target)
        if key in _CORE_OUT:
            return ["refuses to overwrite the core manifest"]
        for name in ("manifest.json", "MANIFEST.sha256"):
            written = _rel_key(base, (target / name).resolve())
            if written in _CORE_MANIFEST_FILES:
                return ["refuses to overwrite the core manifest"]
    return []


def created_problems(created: str) -> list[str]:
    if _DATE.fullmatch(created) is None:
        return ["--created must be YYYY-MM-DD"]
    try:
        datetime.date.fromisoformat(created)
    except ValueError:
        return ["--created must be YYYY-MM-DD"]
    return []


def files_outside_out(root: Path, out: str, files: Iterable[str]) -> list[str]:
    """Every --files path must resolve strictly inside the resolved --out directory."""
    target = _resolved_under(root, out)
    problems: list[str] = []
    for rel in files:
        text = rel.replace("\\", "/")
        if _rel_escapes(text):
            continue
        file_path = _resolved_under(root, text)
        try:
            relative = file_path.relative_to(target)
        except ValueError:
            problems.append(f"file is outside --out: {rel}")
            continue
        if not relative.parts:
            problems.append(f"file is outside --out: {rel}")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compute or check the OFFLINE core eval manifest."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit 2 if the manifest or the held-out pin does not match",
    )
    parser.add_argument("--root", type=Path, default=None)
    parser.add_argument(
        "--out",
        default=None,
        help="repo-relative directory for manifest.json, MANIFEST.sha256, and scenarios/",
    )
    parser.add_argument(
        "--created",
        default=None,
        help="manifest created date; requires --out",
    )
    parser.add_argument(
        "--author",
        default=None,
        help="manifest author; requires --out",
    )
    parser.add_argument("--files", action="append", default=None)
    args = parser.parse_args(argv)
    if args.created is not None or args.author is not None:
        if not args.out:
            print("--created and --author require --out", file=sys.stderr)
            return 2
    if args.created is not None:
        for item in created_problems(args.created):
            print(item, file=sys.stderr)
            return 2
    if (args.files is None) != (args.out is None):
        if args.files is not None:
            print("--files requires --out", file=sys.stderr)
        else:
            print("--out requires --files", file=sys.stderr)
        return 2
    root = args.root if args.root is not None else repo_root()
    chosen = tuple(args.files) if args.files else None
    if chosen is not None:
        conflict = core_output_problems(root, args.out)
        if conflict:
            for item in conflict:
                print(item, file=sys.stderr)
            return 2
    escaped = cli_path_problems(root, chosen)
    if args.out is not None:
        escaped = [*escaped, *cli_out_problems(root, args.out)]
    if escaped:
        for item in escaped:
            print(item, file=sys.stderr)
        return 2
    if chosen is not None:
        outside = files_outside_out(root, args.out, chosen)
        if outside:
            for item in outside:
                print(item, file=sys.stderr)
            return 2
    check_heldout = chosen is None
    if args.check:
        problems = check(root, chosen, check_heldout=check_heldout, out=args.out)
        for item in problems:
            print(item, file=sys.stderr)
        return 2 if problems else 0
    if check_heldout:
        problems = heldout_problems(root)
        if problems:
            for item in problems:
                print(item, file=sys.stderr)
            return 2
    digest = write_manifest(
        root,
        chosen,
        check_heldout=False,
        out=args.out,
        created=args.created,
        author=args.author,
    )
    print(digest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
