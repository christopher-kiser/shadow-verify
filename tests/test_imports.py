"""AST guards. A stray boto3 client must fail here, with no network call."""

import ast
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1] / "src" / "shadow_verify"


def _modules():
    return sorted(PACKAGE.rglob("*.py"))


def test_boto3_is_imported_only_in_cli():
    offenders = []
    for path in _modules():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            else:
                continue
            if any(name == "boto3" or name.startswith("boto3.") for name in names):
                if path.name != "cli.py":
                    offenders.append(str(path.relative_to(PACKAGE.parent.parent)))
    assert offenders == []


def test_client_calls_only_inside_from_session():
    offenders = []
    for path in _modules():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef) or node.name != "from_session":
                continue
            if path.name != "aws.py":
                offenders.append(f"from_session in {path.name}")
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _is_client_call(node):
                if not _inside_from_session(tree, node):
                    offenders.append(f"{path.name}:{node.lineno}")
    assert offenders == []


def _is_client_call(node: ast.Call) -> bool:
    return isinstance(node.func, ast.Attribute) and node.func.attr == "client"


def _inside_from_session(tree: ast.AST, target: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "from_session":
            for child in ast.walk(node):
                if child is target:
                    return True
    return False
