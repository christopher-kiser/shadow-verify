"""Substitute ``${name}`` saved by earlier seed steps. Stdlib only."""

from __future__ import annotations

import re
from typing import Any

TOKEN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class PlaceholderError(Exception):
    def __init__(self, name: str) -> None:
        super().__init__(f"unknown placeholder ${{{name}}}")
        self.name = name


def names_in(value: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(value, str):
        found.update(TOKEN.findall(value))
    elif isinstance(value, dict):
        for item in value.values():
            found.update(names_in(item))
    elif isinstance(value, list):
        for item in value:
            found.update(names_in(item))
    return found


def substitute(value: Any, env: dict[str, str]) -> Any:
    if isinstance(value, str):

        def repl(match: re.Match[str]) -> str:
            name = match.group(1)
            if name not in env:
                raise PlaceholderError(name)
            return env[name]

        return TOKEN.sub(repl, value)
    if isinstance(value, dict):
        return {key: substitute(item, env) for key, item in value.items()}
    if isinstance(value, list):
        return [substitute(item, env) for item in value]
    return value


def dig(payload: Any, path: str) -> Any:
    current = payload
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            raise KeyError(path)
        current = current[part]
    return current
