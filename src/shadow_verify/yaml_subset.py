"""YAML subset for claim files.

The subset is deliberate: claim files must parse the same way on every
machine, with no extra dependency and no YAML features that hide structure.
JSON is the escape hatch for anything this loader rejects.
"""

from __future__ import annotations

import re

from shadow_verify.errors import ClaimsError

_Line = tuple[int, int, str]
_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")
_INT = re.compile(r"-?(0|[1-9][0-9]*)")


class YamlSubsetError(ClaimsError):
    pass


def load_yaml_subset(text: str) -> object:
    if text.startswith("\ufeff"):
        text = text.lstrip("\ufeff")
    lines = _prepare(text)
    if not lines:
        raise YamlSubsetError("document is empty")
    value, index = _parse_block(lines, 0)
    if index != len(lines):
        raise YamlSubsetError(f"line {lines[index][0]}: unexpected content")
    return value


def _prepare(text: str) -> list[_Line]:
    lines: list[_Line] = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        if "\t" in raw:
            raise YamlSubsetError(f"line {lineno}: tabs are not allowed; use spaces or JSON")
        if raw.strip() == "" or raw.lstrip(" ").startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        stripped = raw.strip()
        if stripped.startswith(("&", "*", "!", "%", "?")):
            raise YamlSubsetError(
                f"line {lineno}: anchors, aliases, tags, and directives are not supported; use JSON"
            )
        head = stripped.split(":", 1)[0]
        if "<<" in head:
            raise YamlSubsetError(f"line {lineno}: merge keys are not supported; use JSON")
        lines.append((lineno, indent, stripped))
    return lines


def _parse_block(lines: list[_Line], index: int) -> tuple[object, int]:
    if index >= len(lines):
        raise YamlSubsetError("expected a value")
    text = lines[index][2]
    if text.startswith("- "):
        return _parse_list(lines, index)
    return _parse_map(lines, index)


def _parse_map(lines: list[_Line], index: int) -> tuple[dict[str, object], int]:
    indent = lines[index][1]
    mapping: dict[str, object] = {}
    while index < len(lines):
        lineno, ind, text = lines[index]
        if ind < indent:
            break
        if ind > indent:
            raise YamlSubsetError(f"line {lineno}: unexpected indent")
        if text.startswith("- "):
            raise YamlSubsetError(f"line {lineno}: expected a key, found a list item")
        key, raw_value = _split_key(text, lineno)
        if key in mapping:
            raise YamlSubsetError(f"line {lineno}: duplicate key {key!r}")
        if raw_value == "":
            if index + 1 >= len(lines) or lines[index + 1][1] <= indent:
                raise YamlSubsetError(f"line {lineno}: expected a nested value for {key!r}")
            value, index = _parse_block(lines, index + 1)
        else:
            value = _parse_scalar(raw_value, lineno)
            index += 1
        mapping[key] = value
    return mapping, index


def _parse_list(lines: list[_Line], index: int) -> tuple[list[object], int]:
    indent = lines[index][1]
    items: list[object] = []
    while index < len(lines):
        lineno, ind, text = lines[index]
        if ind < indent:
            break
        if ind > indent:
            raise YamlSubsetError(f"line {lineno}: unexpected indent")
        if not text.startswith("- "):
            break
        rest = text[2:].strip()
        if rest == "":
            if index + 1 >= len(lines) or lines[index + 1][1] <= indent:
                raise YamlSubsetError(f"line {lineno}: expected a nested list value")
            value, index = _parse_block(lines, index + 1)
            items.append(value)
            continue
        if _is_key(rest):
            item, index = _parse_list_map(lines, index, indent, rest, lineno)
            items.append(item)
            continue
        items.append(_parse_scalar(rest, lineno))
        index += 1
    if not items:
        raise YamlSubsetError("expected a list item")
    return items, index


def _parse_list_map(
    lines: list[_Line],
    index: int,
    dash_indent: int,
    rest: str,
    lineno: int,
) -> tuple[dict[str, object], int]:
    key, raw_value = _split_key(rest, lineno)
    item: dict[str, object] = {}
    if raw_value == "":
        if index + 1 >= len(lines) or lines[index + 1][1] <= dash_indent:
            raise YamlSubsetError(f"line {lineno}: expected a nested value for {key!r}")
        nested, index = _parse_block(lines, index + 1)
        item[key] = nested
    else:
        item[key] = _parse_scalar(raw_value, lineno)
        index += 1
    cont_indent = dash_indent + 2
    while index < len(lines):
        line_no, ind, text = lines[index]
        if ind != cont_indent or text.startswith("- "):
            break
        key, raw_value = _split_key(text, line_no)
        if key in item:
            raise YamlSubsetError(f"line {line_no}: duplicate key {key!r}")
        if raw_value == "":
            if index + 1 >= len(lines) or lines[index + 1][1] <= cont_indent:
                raise YamlSubsetError(f"line {line_no}: expected a nested value for {key!r}")
            nested, index = _parse_block(lines, index + 1)
            item[key] = nested
        else:
            item[key] = _parse_scalar(raw_value, line_no)
            index += 1
    return item, index


def _split_key(text: str, lineno: int) -> tuple[str, str]:
    if text.startswith(("'", '"')):
        raise YamlSubsetError(f"line {lineno}: quoted keys are not supported; use JSON")
    if text.endswith(":") and ": " not in text:
        key, raw_value = text[:-1], ""
    elif ": " in text:
        key, raw_value = text.split(": ", 1)
    else:
        raise YamlSubsetError(f"line {lineno}: expected 'key: value'")
    key = key.strip()
    if not _KEY.fullmatch(key):
        raise YamlSubsetError(f"line {lineno}: invalid key {key!r}")
    return key, raw_value.strip()


def _is_key(text: str) -> bool:
    if text.startswith(("'", '"', "[", "{", "|", ">", "*", "&", "!")):
        return False
    if text.endswith(":") and ": " not in text:
        return True
    return ": " in text


def _parse_scalar(raw: str, lineno: int) -> object:
    text = raw.strip()
    if text.startswith(("'", '"')):
        return _parse_quoted(text, lineno)
    text = _strip_comment(text).strip()
    if text == "":
        raise YamlSubsetError(f"line {lineno}: empty value; quote it or use JSON")
    if text.startswith(("&", "*")):
        raise YamlSubsetError(f"line {lineno}: anchors and aliases are not supported; use JSON")
    if text.startswith(("|", ">", "[", "{", "!")):
        raise YamlSubsetError(
            f"line {lineno}: unsupported YAML value {text!r}; use a plain scalar or JSON"
        )
    if text in {"true", "True", "TRUE"}:
        return True
    if text in {"false", "False", "FALSE"}:
        return False
    if text in {"null", "Null", "NULL", "~"}:
        return None
    if _INT.fullmatch(text):
        return int(text)
    return text


def _parse_quoted(text: str, lineno: int) -> str:
    quote = text[0]
    chars: list[str] = []
    index = 1
    closed = False
    while index < len(text):
        char = text[index]
        if quote == '"' and char == "\\":
            if index + 1 >= len(text):
                raise YamlSubsetError(f"line {lineno}: bad escape")
            nxt = text[index + 1]
            mapping = {'"': '"', "\\": "\\", "n": "\n", "t": "\t"}
            if nxt not in mapping:
                raise YamlSubsetError(f"line {lineno}: unsupported escape \\{nxt}")
            chars.append(mapping[nxt])
            index += 2
            continue
        if char == quote:
            if quote == "'" and index + 1 < len(text) and text[index + 1] == "'":
                chars.append("'")
                index += 2
                continue
            closed = True
            index += 1
            break
        chars.append(char)
        index += 1
    if not closed:
        raise YamlSubsetError(f"line {lineno}: unterminated string")
    trailing = text[index:].strip()
    if trailing and not trailing.startswith("#"):
        raise YamlSubsetError(f"line {lineno}: unexpected trailing characters")
    return "".join(chars)


def _strip_comment(text: str) -> str:
    in_single = False
    in_double = False
    for index, char in enumerate(text):
        if char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        elif char == "#" and not in_single and not in_double and (index == 0 or text[index - 1] == " "):
            return text[:index]
    return text
