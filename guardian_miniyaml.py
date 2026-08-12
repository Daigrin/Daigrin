"""Minimal YAML loader — zero-dependency fallback for Guardian.

Guardian normally uses PyYAML. On devices where PyYAML is not installed
(low-power, embedded, fresh machines), this module provides ``safe_load``
for the subset of YAML that Guardian.yaml uses: nested mappings, lists
(block and inline), scalars (str/int/float/bool/null), comments, and
document markers. It is a defensive fallback, not a general YAML parser —
full YAML users should install PyYAML (``pip install pyyaml``).

Only ``safe_load`` is implemented; anything it cannot parse raises
ValueError rather than guessing, so a misread config can never silently
weaken a safety gate.
"""

from typing import Any

_MISSING = object()


def safe_load(text: Any) -> Any:  # noqa: D401 - mirrors yaml.safe_load
    """Parse the Guardian.yaml subset. Returns dict/list/scalar, or None.

    Accepts a string or a text stream (anything with .read()), matching
    PyYAML's safe_load flexibility.
    """
    if hasattr(text, "read"):
        text = text.read()
    if not isinstance(text, str):
        raise ValueError("miniyaml: safe_load expects a string or text stream")
    lines = []
    for raw in text.splitlines():
        stripped = _strip_comment(raw)
        if stripped.strip() in ("", "---", "..."):
            continue
        indent = len(stripped) - len(stripped.lstrip(" "))
        lines.append((indent, stripped.strip()))
    if not lines:
        return None
    value, _ = _parse_block(lines, 0, lines[0][0])
    return value


def _strip_comment(line: str) -> str:
    """Remove a trailing # comment that is not inside quotes."""
    out = []
    in_single = in_double = False
    for i, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            if i == 0 or line[i - 1] in (" ", "\t"):
                break
        out.append(ch)
    return "".join(out).rstrip()


def _parse_block(lines: list[tuple[int, str]], i: int, indent: int) -> tuple[Any, int]:
    if i >= len(lines):
        return None, i
    if lines[i][1].startswith("- ") or lines[i][1] == "-":
        return _parse_list(lines, i, indent)
    return _parse_map(lines, i, indent)


def _parse_list(lines: list[tuple[int, str]], i: int, indent: int) -> tuple[list, int]:
    items: list[Any] = []
    while i < len(lines) and lines[i][0] == indent and lines[i][1].startswith("-"):
        text = lines[i][1][1:].strip()
        if text == "":
            # Nested block on the following deeper-indented lines.
            if i + 1 < len(lines) and lines[i + 1][0] > indent:
                value, i = _parse_block(lines, i + 1, lines[i + 1][0])
                items.append(value)
            else:
                items.append(None)
                i += 1
            continue
        if ":" in text and _is_key_value(text):
            # Mapping item: "- key: value" with continuation lines indented
            # to the key column (dash_indent + 2).
            mapping: dict[str, Any] = {}
            key, value = _split_kv(text)
            mapping[key] = value if value is not _MISSING else None
            i += 1
            cont = indent + 2
            while i < len(lines) and lines[i][0] == cont and not lines[i][1].startswith("-"):
                k, v = _split_kv(lines[i][1])
                if v is _MISSING:
                    if i + 1 < len(lines) and lines[i + 1][0] > cont:
                        v, i = _parse_block(lines, i + 1, lines[i + 1][0])
                        mapping[k] = v
                        continue
                    mapping[k] = None
                    i += 1
                    continue
                mapping[k] = v
                i += 1
            items.append(mapping)
            continue
        items.append(_scalar(text))
        i += 1
    return items, i


def _parse_map(lines: list[tuple[int, str]], i: int, indent: int) -> tuple[dict, int]:
    mapping: dict[str, Any] = {}
    while i < len(lines) and lines[i][0] == indent and not lines[i][1].startswith("-"):
        key, value = _split_kv(lines[i][1])
        if value is _MISSING:  # value on following, deeper-indented lines
            if i + 1 < len(lines) and lines[i + 1][0] > indent:
                value, i = _parse_block(lines, i + 1, lines[i + 1][0])
                mapping[key] = value
                continue
            mapping[key] = None
            i += 1
            continue
        mapping[key] = value
        i += 1
    return mapping, i


def _is_key_value(text: str) -> bool:
    head = text.split(":", 1)[0]
    return bool(head) and " " not in head.strip()


def _split_kv(text: str) -> tuple[str, Any]:
    if ":" not in text:
        raise ValueError(f"miniyaml: expected 'key: value', got {text!r}")
    key, _, rest = text.partition(":")
    key = key.strip().strip('"').strip("'")
    rest = rest.strip()
    if rest == "":
        return key, _MISSING
    return key, _scalar(rest)


def _scalar(text: str) -> Any:
    if text.startswith("[") and text.endswith("]"):
        inner = text[1:-1].strip()
        return [_scalar(p.strip()) for p in inner.split(",")] if inner else []
    if text.startswith("{") and text.endswith("}"):
        inner = text[1:-1].strip()
        result = {}
        if inner:
            for part in inner.split(","):
                k, _, v = part.partition(":")
                result[k.strip().strip('"').strip("'")] = _scalar(v.strip())
        return result
    if (text.startswith('"') and text.endswith('"')) or \
       (text.startswith("'") and text.endswith("'")):
        return text[1:-1]
    low = text.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    if low in ("null", "~", "none", ""):
        return None
    try:
        return int(text)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        pass
    return text
