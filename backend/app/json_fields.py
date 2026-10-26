"""Wazuh JSON_Decoder flattening with character positions.

Flattening follows src/analysisd/decoders/plugins/json_decoder.c: nested keys
are joined with '.', integers print as ``%i`` (when they fit an int) else
``%f``, booleans as true/false, null is dropped (``json_null_field`` =
string keeps "null"), arrays are kept as JSON (``json_array_structure`` = csv
joins scalars with ',').
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from json.decoder import scanstring
from typing import List, Optional, Tuple

_NUMBER_RE = re.compile(r"-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][-+]?\d+)?")
_WS = " \t\n\r"


@dataclass
class JsonLeaf:
    path: str
    value: Optional[str]  # None = dropped by Wazuh (null)
    start: int  # value span in the source text
    end: int
    key_start: int
    key_end: int


def _num_text(raw: str) -> str:
    value = float(raw)
    if value.is_integer() and -2147483648 <= value <= 2147483647:
        return str(int(value))
    return "%f" % value


def _skip(s: str, i: int) -> int:
    while i < len(s) and s[i] in _WS:
        i += 1
    return i


def _scalar(value: object, null_mode: str) -> Optional[str]:
    if value is None:
        return "null" if null_mode == "string" else None
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        return _num_text(repr(value))
    return str(value)


def _parse(s: str, i: int, path: str, key_span: Tuple[int, int], leaves: List[JsonLeaf],
           null_mode: str, array_mode: str) -> Tuple[object, int]:
    i = _skip(s, i)
    if i >= len(s):
        raise ValueError("unexpected end of JSON")
    ch = s[i]
    if ch == "{":
        obj = {}
        i = _skip(s, i + 1)
        if i < len(s) and s[i] == "}":
            return obj, i + 1
        while True:
            i = _skip(s, i)
            if i >= len(s) or s[i] != '"':
                raise ValueError("expected a key")
            ks = i
            key, i = scanstring(s, i + 1)
            ke = i
            i = _skip(s, i)
            if i >= len(s) or s[i] != ":":
                raise ValueError("expected ':'")
            child = f"{path}.{key}" if path else key
            obj[key], i = _parse(s, i + 1, child, (ks, ke), leaves, null_mode, array_mode)
            i = _skip(s, i)
            if i < len(s) and s[i] == ",":
                i += 1
                continue
            if i < len(s) and s[i] == "}":
                return obj, i + 1
            raise ValueError("expected ',' or '}'")
    if ch == "[":
        start = i
        items = []
        i = _skip(s, i + 1)
        if i < len(s) and s[i] == "]":
            i += 1
        else:
            while True:
                item, i = _parse(s, i, "", (0, 0), [], null_mode, array_mode)
                items.append(item)
                i = _skip(s, i)
                if i < len(s) and s[i] == ",":
                    i += 1
                    continue
                if i < len(s) and s[i] == "]":
                    i += 1
                    break
                raise ValueError("expected ',' or ']'")
        if path:
            if array_mode == "csv":
                text = ",".join(v for v in (_scalar(x, "string") for x in items if not isinstance(x, (dict, list))) if v)
            else:
                text = json.dumps(items, separators=(",", ":"))
            leaves.append(JsonLeaf(path, text or None, start, i, *key_span))
        return items, i
    if ch == '"':
        value, end = scanstring(s, i + 1)
        if path:
            leaves.append(JsonLeaf(path, value, i + 1, end - 1, *key_span))
        return value, end
    for literal, value in (("true", True), ("false", False), ("null", None)):
        if s.startswith(literal, i):
            if path:
                leaves.append(JsonLeaf(path, _scalar(value, null_mode), i, i + len(literal), *key_span))
            return value, i + len(literal)
    m = _NUMBER_RE.match(s, i)
    if not m:
        raise ValueError(f"unexpected character {ch!r}")
    if path:
        leaves.append(JsonLeaf(path, _num_text(m.group(0)), i, m.end(), *key_span))
    raw = m.group(0)
    return (float(raw) if any(c in raw for c in ".eE") else int(raw)), m.end()


def parse_json(s: str, start: int = 0, null_mode: str = "discard",
               array_mode: str = "array") -> Optional[Tuple[List[JsonLeaf], int, int]]:
    """(leaves, value start, value end) of the JSON value at ``s[start:]`` (trailing text ignored,
    like cJSON_ParseWithOpts), or None when it is malformed."""
    leaves: List[JsonLeaf] = []
    try:
        begin = _skip(s, start)
        _, end = _parse(s, start, "", (0, 0), leaves, null_mode, array_mode)
    except (ValueError, IndexError):
        return None
    return leaves, begin, end


def flatten_json(s: str, start: int = 0, null_mode: str = "discard",
                 array_mode: str = "array") -> Optional[List[JsonLeaf]]:
    parsed = parse_json(s, start, null_mode, array_mode)
    return parsed[0] if parsed else None
