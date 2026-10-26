r"""Wazuh expression engines: OS_Regex, OS_Match and PCRE2.

Semantics follow the Wazuh 4.11.2 sources (src/os_regex, src/shared/expression.c)
and were checked against real wazuh-logtest output:

* OS_Regex is case-insensitive.  Valid escapes are only
  ``\d \w \s \p \D \W \S \. \t \$ \| \< \( \) \\`` - anything else makes
  Wazuh refuse the decoder.  ``\s`` is a single space (no tab), ``\w`` includes
  ``@`` and ``-``, ``\p`` is ``!"#$%&'()*+,-.:;<=>?[]{|}``, ``\.`` is any char.
* ``+`` / ``*`` are quantifiers only right after an escape; elsewhere they are
  literal characters.  A run stops as soon as the next token matches (lazy),
  except at the end of the pattern where it takes the whole run.
* ``|`` splits the pattern into alternatives with their own ``^`` / ``$``.
  Alternatives are tried in order over the whole string (not leftmost-first).
* One level of ``( )`` only; ``|`` inside parentheses is an error.
* ``^`` anchors at the offset the decoder searches from (after_parent, ...).
* OS_Match (default for ``<program_name>``): ``!`` negates, ``|`` alternatives,
  ``^x`` prefix, ``x$`` suffix, ``^x$`` exact, otherwise substring;
  case-insensitive; no escapes.
* PCRE2 is case-sensitive (Wazuh compiles it with no flags).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

import regex as _pcre

_CLASSES = {
    "d": "[0-9]",
    "w": r"[A-Za-z0-9@_\-]",
    "s": "[ ]",
    "p": r"""[!"#$%&'()*+,\-.:;<=>?\[\]{|}]""",
    "D": "[^0-9]",
    "W": r"[^A-Za-z0-9@_\-]",
    "S": "[^ ]",
    ".": r"[\s\S]",
    "t": r"\t",
    "$": r"\$",
    "|": r"\|",
    "<": "<",
    "(": r"\(",
    ")": r"\)",
    "\\": r"\\",
}
_OS_FLAGS = re.IGNORECASE | re.ASCII

Match = Tuple[int, int, List[Tuple[int, int]], int]  # (start, one-past end, capture spans, branch)


class ExpressionError(ValueError):
    pass


@dataclass
class _Branch:
    pattern: re.Pattern
    anchored: bool
    literal: Optional[str]  # lower-case literal every match must contain (prefilter)


@dataclass
class Expression:
    """A compiled Wazuh expression. ``search`` mimics ``w_expression_match``."""

    raw: str
    kind: str  # os_regex | os_match | pcre2
    branches: List[_Branch] = field(default_factory=list)
    negate: bool = False
    pcre: Optional[_pcre.Pattern] = None

    def search(self, text: str, pos: int = 0, lower: Optional[str] = None) -> Optional[Match]:
        """Match ``text[pos:]``; returns (start, one-past end, group spans) in ``text`` offsets.

        ``lower`` is an optional pre-lowered copy of ``text`` used for the
        literal prefilter (purely an optimisation, never changes the result).
        """
        if self.kind == "pcre2":
            assert self.pcre is not None
            m = self.pcre.search(text[pos:] if pos else text)
            if m is None:
                return None
            spans = []
            for g in range(1, (m.lastindex or 0) + 1):
                s, e = m.span(g)
                if s < 0:
                    break
                spans.append((s + pos, e + pos))
            return m.start() + pos, m.end() + pos, spans, 0

        if self.kind == "os_match":
            hit = any(b.pattern.search(text, pos) for b in self.branches)
            # OS_Match does not move the end pointer (expression.c).
            return (pos, pos, [], 0) if hit != self.negate else None

        for number, branch in enumerate(self.branches):
            if branch.literal and lower is not None and branch.literal not in lower:
                continue
            m = branch.pattern.match(text, pos) if branch.anchored else branch.pattern.search(text, pos)
            if m is None:
                continue
            spans = []
            for g in range(1, (m.re.groups or 0) + 1):
                s, e = m.span(g)
                if s < 0:
                    break
                spans.append((s, e))
            return m.start(), m.end(), spans, number
        return None


def _tokenize(pattern: str) -> List[Tuple[str, str]]:
    """Split an OS_Regex into ('esc', c) / ('lit', c) / ('(', '') / (')', '') / ('|', '')."""
    tokens: List[Tuple[str, str]] = []
    depth = 0
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\":
            if i + 1 >= len(pattern):
                raise ExpressionError("pattern ends with a lone backslash")
            esc = pattern[i + 1]
            if esc not in _CLASSES:
                raise ExpressionError(
                    f"invalid OS_Regex escape '\\{esc}' (valid: \\d \\w \\s \\p \\D \\W \\S \\. \\t \\$ \\| \\< \\( \\) \\\\)"
                )
            tokens.append(("esc", esc))
            i += 2
            continue
        if ch == "(":
            depth += 1
            if depth > 1:
                raise ExpressionError("nested parentheses are not supported by OS_Regex")
            tokens.append(("(", ""))
        elif ch == ")":
            depth -= 1
            if depth < 0:
                raise ExpressionError("unbalanced ')'")
            tokens.append((")", ""))
        elif ch == "|":
            if depth:
                raise ExpressionError("'|' inside parentheses is not supported by OS_Regex")
            tokens.append(("|", ""))
        else:
            tokens.append(("lit", ch))
        i += 1
    if depth:
        raise ExpressionError("unclosed '('")
    return tokens


def _compile_branch(tokens: List[Tuple[str, str]]) -> _Branch:
    anchored = bool(tokens) and tokens[0] == ("lit", "^")
    if anchored:
        tokens = tokens[1:]
    end_set = bool(tokens) and tokens[-1] == ("lit", "$")
    if end_set:
        tokens = tokens[:-1]

    out: List[str] = []
    literal_runs: List[str] = []
    run = ""
    prev_escape = False
    for index, (kind, value) in enumerate(tokens):
        if kind == "lit" and value in "+*" and prev_escape:
            at_end = all(t[0] == ")" for t in tokens[index + 1:])
            out.append(value if at_end else value + "?")
            prev_escape = False
            continue
        if kind == "lit":
            out.append(re.escape(value))
            if value.isascii():
                run += value.lower()
            else:
                literal_runs.append(run)
                run = ""
        else:
            literal_runs.append(run)
            run = ""
            if kind == "esc":
                out.append(_CLASSES[value])
            else:
                out.append(kind)
        prev_escape = kind == "esc"
    literal_runs.append(run)
    if end_set:
        out.append(r"\Z")
    longest = max(literal_runs, key=len)
    return _Branch(
        pattern=re.compile("".join(out), _OS_FLAGS),
        anchored=anchored,
        literal=longest if len(longest) >= 2 else None,
    )


def compile_os_regex(pattern: str) -> Expression:
    tokens = _tokenize(pattern)
    branches: List[List[Tuple[str, str]]] = [[]]
    for token in tokens:
        if token[0] == "|":
            branches.append([])
        else:
            branches[-1].append(token)
    return Expression(raw=pattern, kind="os_regex", branches=[_compile_branch(b) for b in branches])


def compile_os_match(pattern: str) -> Expression:
    negate = pattern.startswith("!")
    body = pattern[1:] if negate else pattern
    branches = []
    for alt in body.split("|"):
        begin = alt.startswith("^")
        end = alt.endswith("$") and len(alt) > (1 if begin else 0)
        core = alt[1 if begin else 0: len(alt) - (1 if end else 0)]
        expr = ("^" if begin else "") + re.escape(core) + (r"\Z" if end else "")
        branches.append(_Branch(pattern=re.compile(expr, _OS_FLAGS), anchored=False, literal=None))
    return Expression(raw=pattern, kind="os_match", branches=branches, negate=negate)


def _invert_greed(pattern: str) -> str:
    """Rewrite quantifiers for PCRE2's U flag (Python's regex has no ungreedy mode): x* <-> x*?."""
    out, i, n = [], 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "\\":
            out.append(pattern[i:i + 2])
            i += 2
            continue
        if c == "[":  # character class: copy verbatim
            j = i + 1
            if j < n and pattern[j] == "^":
                j += 1
            if j < n and pattern[j] == "]":
                j += 1
            while j < n and pattern[j] != "]":
                j += 2 if pattern[j] == "\\" else 1
            out.append(pattern[i:j + 1])
            i = j + 1
            continue
        quant = None
        if c in "*+" or (c == "?" and i > 0 and pattern[i - 1] != "("):
            quant = c
        elif c == "{":
            m = re.match(r"\{\d*,?\d*\}", pattern[i:])
            if m and m.group(0) != "{}":
                quant = m.group(0)
        if quant is None:
            out.append(c)
            i += 1
            continue
        out.append(quant)
        i += len(quant)
        if i < n and pattern[i] == "?":
            i += 1  # lazy -> greedy
        elif i < n and pattern[i] == "+":
            out.append("+")  # possessive: unchanged
            i += 1
        else:
            out.append("?")  # greedy -> lazy
    return "".join(out)


def compile_pcre2(pattern: str) -> Expression:
    flags = re.match(r"\(\?([a-zA-Z]+)\)", pattern)
    if flags and "U" in flags.group(1):
        rest = flags.group(1).replace("U", "")
        pattern = (f"(?{rest})" if rest else "") + _invert_greed(pattern[flags.end():])
    try:
        compiled = _pcre.compile(pattern)
    except _pcre.error as exc:
        raise ExpressionError(f"invalid PCRE2 pattern: {exc}") from exc
    return Expression(raw=pattern, kind="pcre2", pcre=compiled)


def compile_expression(pattern: str, kind: str) -> Expression:
    """Compile ``pattern`` as Wazuh would for ``type`` = osregex | osmatch | pcre2."""
    kind = (kind or "osregex").lower().replace("_", "")
    if kind == "pcre2":
        return compile_pcre2(pattern)
    if kind == "osmatch":
        return compile_os_match(pattern)
    if kind == "osregex":
        return compile_os_regex(pattern)
    raise ExpressionError(f"unknown expression type '{kind}'")


def split_branches(pattern: str) -> List[str]:
    """Split on unescaped top-level '|' (OS_Regex alternatives)."""
    parts, cur, i = [], [], 0
    while i < len(pattern):
        if pattern[i] == "\\" and i + 1 < len(pattern):
            cur.append(pattern[i:i + 2])
            i += 2
            continue
        if pattern[i] == "|":
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(pattern[i])
        i += 1
    parts.append("".join(cur))
    return parts


_KEY_BEFORE_GROUP_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_.\-]*)=$")


def group_keys(pattern: str) -> List[List[Optional[str]]]:
    r"""For each alternative, the key written right before each capture group.

    ``\sSPT=(\d+) DPT=(\d+)`` -> [["SPT", "DPT"]]; groups after free text get None.
    """
    out = []
    for branch in split_branches(pattern or ""):
        keys: List[Optional[str]] = []
        i = 0
        while i < len(branch):
            if branch[i] == "\\":
                i += 2
                continue
            if branch[i] == "(":
                prefix = re.sub(r"(\\p[+*]?|[\"'])$", "", branch[:i])
                # Other escapes (\s, \t, ...) become a separator so "\srule_id=" yields "rule_id".
                m = _KEY_BEFORE_GROUP_RE.search(re.sub(r"\\[\s\S]", "\0", prefix))
                keys.append(m.group(1) if m else None)
            i += 1
        out.append(keys)
    return out


def target_key_of(pattern: str) -> Optional[str]:
    r"""The key a child regex is written for: ``\skey="(\.+)"`` -> ``key``."""
    m = re.match(r"^\^?(?:\\s[+*]?)?([A-Za-z_][A-Za-z0-9_.\-]*)=", (pattern or "").strip())
    return m.group(1) if m else None


def is_unanchored(pattern: str) -> bool:
    """True when the regex starts with a bare key (can match inside a longer key)."""
    return bool(re.match(r"^[A-Za-z_][A-Za-z0-9_.\-]*=", (pattern or "").strip()))


def escape_literal(text: str) -> str:
    """Escape text so OS_Regex matches it literally (+/* become \\p to stay literal)."""
    out = []
    for ch in text:
        if ch in "()\\|$<":
            out.append("\\" + ch)
        elif ch == "\t":
            out.append(r"\t")
        elif ch in "+*":
            out.append(r"\p")
        else:
            out.append(ch)
    return "".join(out)
