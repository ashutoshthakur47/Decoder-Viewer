"""Decode one log line exactly like wazuh-analysisd, then explain what was missed.

Decoding is a port of ``DecodeEvent`` (src/analysisd/decoders/decoder.c,
Wazuh 4.11.2): program_name / no-program_name root lists, first matching root
wins, children selected by prematch (first match) or the first regex-only
child, sibling chains (``get_next``), regex offsets, and the JSON_Decoder
plugin.  Positions are kept so every captured value can be shown in place.

On top of that the engine finds what no decoder extracted:

* ``missing``   key=value pairs (also CEF/LEEF headers) nobody targets
* ``broken``    a decoder targets the key but did not capture it on this line
                (with the reason: not reached, regex mismatch, matched elsewhere)
* ``json``      JSON keys when no JSON decoder ran
* ``value``     IPs, ports, users@, paths, hashes... left in free text
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .decoder_tree import Decoder, DecoderTree
from .json_fields import JsonLeaf, flatten_json, parse_json
from .os_regex import ExpressionError, compile_expression, escape_literal
from .predecoder import predecode
from .schemas import (
    AnalyzedLine,
    DecodedField,
    DecoderRef,
    Issue,
    LineCounts,
    LogToken,
    Suggestion,
    TokenState,
    TraceStep,
)

# --------------------------------------------------------------------------- KV scanning
_KEY_RE = re.compile(r"(?<![^\s,;|{(\[])([A-Za-z_][A-Za-z0-9_.\-]*)=")
# "Key: value" pairs separated by two spaces or a tab (Windows / Sysmon text: "ProcessId: 42  Image: C:\x.exe").
_COLON_KEY_RE = re.compile(r"(?:^|(?<=\s\s)|(?<=\t))([A-Za-z][\w.\-/]*(?: [A-Za-z][\w.\-/]*){0,3}):(?=[ \t])")
_COLON_VALUE_END_RE = re.compile(r"\s\s|\t")
_CEF_RE = re.compile(r"CEF:\d+\|")
_LEEF_RE = re.compile(r"LEEF:\d+(?:\.\d+)?\|")
_CEF_HEADER = ["cef_version", "device_vendor", "device_product", "device_version", "signature_id", "name", "severity"]
_LEEF_HEADER = ["leef_version", "vendor", "product", "version", "event_id"]

_VALUE_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("url", re.compile(r"\b(?:https?|ftp|ldap)://[^\s\"'<>]+")),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("path", re.compile(r"(?<![\w])[A-Za-z]:\\[^\s\"'<>|]+|(?<![\w/.~\-])/(?:[\w.\-@]+/)+[\w.\-@]*")),
    ("mac", re.compile(r"\b[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}\b")),
    ("ip", re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\.?\d)")),
    ("ipv6", re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])")),
    ("hash", re.compile(r"\b(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})\b")),
    ("quoted", re.compile(r"\"[^\"\n]{1,300}\"|'[^'\n]{1,300}'")),
    ("number", re.compile(r"(?<![\w.:/\-+])\d+(?![\w.:/\-])")),
]
_CONTEXT_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_\-]*)[\s:=\[(\"']{0,4}$")

_PRIORITY = {
    TokenState.TEXT: 0,
    TokenState.MATCHED: 1,
    TokenState.MISSING: 2,
    TokenState.BROKEN: 2,
    TokenState.TEST: 2,  # below CAPTURED: what the real tree decodes wins
    TokenState.CAPTURED: 3,
}


@dataclass
class KV:
    key: str
    start: int  # key start
    vstart: int  # value start (inside quotes)
    vend: int
    end: int  # end of the whole pair (after the closing quote)
    quoted: bool
    value: str
    header: bool = False  # CEF/LEEF header field (no "key=" in the text)
    sep: str = "="  # ":" for "Key: value" text (Windows / Sysmon)


def _scan_quoted(text: str, i: int, end: int) -> int:
    quote = text[i]
    j = i + 1
    while j < end:
        if text[j] == "\\":
            j += 2
            continue
        if text[j] == quote:
            return j
        j += 1
    return end


def scan_kv(text: str, start: int, end: int, program_name: Optional[str] = None) -> List[KV]:
    """key=value pairs in ``text[start:end]``; CEF / LEEF aware.

    ``Oct 23 10:00:00 host CEF:0|...`` is pre-decoded with program_name 'CEF' and log '0|...',
    so the header is also recognised from the program name.
    """
    pairs: List[KV] = []
    segment = text[start:end]
    mode = "plain"
    pos = None
    cef = _CEF_RE.search(segment)
    leef = None if cef else _LEEF_RE.search(segment)
    if cef or leef:
        mode = "cef" if cef else "leef"
        head = cef or leef
        pos = start + head.start() + head.group(0).index(":") + 1
    elif (program_name or "").upper() in ("CEF", "LEEF") and re.match(r"\d+(?:\.\d+)?\|", segment):
        mode = program_name.lower()
        pos = start
    if pos is not None:
        names = _CEF_HEADER if mode == "cef" else _LEEF_HEADER
        for index, name in enumerate(names):
            j = pos
            while j < end and text[j] != "|":
                j += 2 if text[j] == "\\" else 1
            j = min(j, end)
            if index < len(names) - 1 and j >= end:
                break
            pairs.append(KV(name, pos, pos, j, j, False, text[pos:j], header=True))
            pos = j + 1
            if pos >= end:
                break
        start = min(pos, end)

    colon = [] if pos is not None else _scan_colon(text, start, end)
    pos = start
    while pos < end:
        m = _KEY_RE.search(text, pos, end)
        if m is None:
            break
        vs = m.end()
        if vs < end and text[vs] in "\"'":
            close = _scan_quoted(text, vs, end)
            pair = KV(m.group(1), m.start(), vs + 1, close, min(close + 1, end), True, text[vs + 1:close])
        else:
            j = vs
            if mode == "leef":
                while j < end and text[j] != "\t":
                    j += 1
            elif mode == "cef":
                nxt = _KEY_RE.search(text, vs, end)
                while nxt is not None and not text[nxt.start() - 1].isspace():
                    nxt = _KEY_RE.search(text, nxt.end(), end)
                j = nxt.start() if nxt is not None else end
                while j > vs and text[j - 1].isspace():
                    j -= 1
            else:
                while j < end and not text[j].isspace():
                    j += 1
                while j > vs and text[j - 1] in ",;":
                    j -= 1
            pair = KV(m.group(1), m.start(), vs, j, j, False, text[vs:j])
        pairs.append(pair)
        pos = max(pair.end, m.end())
    if colon:  # a key=value inside a "Key: value" value ("Hashes: SHA1=...") belongs to that value
        pairs = [p for p in pairs if not any(c.vstart <= p.start < c.vend for c in colon)]
        pairs = sorted(pairs + colon, key=lambda p: p.start)
    return pairs


def _scan_colon(text: str, start: int, end: int) -> List[KV]:
    """``Key: value`` pairs; a value ends at two spaces or a tab. Needs two pairs on the line, so a lone
    "Error: ..." in free text is not taken for a field; '-' (Windows for 'none') counts as empty."""
    pairs: List[KV] = []
    for m in _COLON_KEY_RE.finditer(text, start, end):
        vs = m.end()
        while vs < end and text[vs] in " \t":
            vs += 1
        if _COLON_KEY_RE.match(text, vs, end):
            continue  # "Subject:  Security ID: ..." - no value of its own
        stop = _COLON_VALUE_END_RE.search(text, vs, end)
        ve = stop.start() if stop else end
        while ve > vs and text[ve - 1].isspace():
            ve -= 1
        if pairs and m.start() < pairs[-1].end:
            continue  # inside the previous value
        pairs.append(KV(m.group(1), m.start(), vs, ve, ve, False, text[vs:ve], sep=":"))
    # dropped: empty / '-' values, labels ("Process Information:  Process ID:"), and at the line start a value
    # holding more "x: " separators - that is a positional header (WinEvtLog "Channel: LEVEL(1): ..."), not a pair
    pairs = [p for p in pairs if p.value and p.value != "-" and not p.value.endswith(":")
             and not (p.start == start and ": " in p.value)]
    return pairs if len(pairs) >= 2 else []


_FIELD_SEP_RE = re.compile(r":\s")
_NEXT_JSON_RE = re.compile(r"\s*(?=\{\s*\")")


def _positional_fields(text: str, blocked: List[Tuple[int, int]]) -> List[Tuple[str, int, int]]:
    """Fields of a ``a: b: c: d: message`` header at the start of the message (WinEvtLog, some appliances):
    four or more short segments (up to four words, no sentence) each followed by ': '. The message is not."""
    run: List[Tuple[int, int]] = []
    pos = 0
    for m in _FIELD_SEP_RE.finditer(text):
        s, e = pos, m.start()
        while s < e and text[s].isspace():
            s += 1
        seg = text[s:e]
        if not (0 < len(seg) <= 64 and len(seg.split()) <= 4 and ":" not in seg and ". " not in seg
                and "  " not in seg and not any(bs < e and be > s for bs, be in blocked)):
            break
        run.append((s, e))
        pos = m.end()
    return [("field", s, e) for s, e in run] if len(run) >= 4 else []


def _gap(log: str, kv: KV) -> str:
    """Whitespace between "Key:" and its value (colon pairs)."""
    return log[kv.start + len(kv.key) + 1:kv.vstart]


def value_shape(kv: KV) -> str:
    if kv.quoted:
        return "quoted"
    if kv.value.isdigit():
        return "integer"
    return "text" if " " in kv.value else "token"


# --------------------------------------------------------------------------- XML suggestions
def decoder_xml(name: str, parent: Optional[str], regex: str, order: List[str], regex_type: str = "osregex",
                comment: Optional[str] = None) -> str:
    # No entity escaping: Wazuh's XML reader keeps '&lt;' literally; OS_Regex writes '<' as '\<'.
    lines = []
    if comment:
        lines.append(f"<!-- {comment} -->")
    lines.append(f'<decoder name="{name}">')
    if parent:
        lines.append(f"  <parent>{parent}</parent>")
    type_attr = ' type="pcre2"' if regex_type == "pcre2" else ""
    lines.append(f"  <regex{type_attr}>{regex}</regex>")
    lines.append(f"  <order>{', '.join(order)}</order>")
    lines.append("</decoder>")
    return "\n".join(lines)


def kv_regex(key: str, shapes: set, prefixes: set, mode: str = "plain", gap: str = " ") -> Tuple[str, str]:
    """(regex, type) that captures ``key``'s value for the observed shapes / preceding chars.

    mode: plain (OS_Regex), cef / leef (PCRE2: values with spaces / tab separated),
    case (PCRE2, case-sensitive: for keys that differ only by case, e.g. auditd SYSCALL= vs syscall=),
    colon ("Key: value" text; ``gap`` is the whitespace after the colon, a value ends at two spaces).
    """
    if mode == "colon":
        head = escape_literal(key) + ":" + "".join(r"\t" if c == "\t" else r"\s" for c in gap)
        if "text" in shapes:  # value with spaces: up to the two-space separator, or the end of the line
            cores = [head + r"(\.*)\s\s", head + r"(\.*)$"]
        else:
            cores = [head + (r"(\d+)" if shapes == {"integer"} else r"(\S+)")]
        anchors = sorted({"^" if p == "" else (r"\t" if p == "\t" else r"\s") for p in prefixes})
        return "|".join(a + c for c in cores for a in anchors), "osregex"
    k = re.escape(key)
    if mode == "cef":
        return rf"(?:^|[\s|]){k}=((?:[^\\\s]|\\.|\s(?![A-Za-z_][\w.\-]*=))*)", "pcre2"
    if mode == "leef":
        return rf"(?:^|[\t|]){k}=([^\t]*)", "pcre2"
    if mode == "case":
        quoted, bare = "quoted" in shapes, bool(shapes - {"quoted"})
        core = r"(\d+)" if shapes == {"integer"} else r"(\S+)"
        if quoted:
            core = r'(?|"([^"]*)"|(\S+))' if bare else r'"([^"]*)"'
        return rf"(?:^|\s){k}={core}", "pcre2"
    lit = escape_literal(key)
    cores = []
    if "quoted" in shapes:
        cores.append(rf'{lit}="(\.*)"')
    if shapes - {"quoted"}:
        cores.append(rf"{lit}=(\d+)" if shapes - {"quoted"} == {"integer"} else rf"{lit}=(\S+)")
    anchors = []
    for prefix in sorted(prefixes) or [" "]:
        if prefix == "":
            anchors.append("^")
        elif prefix == " ":
            anchors.append(r"\s")
        elif prefix == "\t":
            anchors.append(r"\t")
        else:
            anchors.append(escape_literal(prefix))
    return "|".join(a + c for c in cores for a in anchors), "osregex"


def captures_exactly(regex: str, rtype: str, log: str, s: int, e: int) -> bool:
    """True when the regex, searched over the whole log like Wazuh does, captures log[s:e] first."""
    try:
        expr = compile_expression(regex, rtype)
    except ExpressionError:
        return False
    m = expr.search(log, 0, log.lower())
    return bool(m and m[2] and m[2][0][0] == s and e <= m[2][0][1] <= e + 1)


def verified_kv_regex(occurrences: List[Tuple[str, "KV"]], mode: str) -> Optional[Tuple[str, str]]:
    """One regex for a key, covering every (log, pair) sample; the one that captures the most samples
    exactly (all, ideally), else None."""
    log0, kv0 = occurrences[0]
    key = kv0.key
    shapes = {value_shape(kv) for _, kv in occurrences}
    prefixes = {log[kv.start - 1] if kv.start > 0 else "" for log, kv in occurrences}
    modes = ["colon"] if kv0.sep == ":" else [mode] if mode != "plain" else ["plain", "case"]
    best, best_hits = None, 0
    for m in modes:
        regex, rtype = kv_regex(key, shapes, prefixes, m, _gap(log0, kv0))
        hits = sum(captures_exactly(regex, rtype, log, kv.vstart, kv.vend) for log, kv in occurrences)
        if hits == len(occurrences):
            return regex, rtype
        if hits > best_hits:
            best, best_hits = (regex, rtype), hits
    return best


_CEF_FIELD = r"((?:[^|\\]|\\.)*)"  # a header field: anything but '|', with \| escapes
_CEF_HEADER_REGEX = r"(?:CEF:)?(\d+)\|" + (_CEF_FIELD + r"\|") * 6
_LEEF_HEADER_REGEX = r"(?:LEEF:)?([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|"
_WORDS_BEFORE_RE = [re.compile(r"((?:[A-Za-z_][\w\-]*[ \t:=#\[(<\"']{1,3}){%d})\Z" % n) for n in (1, 2, 3)]
_SRC_WORDS = {"from", "src", "source", "client", "remote", "sender", "origin"}
_DST_WORDS = {"to", "dst", "destination", "dest", "server", "target"}
_CAPTURE = {"ip": r"(\d+.\d+.\d+.\d+)", "number": r"(\d+)"}  # OS_Regex: unescaped '.' is a literal dot


def value_regex(log: str, s: int, e: int, kind: str) -> Optional[Tuple[str, str]]:
    r"""(OS_Regex, context words) capturing ``log[s:e]`` by the words in front of it:
    'from 1.2.3.4' -> (\sfrom (\d+.\d+.\d+.\d+), 'from').

    One word of context first, up to three when the shorter one also appears earlier in the line;
    the result is verified to capture exactly this value, else None.
    """
    if kind == "quoted":
        capture = rf"{escape_literal(log[s])}(\.*){escape_literal(log[e - 1])}"
        span = (s + 1, e - 1)
    else:
        capture = _CAPTURE.get(kind, r"(\S+)")
        if kind not in _CAPTURE and e < len(log) and not log[e].isspace():
            capture += escape_literal(log[e])  # \S+ stops at the next token: keep a trailing ',' or ']' out
        span = (s, e)
    candidates = []
    for pattern in _WORDS_BEFORE_RE:
        m = pattern.search(log, max(0, s - 80), s)
        if m:
            start = m.start(1)
            lead = "^" if start == 0 else (r"\s" if log[start - 1] == " " else "")
            candidates.append((lead + escape_literal(log[start:s]) + capture, log[start:s]))
    if s == 0:
        candidates.insert(0, ("^" + capture, ""))
    for regex, context in candidates:
        if captures_exactly(regex, "osregex", log, *span):
            return regex, context
    return None


def kv_mode(pairs: List["KV"]) -> str:
    header = [kv for kv in pairs if kv.header]
    return "plain" if not header else ("cef" if header[0].key == "cef_version" else "leef")


def value_field(kind: str, context: Optional[str]) -> str:
    """Field name from the context words: 'from' + ip -> srcip, 'max rate is' -> max_rate_is."""
    words = re.findall(r"[a-z0-9_]+", (context or "").lower())
    if kind in ("ip", "ipv6") and words and words[-1] in _SRC_WORDS:
        return "srcip"  # Wazuh static field: geoip, same_source_ip, ...
    if kind in ("ip", "ipv6") and words and words[-1] in _DST_WORDS:
        return "dstip"
    return "_".join(words) or kind


def _kv_prematch(samples) -> str:
    """Prematch for a key=value format: the first key, its value when every sample has the same word
    (SonicWall 'id=firewall'; never a date or number, which change), and the next key when every sample
    has it right after: 'id=firewall sn=', 'date=\\S+ time='."""
    firsts = [[kv for kv in s[2] if not kv.header and kv.value][:2] for s in samples]
    log0, (k0, *rest) = samples[0][0], firsts[0]
    out = ("^" if k0.start == 0 else "") + escape_literal(k0.key) + k0.sep
    if k0.sep != "=" or k0.quoted:
        return out
    word = re.fullmatch(r"[A-Za-z][\w.\-]{0,29}", k0.value) and all(
        f[0].key == k0.key and f[0].value == k0.value and not f[0].quoted for f in firsts)
    k1 = rest[0] if rest else None
    next_key = k1 is not None and all(len(f) > 1 and f[0].key == k0.key and not f[0].quoted and f[1].key == k1.key
                                      and s[0][f[0].vend:f[1].start] == " " for f, s in zip(firsts, samples))
    if word:
        out += escape_literal(k0.value)
    elif next_key:
        out += r"\S+"
    if next_key:
        out += " " + escape_literal(k1.key) + "="
    return out


def _text_prematch(log: str, values) -> Optional[str]:
    """Prematch for free text: up to the first three words before the first value (or its shape)."""
    first = values[0][1] if values else len(log)
    words = re.match(r"\s*((?:\S+ ){0,2}\S+)", log[:first])
    if words and words.group(1).strip():
        return "^" + escape_literal(words.group(1))
    if values and values[0][1] == 0 and values[0][0] in _CAPTURE:
        return "^" + _CAPTURE[values[0][0]][1:-1]
    return None


# --------------------------------------------------------------------------- engine
@dataclass
class _Capture:
    name: str
    start: int
    end: int
    decoder: Optional[Decoder]
    source: str
    value: Optional[str] = None  # set when the stored value differs from the text (JSON)


@dataclass
class _Outcome:
    root: Optional[Decoder] = None
    decoder: Optional[Decoder] = None  # lf->decoder_info
    chain_name: Optional[str] = None  # name of the sibling chain that ran (for new siblings)
    captures: List[_Capture] = field(default_factory=list)
    matched: List[Tuple[int, int]] = field(default_factory=list)
    trace: List[TraceStep] = field(default_factory=list)
    evaluated: Dict[int, Tuple[bool, int]] = field(default_factory=dict)  # uid -> (matched, search start)
    stop: Optional[str] = None
    json_span: Optional[Tuple[int, int]] = None


def _step(trace: List[TraceStep], dec: Decoder, step: str, result: str, detail: str = "") -> None:
    trace.append(TraceStep(decoder=dec.name, uid=dec.uid, file=dec.file, line=dec.line,
                           step=step, result=result, detail=detail))


class WazuhSpanEngine:
    def __init__(self, tree: DecoderTree):
        self.tree = tree
        self.by_key: Dict[str, List[Decoder]] = {}
        for dec in tree.valid:
            for key in {k.lower() for branch in dec.group_keys for k in branch if k}:
                self.by_key.setdefault(key, []).append(dec)
        self.has_json_decoder = any(d.plugin == "JSON_Decoder" for d in tree.valid)
        self.standalone = [d for d in tree.decoders if d.standalone]

    # ------------------------------------------------------------------ decoding
    def decode(self, log: str, program_name: Optional[str]) -> _Outcome:
        out = _Outcome()
        lower = log.lower()
        roots = self.tree.roots_pn if program_name is not None else self.tree.roots_nopn
        failed: List[Decoder] = []  # roots whose prematch did not match (no program_name lines)
        for root in roots:
            pmatch: Optional[int] = None
            if program_name is not None:
                if root.program_name is None or root.program_name.search(program_name) is None:
                    continue
                _step(out.trace, root, "program_name", "match", f"'{program_name}' matches {root.program_name_raw}")
                pmatch = 0
            if root.prematch_raw is not None:
                m = root.prematch.search(log, 0, lower) if root.prematch else None
                if m is None:
                    if program_name is not None:
                        _step(out.trace, root, "prematch", "no match", root.prematch_raw or "")
                    else:
                        failed.append(root)
                    continue
                pmatch = m[1]
                out.matched.append((m[0], m[1]))
                _step(out.trace, root, "prematch", "match", root.prematch_raw or "")
            out.root = out.decoder = root
            self._run_children(root, log, lower, pmatch or 0, out)
            return out
        out.stop = (
            f"no root decoder with <program_name> matches '{program_name}' (when a program name is "
            "pre-decoded, Wazuh only tries decoders that have <program_name>)"
            if program_name is not None else "no root decoder <prematch> matches this log"
        )
        # Only when nothing matched: say which prematches were tried (a stock ruleset has hundreds of roots).
        for root in failed[:10]:
            _step(out.trace, root, "prematch", "no match", root.prematch_raw or "")
        if len(failed) > 10:
            out.stop += f"; {len(failed) - 10} more root prematches did not match"
        rejected = [d for d in self.tree.decoders if d.errors]
        if rejected:
            out.stop += (f"; note: {len(rejected)} loaded decoder(s) were rejected and are not used, "
                         f"e.g. '{rejected[0].name}': {rejected[0].errors[0]}")
        return out

    def _run_children(self, root: Decoder, log: str, lower: str, pmatch: int, out: _Outcome) -> None:
        log_after_parent: Optional[int] = None
        log_after_prematch: Optional[int] = pmatch
        cmatch: Optional[int] = None
        if not root.children:
            nodes, index = [root], 0
        else:
            nodes, index = root.children, 0
            chosen: Optional[Decoder] = None
            while index < len(nodes):
                child = nodes[index]
                if child.prematch_raw is not None:
                    base = pmatch if child.prematch_offset == "after_parent" else 0
                    m = child.prematch.search(log, base, lower) if child.prematch else None
                    if m is not None:
                        cmatch = m[1]
                        out.decoder = child
                        log_after_parent, log_after_prematch = pmatch, cmatch
                        out.matched.append((m[0], m[1]))
                        _step(out.trace, child, "child prematch", "match", child.prematch_raw or "")
                        chosen = child
                        break
                    _step(out.trace, child, "child prematch", "no match", child.prematch_raw or "")
                else:
                    cmatch = pmatch
                    chosen = child
                    break
                if child.get_next:
                    while index < len(nodes) and nodes[index].get_next:
                        index += 1
                    if index >= len(nodes):
                        break
                index += 1
            if chosen is None:
                out.stop = f"no child of '{root.name}' was selected (every child <prematch> failed)"
                return
        out.chain_name = nodes[index].name

        regex_prev: Optional[int] = None
        while index < len(nodes):
            node = nodes[index]
            if node.plugin:
                start = {None: 0, "after_parent": log_after_parent, "after_prematch": log_after_prematch}.get(
                    node.plugin_offset, None)
                if node.plugin != "JSON_Decoder":
                    _step(out.trace, node, "plugin", "info", f"{node.plugin} is not emulated by this tool")
                elif start is None:
                    _step(out.trace, node, "plugin", "no match", "JSON_Decoder got no input for this offset")
                else:
                    parsed = parse_json(log, start, node.json_null_field, node.json_array_structure)
                    if parsed is None:
                        _step(out.trace, node, "plugin", "no match", "JSON_Decoder: malformed JSON")
                    else:
                        leaves, lo, hi = parsed
                        _step(out.trace, node, "plugin", "match", f"JSON_Decoder extracted {len(leaves)} keys")
                        out.json_span = (lo, hi)
                        for leaf in leaves:
                            if leaf.value is not None:
                                out.captures.append(_Capture(leaf.path, leaf.start, leaf.end, node, "json", leaf.value))
            elif node.regex_raw is not None:
                if not node.regex_offset:
                    llog: Optional[int] = 0
                elif node.regex_offset == "after_parent":
                    llog = pmatch
                elif node.regex_offset == "after_prematch":
                    llog = cmatch
                else:
                    llog = regex_prev if regex_prev is not None else cmatch
                m = node.regex.search(log, llog, lower) if (llog is not None and node.regex) else None
                out.evaluated[node.uid] = (m is not None, llog or 0)
                if m is None:
                    _step(out.trace, node, "regex", "no match", node.regex_raw or "")
                    if node.get_next:
                        index += 1
                        continue
                    if index + 1 < len(nodes):
                        out.stop = (f"decoder '{node.name}' ({node.file}:{node.line}) did not match and is the last "
                                    "of its sibling chain, so the decoders after it were not evaluated")
                    return
                regex_prev = m[1]
                out.matched.append((m[0], m[1]))
                names = node.fields
                got = []
                for i, (s, e) in enumerate(m[2]):
                    if i < len(names):
                        out.captures.append(_Capture(names[i], s, e, node, "regex"))
                        got.append(f"{names[i]}={log[s:e]!r}")
                _step(out.trace, node, "regex", "match", (node.regex_raw or "") + ("  ->  " + ", ".join(got) if got else ""))
            else:
                return
            if node.get_next:
                index += 1
            else:
                return

    def _run_standalone(self, log: str, program_name: Optional[str], out: _Outcome) -> None:
        """Run each decoder Wazuh rejects only for its place in the tree on its own, from the start of the
        log, so a single decoder (name + regex, no parent) can be tested. Adds 'test' captures only: what the
        real tree decoded is unchanged."""
        lower = log.lower()
        for dec in self.standalone:
            if dec.program_name is not None and (program_name is None or dec.program_name.search(program_name) is None):
                continue
            pm = dec.prematch.search(log, 0, lower) if dec.prematch else None
            if dec.prematch and pm is None:
                _step(out.trace, dec, "tested alone", "no match", f"prematch {dec.prematch_raw}")
                continue
            start = pm[1] if pm and dec.regex_offset == "after_prematch" else 0
            m = dec.regex.search(log, start, lower) if dec.regex else None
            if dec.regex and m is None:
                _step(out.trace, dec, "tested alone", "no match", f"regex {dec.regex_raw}")
                continue
            got = []
            for span in ([pm[:2]] if pm else []) + ([m[:2]] if m else []):
                out.matched.append(tuple(span))
            if m:
                for i, (s, e) in enumerate(m[2]):
                    # no <order> yet: name the value after the word in front of it ("ProcessId: 42"), else by position
                    word = re.search(r"([A-Za-z_][\w.\-]*)[\s:=\"']*$", log[max(0, s - 40):s])
                    name = dec.fields[i] if i < len(dec.fields) else (word.group(1) if word else f"field{i + 1}")
                    out.captures.append(_Capture(name, s, e, dec, "test"))
                    got.append(f"{name}={log[s:e]!r}")
            _step(out.trace, dec, "tested alone", "match",
                  f"not in the decoder tree ({dec.errors[0]}), so it ran alone on the log"
                  + ("  ->  " + ", ".join(got) if got else ""))

    # ------------------------------------------------------------------ analysis
    def analyze(self, raw_line: str, line_number: int = 0, detail: bool = True) -> AnalyzedLine:
        pre = predecode(raw_line)
        raw = pre.raw_line
        event = raw[pre.event_offset:]
        stripped = event.lstrip()
        # Agent eventchannel events (archive location "EventChannel") skip the XML decoders; the same
        # JSON sent as plain text goes through them (stock "json" decoder), like wazuh-logtest.
        if pre.location == "EventChannel" and stripped.startswith("{"):
            builtin = self._windows(raw, pre.event_offset)
            if builtin is not None:
                return self._finish(line_number, pre, raw, pre.event_offset, None, builtin, detail)

        log_start = pre.log_offset
        log = raw[log_start:pre.log_end]
        program_name = pre.text(pre.program_name)
        outcome = self.decode(log, program_name)
        self._run_standalone(log, program_name, outcome)
        return self._finish(line_number, pre, raw, log_start, program_name, outcome, detail)

    def _windows(self, raw: str, offset: int) -> Optional[_Outcome]:
        parsed = parse_json(raw, offset)
        if not parsed or not any(l.path.startswith("win.") for l in parsed[0]):
            return None
        out = _Outcome()
        out.trace.append(TraceStep(decoder="windows_eventchannel", step="builtin", result="match",
                                   detail="Windows eventchannel events are decoded by Wazuh's internal "
                                          "windows_eventchannel decoder (JSON), not by XML decoders"))
        for leaf in parsed[0]:
            if leaf.value is not None:
                out.captures.append(_Capture(leaf.path, leaf.start, leaf.end, None, "windows", leaf.value))
        out.json_span = (parsed[1], parsed[2])
        return out

    def _finish(self, line_number: int, pre, raw: str, log_start: int, program_name: Optional[str],
                out: _Outcome, detail: bool) -> AnalyzedLine:
        builtin = out.trace[:1] and out.trace[0].step == "builtin"
        n = len(raw)
        log = raw[log_start:pre.log_end]
        shift = 0 if builtin else log_start  # builtin spans are already raw offsets

        # ---- decoded fields ------------------------------------------------
        fields: List[DecodedField] = []
        predecoded: Dict[str, str] = {}
        for name, span in (("timestamp", pre.timestamp), ("hostname", pre.hostname), ("program_name", pre.program_name)):
            if span:
                predecoded[name] = raw[span[0]:span[1]]
                fields.append(DecodedField(name=name, value=predecoded[name], source="predecoder",
                                           start=span[0], end=span[1]))
        caps: List[Tuple[_Capture, int, int]] = []
        for cap in out.captures:
            s, e = (cap.start + shift, cap.end + shift) if cap.start >= 0 else (-1, -1)
            caps.append((cap, s, e))

        # ---- candidate fields in the text -----------------------------------
        issues: List[Issue] = []
        kv_pairs: List[KV] = []
        json_leaves: List[JsonLeaf] = []
        json_region = out.json_span
        json_at: Optional[int] = None
        if not builtin:
            json_at = self._json_start(log) if out.json_span is None else None
            parsed = parse_json(log, json_at) if json_at is not None else None
            if parsed:
                json_leaves, lo, hi = parsed
                json_region = (lo, hi)
            kv_pairs = scan_kv(log, 0, json_region[0] if json_region else len(log), program_name)

        # Wazuh's JSON_Decoder reads the first JSON value of a line and ignores the rest (cJSON_ParseWithOpts):
        # a second event glued on the same line ("{...}{...}") is never decoded.
        glued: List[JsonLeaf] = []
        glued_regions: List[Tuple[int, int]] = []
        pos = json_region[1] if json_region and not builtin else None
        while pos is not None:
            m = _NEXT_JSON_RE.match(log, pos)
            parsed = parse_json(log, m.end()) if m else None
            if not parsed:
                break
            glued += parsed[0]
            glued_regions.append((parsed[1], parsed[2]))
            pos = parsed[2]

        cap_intervals = sorted((s, e, i) for i, (_, s, e) in enumerate(caps) if s >= 0)

        def captured_in(s: int, e: int) -> List[int]:
            return [i for cs, ce, i in cap_intervals if (cs < e and ce > s) or (cs == ce and s <= cs < e)]

        for kv in kv_pairs:
            if not kv.value:
                continue  # empty value: nothing to extract
            vs, ve = kv.vstart + log_start, kv.vend + log_start
            if captured_in(vs, max(ve, vs + 1)):
                continue
            issues.append(self._kv_issue(kv, log, log_start, out, detail, kv_mode(kv_pairs)))

        for leaf in json_leaves:
            if leaf.value is None:
                continue
            issues.append(Issue(
                kind="json", key=leaf.path, value=leaf.value, value_kind="json",
                start=leaf.key_start + log_start, end=leaf.end + log_start,
                reason=("JSON key not decoded: no decoder with <plugin_decoder>JSON_Decoder</plugin_decoder> ran on "
                        "this line (Wazuh's stock json decoder only reads lines that start with '{' and have no "
                        "syslog program name)."),
            ))
        for leaf in glued:
            if leaf.value is not None:
                issues.append(Issue(
                    kind="json", key=leaf.path, value=leaf.value, value_kind="json",
                    start=leaf.key_start + log_start, end=leaf.end + log_start,
                    reason=("Second JSON event on the same line: Wazuh's JSON decoder reads only the first JSON object "
                            "of a line and ignores the rest, so this key is never extracted. Send one event per line."),
                ))

        # Free-text values outside key=value pairs and JSON.
        values: List[Tuple[str, int, int, Optional[str]]] = []
        if not builtin:
            blocked = [(kv.start, kv.end) for kv in kv_pairs]
            if out.json_span:
                blocked.append(out.json_span)
            if json_region:
                blocked.append(json_region)
            blocked += glued_regions
            for kind, s, e in _value_tokens(log, blocked):
                gs, ge = s + log_start, e + log_start
                if captured_in(gs, ge):
                    continue
                m = _CONTEXT_RE.search(log[max(0, s - 30):s])
                ctx = m.group(1) if m else None
                values.append((kind, s, e, ctx))
                issue = Issue(
                    kind="value", value=log[s:e], value_kind=kind, context=ctx, start=gs, end=ge,
                    reason=(f"{_KIND_LABEL.get(kind, kind)} in the message that no decoder extracts"
                            + (f" (after '{ctx}')" if ctx else "") + "."),
                )
                found = value_regex(log, s, e, kind) if detail and out.root is not None else None
                if found:
                    issue.suggestion = self._child_suggestion(found[0], "osregex", [value_field(kind, found[1])], out)
                issues.append(issue)

        new_decoder = None
        if detail and not builtin and out.root is None:
            # decoders tested alone that name a missing <parent>: suggest that parent, not a new decoder set
            parent = next((c.decoder.parent for c in out.captures if c.source == "test" and c.decoder.parent), None)
            new_decoder = self._format_suggestion([(log, program_name, kv_pairs, json_at if json_region else None,
                                                    values)], parent)

        # ---- fields list -----------------------------------------------------
        for i, (cap, s, e) in enumerate(caps):
            value = cap.value if cap.value is not None else (raw[s:e] if s >= 0 else "")
            dec = cap.decoder
            fields.append(DecodedField(
                name=cap.name, value=value, source=cap.source,
                decoder=dec.name if dec else ("windows_eventchannel" if cap.source == "windows" else None),
                decoder_uid=dec.uid if dec else None, file=dec.file if dec else None,
                xml_line=dec.line if dec else None,
                start=s if s >= 0 else None, end=e if s >= 0 else None,
            ))

        counts = LineCounts(
            fields=len(caps),
            missing=sum(1 for x in issues if x.kind in ("missing", "json")),
            broken=sum(1 for x in issues if x.kind == "broken"),
            values=sum(1 for x in issues if x.kind == "value"),
        )
        denominator = counts.fields + counts.missing + counts.broken + counts.values
        if denominator:
            coverage = round(counts.fields / denominator * 100.0, 1)
        else:
            coverage = 100.0 if out.decoder is not None or builtin else 0.0

        if builtin:
            status = "decoded"
            ref = DecoderRef(name="windows_eventchannel", xml_name="windows_eventchannel", builtin=True)
        elif out.root is None:
            test = next((c.decoder for c in out.captures if c.source == "test"), None)
            status = "no_decoder"  # what Wazuh does; a decoder tested alone is shown, but never counts as decoded
            ref = DecoderRef(name=test.name, xml_name=test.name, uid=test.uid, file=test.file, xml_line=test.line,
                             test=True) if test else None
        else:
            status = "decoded" if (out.captures or out.decoder is not out.root or not out.root.children) else "parent_only"
            d = out.decoder or out.root
            shown = d.name if (d.is_root or d.use_own_name) else out.root.name
            ref = DecoderRef(name=shown, parent=None if d.is_root else out.root.name, xml_name=d.name,
                             uid=d.uid, file=d.file, xml_line=d.line)

        tokens: List[LogToken] = []
        trace: List[TraceStep] = []
        if detail:
            trace = list(out.trace)
            if out.stop:
                trace.append(TraceStep(decoder=out.root.name if out.root else "-", step="result", result="info",
                                       detail=out.stop))
            tokens = self._tokens(raw, pre.event_offset, log_start, out, caps, issues, pre.log_end)

        return AnalyzedLine(
            line_number=line_number, raw_line=raw, envelope=pre.envelope, location=pre.location,
            event_offset=pre.event_offset, log_offset=log_start, predecoded=predecoded,
            status=status, decoder=ref, fields=fields, issues=issues, tokens=tokens, trace=trace,
            counts=counts, coverage_pct=coverage, new_decoder=new_decoder,
        )

    @staticmethod
    def _json_start(log: str) -> Optional[int]:
        """Start of a JSON object that runs to the end of the log (``app: {"a":1}``), else None."""
        if not log.rstrip().endswith("}"):
            return None
        m = re.search(r'\{\s*"', log)
        return m.start() if m else None

    # ------------------------------------------------------------------ key issues
    def _kv_issue(self, kv: KV, log: str, log_start: int, out: _Outcome, detail: bool, mode: str) -> Issue:
        shape = value_shape(kv)
        span = (kv.start + log_start, kv.end + log_start)
        candidates = self.by_key.get(kv.key.lower(), [])
        active = set()
        if out.root is not None:
            active = {d.uid for d in out.root.children} | {out.root.uid}
        target = next((d for d in candidates if d.uid in active and self._same_format(d, out)), None)

        if target is None or kv.header:
            label = "CEF/LEEF header field" if kv.header else "key"
            if out.root is None:
                reason = f"No decoder handles this line, so {label} '{kv.key}' is not extracted."
            else:
                reason = f"No decoder under '{out.root.name}' extracts {label} '{kv.key}' (value shape: {shape})."
            if candidates and not kv.header:
                other = candidates[0]
                reason += f" ('{other.name}' in {other.file} reads '{kv.key}', but only for its own log format.)"
            issue = Issue(kind="missing", key=kv.key, value=kv.value, value_kind=shape,
                          start=span[0], end=span[1], reason=reason)
            if detail and out.root is not None and not kv.header:
                issue.suggestion = self._kv_child_suggestion(kv, log, out, mode)
            return issue

        reason, fix = self._diagnose(target, kv, log, out)
        issue = Issue(kind="broken", key=kv.key, value=kv.value, value_kind=shape, start=span[0], end=span[1],
                      reason=reason, decoder=target.name, decoder_uid=target.uid, decoder_file=target.file,
                      decoder_line=target.line, decoder_regex=target.regex_raw)
        if detail:
            if fix is not None:
                issue.suggestion = Suggestion(action="replace_regex", target_uid=target.uid, regex=fix,
                                              note=f"replace the regex with {fix}")
            elif out.root is not None:
                issue.suggestion = self._kv_child_suggestion(kv, log, out, mode)
        return issue

    @staticmethod
    def _same_format(dec: Decoder, out: _Outcome) -> bool:
        """False for a child meant for another log format: its group starts with a <prematch> that did not
        select this line (Sysmon event 1 'new' decoders on an 'old' event 1 line). Such a key is missing, not broken."""
        if out.root is None or dec is out.root or dec.uid in out.evaluated:
            return True
        head = next((c for c in out.root.children if c.name == dec.name), dec)
        return head.prematch_raw is None or head is out.decoder

    def _diagnose(self, dec: Decoder, kv: KV, log: str, out: _Outcome) -> Tuple[str, Optional[str]]:
        where = f"'{dec.name}' ({dec.file}:{dec.line})"
        state = out.evaluated.get(dec.uid)
        if state is None:
            why = out.stop or "the decoder chain did not reach it"
            return f"Decoder {where} targets '{kv.key}' but was not evaluated: {why}.", None
        matched, start = state
        if matched:
            for cap in out.captures:
                if cap.decoder is dec:
                    return (f"Decoder {where} matched somewhere else in the line (value '{log[cap.start:cap.end]}') "
                            f"instead of this '{kv.key}{kv.sep}'; anchor the regex so it only matches this key."), \
                        (r"\s" + dec.regex_raw if dec.unanchored and dec.regex_raw else None)
            return f"Decoder {where} matched but captured nothing for '{kv.key}'.", None
        if start > kv.start:
            return (f"Decoder {where} searches from offset {start} ({dec.regex_offset}), "
                    f"which is after this key."), None
        raw = dec.regex_raw or ""
        shapes = {value_shape(kv)}
        prefix = log[kv.start - 1] if kv.start > 0 else ""
        fix, _ = kv_regex(kv.key, shapes, {prefix}, "colon" if kv.sep == ":" else "plain", _gap(log, kv))
        at_eol = kv.end >= len(log.rstrip())
        if re.search(r"\\s[+*]?\)?$", raw) and at_eol:
            return (f"Decoder {where} requires whitespace after the value, but '{kv.key}' ends the line. "
                    "Remove the trailing \\s."), re.sub(r"\\s[+*]?(\)?)$", r"\1", raw)
        if '="' in raw and not kv.quoted:
            return (f"Decoder {where} expects a quoted value, but this line has {kv.key}={kv.value} (unquoted)."), fix
        if '="' not in raw and kv.quoted and "\\p" not in raw:
            return (f"Decoder {where} expects an unquoted value, but this line has a quoted one."), fix
        if re.search(r"\\d[+*]", raw) and not kv.value.isdigit():
            return (f"Decoder {where} expects digits, but the value '{kv.value}' is not numeric."), fix
        if raw.startswith(r"\s") and prefix != " ":
            return (f"Decoder {where} expects a space before '{kv.key}{kv.sep}', but here it is "
                    f"{'at the start of the log' if not prefix else repr(prefix)}."), fix
        return f"Decoder {where} did not match: {raw}", fix

    def _kv_child_suggestion(self, kv: KV, log: str, out: _Outcome, mode: str) -> Optional[Suggestion]:
        found = verified_kv_regex([(log, kv)], mode)
        return self._child_suggestion(found[0], found[1], [kv.key], out) if found else None

    def _child_suggestion(self, regex: str, rtype: str, order: List[str], out: _Outcome) -> Suggestion:
        """A new child of the root that decoded this line, placed where Wazuh will actually run it."""
        root = out.root
        assert root is not None
        if out.chain_name and root.children:
            name, after = out.chain_name, out.chain_name
            note = f"joins the '{name}' sibling chain (inserted after its last member)"
        elif root.children:
            name, after = root.name + "-custom", None
            note = "new child: reached only when no earlier child is selected"
        else:
            name, after = root.name, None
            note = ("first child of this root" + (" - a root with children no longer runs its own <regex>; "
                                                    "move that regex into a child too" if root.regex_raw else ""))
        return Suggestion(action="add_decoder", xml=decoder_xml(name, root.name, regex, order, rtype),
                          insert_after=after, parent=root.name, note=note)

    def format_suggestion(self, raw_lines: List[str]) -> Optional[Suggestion]:
        """Decoder for a log format no decoder handles, learned from several sample lines of it."""
        samples = [s for s in map(self._format_inputs, raw_lines) if s]
        return self._format_suggestion(samples) if samples else None

    def _format_inputs(self, raw_line: str):
        """(log, program_name, kv pairs, json start, free-text values) of a line no decoder handles, else None."""
        pre = predecode(raw_line)
        log = pre.raw_line[pre.log_offset:pre.log_end]
        program_name = pre.text(pre.program_name)
        if self.decode(log, program_name).root is not None:
            return None
        json_at = self._json_start(log)
        parsed = parse_json(log, json_at) if json_at is not None else None
        region = (parsed[1], parsed[2]) if parsed else None
        kv_pairs = scan_kv(log, 0, region[0] if region else len(log), program_name)
        blocked = [(kv.start, kv.end) for kv in kv_pairs] + ([region] if region else [])
        values = [(kind, s, e, None) for kind, s, e in _value_tokens(log, blocked)]
        return log, program_name, kv_pairs, (json_at if parsed else None), values

    def _format_suggestion(self, samples, root_name: Optional[str] = None) -> Optional[Suggestion]:
        """Root + child decoders for a log format no decoder handles (appended to local_decoder.xml).
        With ``root_name`` (the missing <parent> of decoders tested alone): only that root.

        ``samples``: one or more (log, program_name, kv_pairs, json_at, values) of lines of that format.
        Each key gets one regex covering every value shape seen, checked on every sample.
        """
        log, program_name, kv_pairs, json_at, values = samples[0]
        header = [kv for kv in kv_pairs if kv.header]
        body = [kv for kv in kv_pairs if not kv.header and kv.value]
        base = (program_name or (f"{header[1].value}-{header[2].value}" if len(header) > 2 else None)
                or ((f"{body[0].key}-{body[0].value}" if re.fullmatch(r"[A-Za-z][\w.\-]{0,19}", body[0].value) else body[0].key)
                    if body else None)
                or (log.split()[0] if log.split() else "log"))
        name = root_name or "custom-" + re.sub(r"[^a-z0-9]+", "-", base.lower()).strip("-")[:40]
        taken = {d.name for d in self.tree.decoders}
        while name in taken and not root_name:
            name += "-2"

        root = [f'<decoder name="{name}">']
        if program_name:
            root.append(f"  <program_name>^{program_name}$</program_name>")
        if json_at is not None:
            if json_at == 0 and program_name:
                root.append("  <plugin_decoder>JSON_Decoder</plugin_decoder>")
            elif json_at == 0:  # like the stock json decoder (an empty prematch would break the plugin offset)
                root.append(r'  <prematch>^{\s*"</prematch>')
                root.append("  <plugin_decoder>JSON_Decoder</plugin_decoder>")
            else:  # JSON after some text: prematch stops right before '{', the plugin reads from there
                root.append(r'  <prematch type="pcre2">^[^{]*(?=\{\s*")</prematch>')
                root.append('  <plugin_decoder offset="after_prematch">JSON_Decoder</plugin_decoder>')
            root.append("</decoder>")
            return Suggestion(action="add_decoder", xml="\n".join(root),
                              note="new decoder for this JSON format (added to local_decoder.xml)")
        if not program_name:
            if header:
                root.append("  <prematch>" + (r"CEF:\d+\|" if header[0].key == "cef_version" else "LEEF:") + "</prematch>")
            elif body:
                root.append(f"  <prematch>{_kv_prematch(samples)}</prematch>")
            else:
                prematch = _text_prematch(log, values)
                if prematch is None:
                    return None
                root.append(f"  <prematch>{prematch}</prematch>")
        root.append("</decoder>")
        if root_name:
            return Suggestion(action="add_decoder", xml="\n".join(root),
                              note=f"your decoders name '{root_name}' as <parent>, but it is not loaded: add this root "
                                   "(placed before them) and they join the tree; review the prematch")

        parts = ["\n".join(root)]
        mode = kv_mode(kv_pairs)
        if header:
            parts.append(decoder_xml(name, name, _CEF_HEADER_REGEX if mode == "cef" else _LEEF_HEADER_REGEX,
                                     [k.key for k in header], "pcre2"))
        used = {k.key for k in header}
        occurrences: Dict[str, List[Tuple[str, KV]]] = {}  # key -> every (log, pair), first-seen order
        for s_log, _, s_pairs, _, _ in samples:
            for kv in s_pairs:
                if not kv.header and kv.value and kv.key not in used:
                    occurrences.setdefault(kv.key, []).append((s_log, kv))
        for key, occ in occurrences.items():
            used.add(key)
            found = verified_kv_regex(occ, mode)
            if found:  # a key no regex can single out (e.g. repeated) stays visible as missing
                parts.append(decoder_xml(name, name, found[0], [key], found[1]))
        seen_regex = set()
        for s_log, _, _, _, s_values in samples:
            for kind, s, e, _ in s_values:
                found = value_regex(s_log, s, e, kind)
                if not found or found[0] in seen_regex:
                    continue  # no stable word in front (e.g. CSV columns): left for a hand-written regex
                seen_regex.add(found[0])
                field = value_field(kind, found[1])
                while field in used:
                    field += "_2"
                used.add(field)
                parts.append(decoder_xml(name, name, found[0], [field]))
        learned = f", learned from {len(samples)} sample lines" if len(samples) > 1 else ""
        return Suggestion(action="add_decoder", xml="\n\n".join(parts),
                          note=f"new decoder '{name}' for this log format: 1 root + {len(parts) - 1} field decoders"
                               f"{learned} (added to local_decoder.xml; review names before installing)")

    # ------------------------------------------------------------------ tokens
    def _tokens(self, raw: str, event_offset: int, log_start: int, out: _Outcome, caps,
                issues: List[Issue], log_end: Optional[int] = None) -> List[LogToken]:
        n = len(raw)
        state: List[TokenState] = [TokenState.TEXT] * n
        tag: List[Tuple[Optional[str], Optional[int]]] = [(None, None)] * n

        def paint(s: int, e: int, st: TokenState, label: Optional[str] = None, issue: Optional[int] = None):
            p = _PRIORITY[st]
            for k in range(max(0, s), min(n, e)):
                if _PRIORITY[state[k]] <= p:
                    state[k] = st
                    tag[k] = (label, issue)

        builtin = out.trace[:1] and out.trace[0].step == "builtin"
        offset = 0 if builtin else log_start
        for s, e in out.matched:
            paint(s + offset, e + offset, TokenState.MATCHED)
        if out.json_span:
            paint(out.json_span[0] + offset, out.json_span[1] + offset, TokenState.MATCHED)
        for idx, issue in enumerate(issues):
            if issue.kind in ("missing", "broken", "json") and issue.start is not None:
                paint(issue.start, issue.end, TokenState.BROKEN if issue.kind == "broken" else TokenState.MISSING,
                      issue.key, idx)
            elif issue.kind == "value" and issue.start is not None:
                paint(issue.start, issue.end, TokenState.MISSING, issue.value_kind, idx)
        for cap, s, e in caps:
            if s >= 0:
                paint(s, e, TokenState.TEST if cap.source == "test" else TokenState.CAPTURED, cap.name)

        tokens: List[LogToken] = []
        header_end = event_offset if builtin else log_start
        if header_end > 0:
            tokens.append(LogToken(text=raw[:header_end], start=0, end=header_end, state=TokenState.HEADER))
        if log_end is not None:  # text after an ASL [Message ...] entry is header, not log
            for k in range(log_end, n):
                state[k], tag[k] = TokenState.HEADER, (None, None)
        k = header_end
        while k < n:
            j = k + 1
            while j < n and state[j] == state[k] and tag[j] == tag[k]:
                j += 1
            tokens.append(LogToken(text=raw[k:j], start=k, end=j, state=state[k], field=tag[k][0], issue=tag[k][1]))
            k = j
        return tokens


_KIND_LABEL = {
    "url": "URL", "email": "E-mail address", "path": "File path", "mac": "MAC address", "ip": "IP address",
    "ipv6": "IPv6 address", "hash": "Hash", "quoted": "Quoted text", "number": "Number", "field": "Field",
}


def _value_tokens(text: str, blocked: List[Tuple[int, int]]) -> List[Tuple[str, int, int]]:
    found = _positional_fields(text, blocked)
    taken: List[Tuple[int, int]] = list(blocked) + [(s, e) for _, s, e in found]
    for kind, pattern in _VALUE_PATTERNS:
        for m in pattern.finditer(text):
            s, e = m.span()
            if kind == "ipv6" and (m.group(0).count(":") < 2 or not re.search(r"[A-Fa-f]|::", m.group(0))
                                   or not re.search(r"[0-9A-Fa-f]", m.group(0))):
                continue
            if any(s < te and e > ts for ts, te in taken):
                continue
            if kind == "quoted" and m.group(0)[1:-1].strip() in ("", "-"):
                continue
            taken.append((s, e))
            found.append((kind, s, e))
    found.sort(key=lambda x: x[1])
    return found
