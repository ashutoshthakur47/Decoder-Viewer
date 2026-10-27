"""Load Wazuh decoder XML files into the same tree analysisd builds.

Mirrors src/analysisd/decoders/decode-xml.c and decoders_list.c:

* files are read in the given order (like the ruleset/decoders + etc/decoders
  load order); ``<var>`` definitions are substituted;
* several ``<regex>`` / ``<prematch>`` elements in one decoder are concatenated;
* a root decoder (no ``<parent>``) goes to the *program_name* list when it has
  ``<program_name>``, otherwise to the *no program_name* list;
* a child is attached to every root with that name, in load order; when a
  child has the same name as an earlier sibling, every earlier same-name
  sibling gets ``get_next`` (sibling decoders run as a chain);
* children without ``use_own_name`` are reported under the parent's name.

Errors that make Wazuh refuse to start are collected per decoder instead of
aborting, so the UI can show them.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from . import wazuh_xml
from .os_regex import Expression, ExpressionError, compile_expression, group_keys, is_unanchored, target_key_of

_VAR_REF_RE = re.compile(r"\$([A-Za-z0-9_]+)")
_OFFSETS = {"after_parent", "after_prematch", "after_regex"}
# <order> names Wazuh maps to static fields (decode-xml.c).
STATIC_ALIASES = {"user": "dstuser"}
PLUGINS = {"JSON_Decoder", "PF_Decoder", "SymantecWS_Decoder", "SonicWall_Decoder", "OSSECAlert_Decoder"}


@dataclass(eq=False)
class Decoder:
    uid: int
    name: str
    file: str
    line: int
    parent: Optional[str] = None
    program_name_raw: Optional[str] = None
    program_name: Optional[Expression] = None
    prematch_raw: Optional[str] = None
    prematch: Optional[Expression] = None
    prematch_offset: Optional[str] = None
    regex_raw: Optional[str] = None
    regex: Optional[Expression] = None
    regex_type: str = "osregex"
    regex_offset: Optional[str] = None
    order: List[str] = field(default_factory=list)
    plugin: Optional[str] = None
    plugin_offset: Optional[str] = None
    use_own_name: bool = False
    type: Optional[str] = None
    json_null_field: str = "discard"
    json_array_structure: str = "array"
    get_next: bool = False
    children: List["Decoder"] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)  # Wazuh would refuse to load it
    warnings: List[str] = field(default_factory=list)  # loaded, but this tool cannot emulate part of it
    target_key: Optional[str] = None
    unanchored: bool = False
    group_keys: List[List[Optional[str]]] = field(default_factory=list)  # per alternative, key before each group

    @property
    def is_root(self) -> bool:
        return self.parent is None

    @property
    def fields(self) -> List[str]:
        return [STATIC_ALIASES.get(name, name) for name in self.order]

    @property
    def standalone(self) -> bool:
        """Rejected only for its place in the tree (no / unknown parent, sibling or offset rules), with
        expressions that compile: it can still be run alone on a log to test it."""
        compiled = all(raw is None or expr is not None for raw, expr in (
            (self.regex_raw, self.regex), (self.prematch_raw, self.prematch), (self.program_name_raw, self.program_name)))
        # shortcut: plugin decoders (JSON_Decoder) are not run alone; add if JSON children get tested without a parent
        return bool(self.errors and self.name and not self.plugin and compiled and (self.regex or self.prematch))


@dataclass
class DecoderTree:
    files: List[Tuple[str, str]]  # (name, xml text) in load order
    decoders: List[Decoder] = field(default_factory=list)  # every parsed decoder, load order
    roots_pn: List[Decoder] = field(default_factory=list)
    roots_nopn: List[Decoder] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)  # file-level problems

    @property
    def valid(self) -> List[Decoder]:
        return [d for d in self.decoders if not d.errors]

    def by_uid(self, uid: int) -> Optional[Decoder]:
        for d in self.decoders:
            if d.uid == uid:
                return d
        return None


def _parse_file(name: str, text: str, uid_start: int, variables: Dict[str, str], file_errors: List[str]) -> List[Decoder]:
    try:
        elements = wazuh_xml.parse(text)
    except wazuh_xml.WazuhXmlError as exc:
        file_errors.append(f"{name}: {exc} (Wazuh would refuse this file)")
        return []

    def subst(value: str) -> str:
        return _VAR_REF_RE.sub(lambda m: variables.get(m.group(1), m.group(0)), value)

    out: List[Decoder] = []
    uid = uid_start
    for elem in elements:
        if elem.name == "var":
            var_name = elem.get("name") or ""
            if var_name:
                variables[var_name] = elem.content
            continue
        if elem.name != "decoder":
            file_errors.append(f"{name}:{elem.line}: unexpected <{elem.name}> element (ignored)")
            continue
        dec = Decoder(uid=uid, name=elem.get("name") or "", file=name, line=elem.line)
        uid += 1
        if not dec.name:
            dec.errors.append("decoder has no name attribute")
        regex_parts: List[str] = []
        prematch_parts: List[str] = []
        pname_parts: List[str] = []
        prematch_type = "osregex"
        pname_type = "osmatch"
        for child in elem.children:
            ctag = child.name
            content = subst(child.content)
            if ctag == "parent":
                dec.parent = content
            elif ctag == "regex":
                offset = child.get("offset")
                if offset and regex_parts:
                    dec.errors.append("only the first <regex> may have an offset")
                if offset:
                    if offset not in _OFFSETS:
                        dec.errors.append(f"invalid regex offset '{offset}'")
                    dec.regex_offset = offset
                dec.regex_type = (child.get("type") or "osregex").lower()
                regex_parts.append(content)
            elif ctag == "prematch":
                offset = child.get("offset")
                if offset:
                    if offset != "after_parent":
                        dec.errors.append(f"invalid prematch offset '{offset}' (only after_parent)")
                    dec.prematch_offset = offset
                prematch_type = (child.get("type") or "osregex").lower()
                prematch_parts.append(content)
            elif ctag == "program_name":
                pname_type = (child.get("type") or "osmatch").lower()
                pname_parts.append(content)
            elif ctag == "order":
                dec.order.extend(p.strip().split(" ")[0] for p in content.split(",") if p.strip())
            elif ctag == "plugin_decoder":
                dec.plugin = content
                dec.plugin_offset = child.get("offset")
                if content not in PLUGINS:
                    dec.errors.append(f"unknown plugin_decoder '{content}'")
            elif ctag == "use_own_name":
                dec.use_own_name = content.lower() == "true"
            elif ctag == "type":
                dec.type = content
            elif ctag == "json_null_field":
                dec.json_null_field = content.lower()
            elif ctag == "json_array_structure":
                dec.json_array_structure = content.lower()

        if regex_parts:
            dec.regex_raw = "".join(regex_parts)
        if prematch_parts:
            dec.prematch_raw = "".join(prematch_parts)
        if pname_parts:
            dec.program_name_raw = "".join(pname_parts)

        for attr, raw, kind in (("regex", dec.regex_raw, dec.regex_type),
                                ("prematch", dec.prematch_raw, prematch_type),
                                ("program_name", dec.program_name_raw, pname_type)):
            if raw is None:
                continue
            try:
                setattr(dec, attr, compile_expression(raw, kind))
            except ExpressionError as exc:
                if kind == "pcre2":
                    # Python's regex engine lacks some PCRE2 features (e.g. the U flag): Wazuh may
                    # accept the pattern, so keep the decoder and treat it as never matching.
                    dec.warnings.append(f"<{attr}> uses PCRE2 syntax this tool cannot run ({exc}); "
                                        "treated as 'no match'")
                else:
                    dec.errors.append(f"<{attr}> {exc}")

        # Validation from decode-xml.c (each makes analysisd refuse to start).
        if dec.prematch_raw is None and dec.parent is None and dec.program_name_raw is None:
            dec.errors.append("a root decoder needs <prematch> or <program_name>")
        if (dec.regex_raw is None) != (not dec.order) and not dec.plugin:
            dec.errors.append("<regex> and <order> must be used together")
        if dec.plugin and (dec.regex_raw is not None or dec.order):
            dec.errors.append("<plugin_decoder> cannot be combined with <regex>/<order>")
        if dec.regex_offset == "after_parent" and dec.parent is None:
            dec.errors.append("offset after_parent needs a <parent>")
        if dec.regex_offset == "after_prematch" and dec.parent is None:
            dec.regex_offset = "after_parent"  # Wazuh rewrites it for root decoders
        elif dec.regex_offset == "after_prematch" and dec.prematch_raw is None:
            dec.errors.append("offset after_prematch needs a <prematch>")
        if dec.regex_offset == "after_regex" and dec.parent is None:
            dec.errors.append("offset after_regex needs a <parent>")
        if dec.prematch_offset and dec.parent is None:
            dec.errors.append("prematch offset after_parent needs a <parent>")

        dec.target_key = target_key_of(dec.regex_raw or "") if dec.regex_type == "osregex" else None
        dec.group_keys = group_keys(dec.regex_raw or "") if dec.regex_type == "osregex" else []
        dec.unanchored = dec.regex_type == "osregex" and is_unanchored(dec.regex_raw or "")
        out.append(dec)
    return out


def _add_child(siblings: List[Decoder], dec: Decoder) -> Optional[str]:
    """_OS_AddOSDecoder for a child: sibling chaining rules. Returns an error or None."""
    for existing in siblings:
        if existing.name != dec.name:
            continue
        if dec.prematch_raw is not None:
            return "a decoder that repeats a sibling's name cannot have <prematch>"
        if (existing.regex_raw is not None or existing.plugin) and (dec.regex_raw is not None or dec.plugin):
            existing.get_next = True
        else:
            return "same-name sibling decoders must all have <regex> (or a plugin)"
    # decoders_list.c (rm_f): after_regex continues an earlier same-name sibling that has a prematch/regex.
    if dec.regex_offset == "after_regex" and not any(
            s.name == dec.name and (s.prematch_raw is not None or s.regex_raw is not None) for s in siblings):
        return ("offset=\"after_regex\" needs an earlier decoder with the same name and a <regex> under this "
                "parent (it continues where that regex stopped)")
    siblings.append(dec)
    return None


def build_tree(files: List[Tuple[str, str]]) -> DecoderTree:
    tree = DecoderTree(files=list(files))
    variables: Dict[str, str] = {}
    uid = 1
    for name, text in files:
        decs = _parse_file(name, text, uid, variables, tree.errors)
        uid += len(decs)
        for dec in decs:
            tree.decoders.append(dec)
            if dec.errors:
                continue
            if dec.parent is None:
                (tree.roots_pn if dec.program_name_raw is not None else tree.roots_nopn).append(dec)
                continue
            parents = [r for r in tree.roots_pn + tree.roots_nopn if r.name == dec.parent]
            if not parents:
                dec.errors.append(
                    f"parent decoder '{dec.parent}' not found: no root decoder (one without <parent>) with that name is "
                    "loaded before it. Add it, e.g. <decoder name=\"" + dec.parent + "\"><prematch>...</prematch>"
                    "</decoder>, or load the file that has it first")
                continue
            for root in parents:
                problem = _add_child(root.children, dec)
                if problem:
                    dec.errors.append(problem)
                    break
    return tree


def read_decoder_path(path: str) -> List[Tuple[str, str]]:
    """Read one XML file, or every *.xml in a folder (sorted, like Wazuh)."""
    if os.path.isdir(path):
        names = sorted(n for n in os.listdir(path) if n.lower().endswith(".xml"))
        return [(n, _read_text(os.path.join(path, n))) for n in names]
    return [(os.path.basename(path), _read_text(path))]


def _read_text(path: str) -> str:
    with open(path, "rb") as handle:
        data = handle.read()
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")
