r"""Minimal port of Wazuh's XML reader (src/os_xml/os_xml.c).

Wazuh does not use a standard XML parser for rules/decoders:

* ``\<`` inside element content is literal text (OS_Regex then reads ``\<`` as
  a literal ``<``), so ``<prematch>\<log>\.+\</log></prematch>`` is one value;
* entities are NOT decoded: ``&`` and ``&lt;`` are kept as typed;
* content is not trimmed.

Standard XML parsers reject or mangle several stock ruleset files (trend-osce,
exim, nginx decoders), which is why this exists.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


class WazuhXmlError(ValueError):
    pass


@dataclass
class Element:
    name: str
    attrs: Dict[str, str]
    line: int
    content: str = ""
    children: List["Element"] = field(default_factory=list)

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        return self.attrs.get(key, default)


class _Reader:
    def __init__(self, text: str):
        self.s = text
        self.i = 0
        self.n = len(text)

    def line(self, pos: Optional[int] = None) -> int:
        return self.s.count("\n", 0, self.i if pos is None else pos) + 1

    def skip_special(self) -> bool:
        """Skip <!-- -->, <? ?> and <! > at the cursor (which points at '<')."""
        s = self.s
        if s.startswith("<!--", self.i):
            end = s.find("-->", self.i + 4)
            if end == -1:
                raise WazuhXmlError(f"line {self.line()}: comment not closed")
            self.i = end + 3
            return True
        if s.startswith("<?", self.i):
            end = s.find("?>", self.i + 2)
            self.i = self.n if end == -1 else end + 2
            return True
        if s.startswith("<!", self.i):
            end = s.find(">", self.i + 2)
            self.i = self.n if end == -1 else end + 1
            return True
        return False

    def element(self) -> Element:
        """Parse one element; the cursor is at its '<'."""
        s = self.s
        start = self.i
        self.i += 1
        j = self.i
        while j < self.n and s[j] != ">" and not s[j].isspace():
            j += 1
        name = s[self.i:j]
        self_closed = name.endswith("/")
        if self_closed:
            name = name[:-1]
        if not name or name.startswith("/"):
            raise WazuhXmlError(f"line {self.line(start)}: element not opened")
        self.i = j
        attrs: Dict[str, str] = {}
        while self.i < self.n and s[self.i] != ">":
            c = s[self.i]
            if c.isspace():
                self.i += 1
                continue
            if c == "/":
                self_closed = True
                self.i += 1
                continue
            eq = s.find("=", self.i)
            if eq == -1:
                raise WazuhXmlError(f"line {self.line()}: bad attribute in <{name}>")
            key = s[self.i:eq].strip()
            k = eq + 1
            while k < self.n and s[k].isspace():
                k += 1
            if k >= self.n or s[k] not in "\"'":
                raise WazuhXmlError(f"line {self.line()}: attribute '{key}' value must be quoted")
            close = s.find(s[k], k + 1)
            if close == -1:
                raise WazuhXmlError(f"line {self.line()}: attribute '{key}' not closed")
            attrs[key] = s[k + 1:close]
            self.i = close + 1
        if self.i >= self.n:
            raise WazuhXmlError(f"line {self.line(start)}: element <{name}> not closed")
        self.i += 1  # '>'
        elem = Element(name=name, attrs=attrs, line=self.line(start))
        if self_closed:
            return elem
        text: List[str] = []
        backslashes = 0
        while self.i < self.n:
            c = s[self.i]
            if c == "<" and backslashes % 2 == 0:
                if self.skip_special():
                    continue
                if s.startswith("</", self.i):
                    end = s.find(">", self.i)
                    closing = s[self.i + 2:end] if end != -1 else ""
                    if closing != name:
                        raise WazuhXmlError(f"line {self.line()}: element <{name}> not closed (found </{closing}>)")
                    self.i = end + 1
                    elem.content = "".join(text)
                    return elem
                elem.children.append(self.element())
                text = []  # os_xml.c resets the content after a nested element
                backslashes = 0
                continue
            # os_xml.c: each '\' flips the escape state; a literal '<' keeps it.
            backslashes = backslashes + 1 if c == "\\" else (backslashes if c == "<" else 0)
            text.append(c)
            self.i += 1
        raise WazuhXmlError(f"line {self.line(start)}: element <{name}> not closed")


def parse(text: str) -> List[Element]:
    """Top-level elements of a Wazuh XML file (no single root required)."""
    reader = _Reader(text or "")
    out: List[Element] = []
    s = reader.s
    while reader.i < reader.n:
        lt = s.find("<", reader.i)
        if lt == -1:
            break
        reader.i = lt
        if reader.skip_special():
            continue
        out.append(reader.element())
    return out
