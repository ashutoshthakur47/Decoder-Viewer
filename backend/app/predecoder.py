"""Turn one raw input line into what Wazuh's decoders see.

1. Envelope (not part of the event):
   * ossec ``archives.log`` prefix ``2026 Sep 10 14:07:41 (agent) ip->location ``
   * ``archives.json`` lines: the event is the ``full_log`` value
   * syslog PRI ``<134>`` (wazuh-remoted drops it)
2. Pre-decoding: a port of ``OS_CleanMSG`` (src/analysisd/cleanevent.c, 4.11.2)
   that extracts timestamp / hostname / program_name and sets ``log``, the text
   decoders run on.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Optional

_ARCHIVE_RE = re.compile(
    r"^\d{4} [A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2} (?:\([^)]*\) )?\S+?->(\S+) "
)
_PRI_RE = re.compile(r"^<\d{1,3}>")


@dataclass
class Predecoded:
    raw_line: str  # what the UI shows
    event_offset: int  # where the event (full_log) starts in raw_line
    envelope: Optional[str]  # archive / archives.json / PRI description
    location: Optional[str]
    timestamp: Optional[tuple]  # (start, end) in raw_line
    hostname: Optional[tuple]
    program_name: Optional[tuple]
    log_offset: int  # where lf->log starts in raw_line
    log_end: Optional[int] = None  # where lf->log ends (only macOS ASL cuts it), None = end of line

    def text(self, span: Optional[tuple]) -> Optional[str]:
        return self.raw_line[span[0]:span[1]] if span else None


_HOSTNAME_CHARS = frozenset("()-./0123456789@ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz")


def _valid(ch: str) -> bool:
    # isValidChar(x) == 1 in cleanevent.c (hostname_map in os_regex_maps.c)
    return ch in _HOSTNAME_CHARS


def _date_len(s: str) -> int:
    """Length of the date prefix OS_CleanMSG skips for syslog-like formats, or 0."""
    n = len(s) + 1  # loglen counts the terminating NUL
    g = lambda i: s[i] if i < len(s) else "\0"  # noqa: E731
    if n > 17 and g(3) == " " and g(6) == " " and g(9) == ":" and g(12) == ":" and g(15) == " ":
        return 16  # Dec 29 10:00:01
    if n > 24 and g(4) == "-" and g(7) == "-" and g(10) == " " and g(13) == ":" and g(16) == ":" and g(19) == ",":
        return 24  # 2015-04-16 21:51:02,805
    if n > 33 and g(4) == "-" and g(7) == "-" and g(10) == "T" and g(13) == ":" and g(16) == ":":
        if g(22) == ":" and g(25) == " ":
            return 26  # 2007-06-14T15:48:55-04:00
        if g(19) == ".":
            if g(26) == ":":
                return 30
            if g(29) == ":":
                return 33
            return 32
    if n > 21 and g(0).isdigit() and g(4) == " " and g(8) == " " and g(11) == " " and g(14) == ":" and g(17) == ":" and g(20) == " ":
        return 21  # 2015 Dec 29 10:00:01
    if (n > 33 and g(0).isdigit() and g(4) == "-" and g(7) == "-" and g(10) == " " and g(13) == ":"
            and g(16) == ":" and g(19) == "." and g(26) in "-+" and g(31) == " "):
        return 32  # 2021-04-21 10:16:09.404756-0700
    return 0


def predecode(line: str) -> Predecoded:
    raw = line
    envelope = None
    location = None
    offset = 0

    if raw.startswith("{") and '"full_log"' in raw:
        try:
            obj = json.loads(raw)
        except ValueError:
            obj = None
        if isinstance(obj, dict) and isinstance(obj.get("full_log"), str):
            location = obj.get("location") if isinstance(obj.get("location"), str) else None
            raw = obj["full_log"]
            envelope = "archives.json event (full_log)"

    if envelope is None:
        m = _ARCHIVE_RE.match(raw)
        if m:
            envelope = "Wazuh archive header"
            location = m.group(1)
            offset = m.end()
    m = _PRI_RE.match(raw, offset)
    if m:
        envelope = (envelope + " + " if envelope else "") + "syslog PRI (dropped by wazuh-remoted)"
        offset = m.end()

    result = Predecoded(raw_line=raw, event_offset=offset, envelope=envelope, location=location,
                        timestamp=None, hostname=None, program_name=None, log_offset=offset)
    s = raw[offset:]
    # "Mär" umlaut repair in cleanevent.c only matters for byte offsets; str is char-based.

    skip = _date_len(s)
    if skip:
        result.timestamp = (offset, offset + skip - 1)
        log = skip
        if log < len(s) and s[log] == " ":
            log += 1
        host_start = log
        p = host_start
        while p < len(s) and _valid(s[p]):
            p += 1
        if p < len(s) and s[p] == ":" and p + 1 < len(s) and s[p + 1] == " ":
            # Solaris without hostname: "Dec 29 10:00:01 sshd: msg"
            result.program_name = (offset + host_start, offset + p)
            log = p + 2
            result.log_offset = offset + log
        elif p >= len(s) or s[p] != " ":
            result.log_offset = offset + log  # invalid hostname: log stays after the date
        else:
            result.hostname = (offset + host_start, offset + p)
            log = p + 1
            result.log_offset = offset + log
            pn_start = log
            q = log
            while q < len(s) and _valid(s[q]):
                q += 1
            pieces: Optional[int] = None
            if q < len(s) and s[q] == ":":
                pieces = q + 1
                if pieces < len(s) and s[pieces] == " ":
                    pieces += 1
                result.program_name = (offset + pn_start, offset + q)
            elif q < len(s) and s[q] == "[" and q + 1 < len(s) and s[q + 1].isdigit():
                r = q + 2
                while r < len(s) and s[r].isdigit():
                    r += 1
                if r < len(s) and s[r] == "]" and r + 1 < len(s) and s[r + 1] == ":":
                    pieces = r + 2
                    if pieces < len(s) and s[pieces] == " ":
                        pieces += 1
                    result.program_name = (offset + pn_start, offset + q)
                elif r < len(s) and s[r] == "]" and r + 1 < len(s) and s[r + 1] == " ":
                    pieces = r + 2
                    result.program_name = (offset + pn_start, offset + q)
            elif q < len(s) and s[q] == "|" and q + 1 < len(s) and s[q + 1].islower():
                # AIX: "host auth|security:info sshd[1]: msg"
                r = q + 2
                while r < len(s) and s[r].isalnum():
                    r += 1
                if r < len(s) and s[r] == ":":
                    r += 1
                    while r < len(s) and s[r].isalnum():
                        r += 1
                    if r < len(s) and s[r] == " ":
                        r += 1
                        aix_start = r
                        while r < len(s) and _valid(s[r]):
                            r += 1
                        if s[r:r + 2] == ": ":
                            pieces = r + 2
                            result.program_name = (offset + aix_start, offset + r)
                        elif r < len(s) and s[r] == "[" and r + 1 < len(s) and s[r + 1].isdigit():
                            t = r + 2
                            while t < len(s) and s[t].isdigit():
                                t += 1
                            if s[t:t + 3] == "]: ":
                                pieces = t + 3
                                result.program_name = (offset + aix_start, offset + r)
            if pieces is not None:
                if s[pieces:pieces + 4] == "[ID ":
                    close = s.find("]", pieces + 4)
                    if close != -1:
                        pieces = close + 2
                result.log_offset = offset + min(pieces, len(s))
        return result

    # Other date formats: the timestamp is cut, no hostname / program_name.
    g = lambda i: s[i] if i < len(s) else "\0"  # noqa: E731
    n = len(s) + 1
    cut = 0
    if n > 28 and g(3) == " " and g(7) == " " and g(10) == " " and g(13) == ":" and g(16) == ":" \
            and g(19) == " " and g(24) == " " and g(26) == " ":
        cut = 25  # xferlog: Mon Apr 17 18:27:14 2006 1 64.160.42.130
    elif n > 24 and g(2) == "/" and g(5) == "-" and g(8) == ":" and g(11) == ":" and g(14) == "." and g(21) == " ":
        cut = 23  # snort: 01/28-09:13:16.240702  [**]
    elif n > 26 and g(2) == "/" and g(5) == "/" and g(10) == "-" and g(13) == ":" and g(16) == ":" \
            and g(19) == "." and g(26) == " ":
        cut = 28  # suricata: 01/28/1979-09:13:16.240702  [**]
    elif n > 27 and g(0) == "[" and g(4) == " " and g(8) == " " and g(11) == " " and g(14) == ":" \
            and g(17) == ":" and g(20) == " " and g(25) == "]":
        cut = 27  # apache: [Fri Feb 11 18:06:35 2004] [warn]
    elif n > 26 and g(0) == "[" and g(1) == "T" and g(5) == " " and g(10) == "." and g(13) == "." \
            and g(16) == " " and g(19) == ":":
        _asl(s, offset, result)  # macOS ASL: [Time ...] [Sender sshd] [Message ...] [Host h]
        return result
    elif (n > 32 and g(0) == "1" and g(1).isdigit() and g(2).isdigit() and g(3).isdigit() and g(10) == "."
          and g(13).isdigit() and g(14) == " " and (g(21) == " " or g(22) == " ")):
        cut = 14  # squid: 1140804070.368  11623 192.168.1.201 TCP_DENIED/400 ...
        while cut < len(s) and s[cut] == " ":
            cut += 1
    if cut:
        result.timestamp = (offset, offset + min(cut, len(s)))
        result.log_offset = offset + min(cut, len(s))
    return result


def _asl(s: str, offset: int, result: Predecoded) -> None:
    """cleanevent.c ASL branch: log += 25, then read [Sender], [Message] (once) and [Host] entries."""
    result.log_offset = offset + 25
    pos = s.find("[", 25)
    done_message = False
    while pos != -1:
        pos += 1
        if s.startswith("Sender ", pos) and result.program_name is None:
            close = s.find("]", pos + 7)
            if close == -1:
                break
            result.program_name = (offset + pos + 7, offset + close)
            pos = close + 1
        elif s.startswith("Message ", pos) and not done_message:
            done_message = True
            result.log_offset = offset + pos + 8
            close = s.find("]", pos + 8)
            if close == -1:
                break
            result.log_end = offset + close
            pos = close + 1
        elif s.startswith("Host ", pos):
            close = s.find("]", pos + 5)
            if close != -1:
                result.hostname = (offset + pos + 5, offset + close)
            break
        pos = s.find("[", pos)
