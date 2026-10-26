"""Corpus-wide profile: which fields are decoded, what is missed, which log formats have no decoder.

Memory stays flat: only counters and a few samples per key are kept.  Identical
lines (common in forwarded syslog) are analysed once.
"""
from __future__ import annotations

import re
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .log_indexer import MmapLogIndexer
from .schemas import (
    AnalyzedLine,
    CorpusProfileReport,
    DecoderHit,
    FieldStat,
    FormatItem,
    GapItem,
)
from .span_engine import WazuhSpanEngine, scan_kv

_MASKS = [
    (re.compile(r"\"[^\"]*\""), '"…"'),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<ip>"),
    (re.compile(r"\b[0-9a-fA-F]{16,}\b"), "<hex>"),
    (re.compile(r"\d+"), "#"),
]
_DEDUPE_LIMIT = 50_000
_FORMAT_SAMPLES = 25  # distinct lines per no-decoder format used to build its decoder


@dataclass
class _Gap:
    kind: str
    key: str
    count: int = 0
    lines: int = 0
    samples: List[str] = field(default_factory=list)
    sample_lines: List[int] = field(default_factory=list)
    shapes: set = field(default_factory=set)
    first_line: int = 0
    first_raw: str = ""
    reason: str = ""
    decoder: Optional[str] = None
    decoder_uid: Optional[int] = None
    decoder_file: Optional[str] = None
    decoder_line: Optional[int] = None


def signature(line: AnalyzedLine) -> Tuple[str, Optional[str], List[str]]:
    """Group key for a line no decoder handled: program name, else its first keys / masked words."""
    program = line.predecoded.get("program_name")
    log = line.raw_line[line.log_offset:]
    keys = [kv.key for kv in scan_kv(log, 0, len(log), program)][:40]
    if program:
        return f"program_name: {program}", program, keys
    if log.lstrip().startswith("{"):
        return "JSON: " + ", ".join(m.group(1) for m in re.finditer(r'"([^"]+)"\s*:', log[:400]))[:120], None, keys
    if len(keys) >= 3:
        return "key=value: " + " ".join(k + "=" for k in keys[:5]), None, keys
    text = " ".join(log.split()[:6])
    for pattern, repl in _MASKS:
        text = pattern.sub(repl, text)
    return "text: " + text[:120], None, keys


class CorpusGapProfiler:
    def __init__(self, engine: WazuhSpanEngine, indexer: MmapLogIndexer):
        self.engine = engine
        self.indexer = indexer

    def run(self, max_lines: Optional[int] = 20_000) -> CorpusProfileReport:
        started = time.perf_counter()
        total = self.indexer.total_lines
        target = total if not max_lines or max_lines > total else max_lines

        statuses: Counter = Counter()
        decoders: Dict[Tuple, int] = Counter()
        fields: Dict[str, Tuple[int, List[str], set]] = {}
        gaps: Dict[Tuple[str, str], _Gap] = {}
        formats: Dict[str, Dict] = {}
        coverage_sum = 0.0
        field_occ = missing_occ = 0
        cache: Dict[str, AnalyzedLine] = {}
        scanned = 0

        for line_no, text in self.indexer.iter_lines(0, target):
            scanned += 1
            res = cache.get(text)
            if res is None:
                res = self.engine.analyze(text, line_no, detail=False)
                if len(cache) < _DEDUPE_LIMIT:
                    cache[text] = res
            statuses[res.status] += 1
            coverage_sum += res.coverage_pct
            if res.decoder:
                decoders[(res.decoder.uid, res.decoder.xml_name, res.decoder.file, res.decoder.xml_line)] += 1
            else:
                sig, program, keys = signature(res)
                entry = formats.setdefault(sig, {"count": 0, "line": line_no, "sample": res.raw_line,
                                                 "program": program, "keys": keys, "raws": []})
                entry["count"] += 1
                if len(entry["raws"]) < _FORMAT_SAMPLES and text not in entry["raws"]:
                    entry["raws"].append(text)  # the generated decoder learns from these

            for f in res.fields:
                if f.source == "predecoder":
                    continue
                field_occ += 1
                count, samples, decs = fields.get(f.name, (0, [], set()))
                if f.value not in samples and len(samples) < 5:
                    samples.append(f.value)
                if f.decoder:
                    decs.add(f.decoder)
                fields[f.name] = (count + 1, samples, decs)

            seen_keys = set()
            for issue in res.issues:
                if issue.kind == "value":
                    key = f"{issue.value_kind}" + (f" after '{issue.context}'" if issue.context else "")
                else:
                    key = issue.key or "?"
                missing_occ += 1
                gap = gaps.get((issue.kind, key))
                if gap is None:
                    gap = gaps[(issue.kind, key)] = _Gap(
                        kind=issue.kind, key=key, first_line=line_no, first_raw=text, reason=issue.reason,
                        decoder=issue.decoder, decoder_uid=issue.decoder_uid, decoder_file=issue.decoder_file,
                        decoder_line=issue.decoder_line)
                gap.count += 1
                if issue.value_kind:
                    gap.shapes.add(issue.value_kind)
                if issue.value not in gap.samples and len(gap.samples) < 5:
                    gap.samples.append(issue.value[:200])
                if (issue.kind, key) not in seen_keys:
                    seen_keys.add((issue.kind, key))
                    gap.lines += 1
                    if len(gap.sample_lines) < 10:
                        gap.sample_lines.append(line_no)

        gap_items = [self._gap_item(g) for g in gaps.values()]
        order = {"broken": 0, "missing": 1, "json": 2, "value": 3}
        gap_items.sort(key=lambda g: (order.get(g.kind, 9), -g.count, g.key.lower()))
        field_items = sorted(
            (FieldStat(name=n, count=c, samples=s, decoders=sorted(d)) for n, (c, s, d) in fields.items()),
            key=lambda f: (-f.count, f.name))
        decoder_items = [DecoderHit(uid=k[0], name=k[1], file=k[2], line=k[3], lines=v)
                         for k, v in sorted(decoders.items(), key=lambda kv: -kv[1])]
        format_items = [FormatItem(signature=s, count=v["count"], sample_line=v["line"], sample=v["sample"][:2000],
                                   program_name=v["program"], keys=v["keys"],
                                   suggestion=self.engine.format_suggestion(v["raws"]))
                        for s, v in sorted(formats.items(), key=lambda kv: -kv[1]["count"])[:100]]

        report = CorpusProfileReport(
            lines_scanned=scanned, total_lines=total,
            decoded_lines=statuses["decoded"], parent_only_lines=statuses["parent_only"],
            no_decoder_lines=statuses["no_decoder"],
            avg_coverage_pct=round(coverage_sum / scanned, 2) if scanned else 0.0,
            field_occurrences=field_occ, missing_occurrences=missing_occ,
            decoders=decoder_items, fields=field_items, gaps=gap_items, formats=format_items,
            generated_xml="", markdown_report="", elapsed_ms=0,
        )
        report.generated_xml = self._generated_xml(report)
        report.markdown_report = self._markdown(report)
        report.elapsed_ms = int((time.perf_counter() - started) * 1000)
        return report

    def _gap_item(self, gap: _Gap) -> GapItem:
        suggestion = None
        if gap.kind in ("missing", "broken", "json"):
            # Re-run the first line with full detail once per key to get its fix.
            detailed = self.engine.analyze(gap.first_raw, gap.first_line, detail=True)
            for issue in detailed.issues:
                if issue.kind == gap.kind and (issue.key or "?") == gap.key:
                    suggestion = issue.suggestion
                    break
        shape = next(iter(gap.shapes)) if len(gap.shapes) == 1 else ("mixed" if gap.shapes else "")
        return GapItem(kind=gap.kind, key=gap.key, count=gap.count, lines=gap.lines, samples=gap.samples,
                       sample_lines=gap.sample_lines, value_shape=shape, reason=gap.reason, decoder=gap.decoder,
                       decoder_uid=gap.decoder_uid, decoder_file=gap.decoder_file, decoder_line=gap.decoder_line,
                       suggestion=suggestion)

    @staticmethod
    def _generated_xml(report: CorpusProfileReport) -> str:
        parts: List[str] = ["<!-- Generated decoders: review before installing. -->"]
        seen = set()
        for fmt in report.formats:
            if fmt.suggestion and fmt.suggestion.xml not in seen:
                seen.add(fmt.suggestion.xml)
                parts.append(f"<!-- format with no decoder ({fmt.count} lines): {fmt.signature} -->\n"
                             + fmt.suggestion.xml)
        for gap in report.gaps:
            s = gap.suggestion
            if s is None:
                continue
            if s.action == "replace_regex":
                text = (f"<!-- {gap.kind} '{gap.key}': in {gap.decoder_file}:{gap.decoder_line} "
                        f"('{gap.decoder}') replace the regex with: {s.regex} -->")
            else:
                text = s.xml
            if text and text not in seen:
                seen.add(text)
                parts.append(text)
        return "\n\n".join(parts) + "\n"

    @staticmethod
    def _markdown(r: CorpusProfileReport) -> str:
        pct = lambda n: f"{n / r.lines_scanned * 100:.1f}%" if r.lines_scanned else "0%"  # noqa: E731
        escape = lambda t: str(t).replace("|", "\\|").replace("\n", " ")  # noqa: E731
        out = [
            "# Decoder coverage report", "",
            f"- Lines profiled: **{r.lines_scanned:,}** of {r.total_lines:,}",
            f"- Decoded: **{r.decoded_lines:,}** ({pct(r.decoded_lines)}) · parent only: {r.parent_only_lines:,} · "
            f"no decoder: **{r.no_decoder_lines:,}** ({pct(r.no_decoder_lines)})",
            f"- Average field coverage per line: **{r.avg_coverage_pct:.1f}%**",
            f"- Decoded field values: {r.field_occurrences:,} · values not decoded: {r.missing_occurrences:,}", "",
            "## Not decoded", "",
            "| Kind | Key / value | Occurrences | Lines | Samples | Reason |",
            "|---|---|---:|---:|---|---|",
        ]
        for g in r.gaps:
            samples = ", ".join(f"`{escape(s[:60])}`" for s in g.samples[:3])
            out.append(f"| {g.kind} | `{escape(g.key)}` | {g.count:,} | {g.lines:,} | {samples} | {escape(g.reason)} |")
        if r.formats:
            out += ["", "## Log formats with no decoder", "", "| Lines | Format | First line |", "|---:|---|---:|"]
            for f in r.formats:
                out.append(f"| {f.count:,} | `{escape(f.signature)}` | {f.sample_line} |")
        out += ["", "## Decoded fields", "", "| Field | Occurrences | Samples |", "|---|---:|---|"]
        for f in r.fields:
            out.append(f"| `{escape(f.name)}` | {f.count:,} | " + ", ".join(f"`{escape(s[:60])}`" for s in f.samples[:3]) + " |")
        out += ["", "## Suggested decoder changes", "", "```xml", r.generated_xml.rstrip(), "```", ""]
        return "\n".join(out)
