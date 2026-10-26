"""API data contract. ``frontend/src/types.ts`` mirrors this file - keep both in sync."""
from __future__ import annotations

from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class TokenState(str, Enum):
    HEADER = "HEADER"        # archive envelope / syslog header handled by the pre-decoder
    MATCHED = "MATCHED"      # consumed by a decoder (prematch / regex literal text, keys)
    CAPTURED = "CAPTURED"    # value stored in a decoded field
    TEST = "TEST"            # captured by a decoder run alone (not attached to the tree: Wazuh would reject it)
    MISSING = "MISSING"      # key / value no decoder extracts
    BROKEN = "BROKEN"        # a decoder targets this key but did not capture it on this line
    TEXT = "TEXT"            # other text no decoder consumed


class LogToken(BaseModel):
    text: str
    start: int
    end: int
    state: TokenState
    field: Optional[str] = None
    issue: Optional[int] = None  # index into AnalyzedLine.issues


class DecodedField(BaseModel):
    name: str
    value: str
    source: str  # predecoder | regex | json | windows | test (decoder run alone, outside the tree)
    decoder: Optional[str] = None  # XML name of the decoder that produced it
    decoder_uid: Optional[int] = None
    file: Optional[str] = None
    xml_line: Optional[int] = None
    start: Optional[int] = None  # span in raw_line (None when the value has no position)
    end: Optional[int] = None


class Suggestion(BaseModel):
    action: str  # add_decoder | replace_regex
    xml: str = ""
    regex: Optional[str] = None
    target_uid: Optional[int] = None  # replace_regex: decoder to patch
    insert_after: Optional[str] = None  # add_decoder: join the sibling chain of this decoder name
    parent: Optional[str] = None
    note: Optional[str] = None


class Issue(BaseModel):
    kind: str  # missing | broken | value | json
    key: Optional[str] = None
    value: str = ""
    value_kind: Optional[str] = None  # quoted | integer | token | ip | email | ...
    context: Optional[str] = None  # word before a free-text value
    start: Optional[int] = None
    end: Optional[int] = None
    reason: str = ""
    decoder: Optional[str] = None
    decoder_uid: Optional[int] = None
    decoder_file: Optional[str] = None
    decoder_line: Optional[int] = None
    decoder_regex: Optional[str] = None
    suggestion: Optional[Suggestion] = None


class TraceStep(BaseModel):
    decoder: str
    uid: Optional[int] = None
    file: Optional[str] = None
    line: Optional[int] = None
    step: str
    result: str  # match | no match | info
    detail: str = ""


class DecoderRef(BaseModel):
    name: str  # name Wazuh reports (children report the parent's name unless use_own_name)
    parent: Optional[str] = None
    xml_name: str
    uid: Optional[int] = None
    file: Optional[str] = None
    xml_line: Optional[int] = None
    builtin: bool = False
    test: bool = False  # a decoder outside the tree, run alone (Wazuh itself would reject it)


class LineCounts(BaseModel):
    fields: int = 0
    missing: int = 0
    broken: int = 0
    values: int = 0


class AnalyzedLine(BaseModel):
    line_number: int
    raw_line: str
    envelope: Optional[str] = None
    location: Optional[str] = None
    event_offset: int = 0
    log_offset: int = 0
    predecoded: Dict[str, str] = Field(default_factory=dict)
    status: str  # decoded | parent_only | no_decoder
    decoder: Optional[DecoderRef] = None
    fields: List[DecodedField] = Field(default_factory=list)
    issues: List[Issue] = Field(default_factory=list)
    tokens: List[LogToken] = Field(default_factory=list)
    trace: List[TraceStep] = Field(default_factory=list)
    counts: LineCounts = Field(default_factory=LineCounts)
    coverage_pct: float = 0.0
    new_decoder: Optional[Suggestion] = None  # root + children for a format no decoder handles


class DecoderInfo(BaseModel):
    uid: int
    name: str
    parent: Optional[str] = None
    file: str
    line: int
    program_name: Optional[str] = None
    prematch: Optional[str] = None
    prematch_offset: Optional[str] = None
    regex: Optional[str] = None
    regex_type: str = "osregex"
    regex_offset: Optional[str] = None
    order: List[str] = Field(default_factory=list)
    plugin: Optional[str] = None
    get_next: bool = False
    use_own_name: bool = False
    target_key: Optional[str] = None
    unanchored: bool = False
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)  # loaded, but this tool cannot emulate part of it
    standalone: bool = False  # rejected only for its place in the tree: still run alone to test it


class DecoderFile(BaseModel):
    name: str
    xml: str
    decoders: int
    errors: int


class DecoderTreeSummary(BaseModel):
    files: List[DecoderFile]
    decoders: List[DecoderInfo]
    errors: List[str]
    roots: int
    children: int
    invalid: int
    stock_json: bool = True  # Wazuh default JSON decoder added automatically when none is loaded


class FieldStat(BaseModel):
    name: str
    count: int
    samples: List[str]
    decoders: List[str]


class DecoderHit(BaseModel):
    uid: Optional[int] = None
    name: str
    file: Optional[str] = None
    line: Optional[int] = None
    lines: int


class GapItem(BaseModel):
    kind: str  # missing | broken | value | json
    key: str
    count: int
    lines: int
    samples: List[str]
    sample_lines: List[int]
    value_shape: str
    reason: str
    decoder: Optional[str] = None
    decoder_uid: Optional[int] = None
    decoder_file: Optional[str] = None
    decoder_line: Optional[int] = None
    suggestion: Optional[Suggestion] = None


class FormatItem(BaseModel):
    signature: str
    count: int
    sample_line: int
    sample: str
    program_name: Optional[str] = None
    keys: List[str] = Field(default_factory=list)
    suggestion: Optional[Suggestion] = None


class CorpusProfileReport(BaseModel):
    lines_scanned: int
    total_lines: int
    decoded_lines: int
    parent_only_lines: int
    no_decoder_lines: int
    avg_coverage_pct: float
    field_occurrences: int
    missing_occurrences: int
    decoders: List[DecoderHit]
    fields: List[FieldStat]
    gaps: List[GapItem]
    formats: List[FormatItem]
    generated_xml: str
    markdown_report: str
    elapsed_ms: int


class LogFileStats(BaseModel):
    path: str
    name: str
    file_size_bytes: int
    total_lines: int


class AppStateResponse(BaseModel):
    decoder_tree: DecoderTreeSummary
    log_file: LogFileStats
    corpus_profile: Optional[CorpusProfileReport] = None


class DecoderPatchRequest(BaseModel):
    action: str  # add_decoder | replace_regex
    xml: Optional[str] = None
    insert_after: Optional[str] = None
    parent: Optional[str] = None
    target_uid: Optional[int] = None
    regex: Optional[str] = None


class SingleLineRequest(BaseModel):
    raw_line: str
