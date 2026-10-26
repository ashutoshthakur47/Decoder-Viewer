/** API contract. Mirrors backend/app/schemas.py - keep both in sync. */

export type TokenState = "HEADER" | "MATCHED" | "CAPTURED" | "MISSING" | "BROKEN" | "TEST" | "TEXT";

export interface LogToken {
  text: string;
  start: number;
  end: number;
  state: TokenState;
  field?: string | null;
  issue?: number | null;
}

export interface DecodedField {
  name: string;
  value: string;
  source: "predecoder" | "regex" | "json" | "windows" | "test";
  decoder?: string | null;
  decoder_uid?: number | null;
  file?: string | null;
  xml_line?: number | null;
  start?: number | null;
  end?: number | null;
}

export interface Suggestion {
  action: "add_decoder" | "replace_regex";
  xml: string;
  regex?: string | null;
  target_uid?: number | null;
  insert_after?: string | null;
  parent?: string | null;
  note?: string | null;
}

export type IssueKind = "missing" | "broken" | "value" | "json";

export interface Issue {
  kind: IssueKind;
  key?: string | null;
  value: string;
  value_kind?: string | null;
  context?: string | null;
  start?: number | null;
  end?: number | null;
  reason: string;
  decoder?: string | null;
  decoder_uid?: number | null;
  decoder_file?: string | null;
  decoder_line?: number | null;
  decoder_regex?: string | null;
  suggestion?: Suggestion | null;
}

export interface TraceStep {
  decoder: string;
  uid?: number | null;
  file?: string | null;
  line?: number | null;
  step: string;
  result: "match" | "no match" | "info";
  detail: string;
}

export interface DecoderRef {
  name: string;
  parent?: string | null;
  xml_name: string;
  uid?: number | null;
  file?: string | null;
  xml_line?: number | null;
  builtin: boolean;
  test?: boolean; // decoder outside the tree, run alone (Wazuh would reject it)
}

export interface AnalyzedLine {
  line_number: number;
  raw_line: string;
  envelope?: string | null;
  location?: string | null;
  event_offset: number;
  log_offset: number;
  predecoded: Record<string, string>;
  status: "decoded" | "parent_only" | "no_decoder";
  decoder?: DecoderRef | null;
  fields: DecodedField[];
  issues: Issue[];
  tokens: LogToken[];
  trace: TraceStep[];
  counts: { fields: number; missing: number; broken: number; values: number };
  coverage_pct: number;
  new_decoder?: Suggestion | null;
}

export interface DecoderInfo {
  uid: number;
  name: string;
  parent?: string | null;
  file: string;
  line: number;
  program_name?: string | null;
  prematch?: string | null;
  regex?: string | null;
  regex_type: string;
  order: string[];
  plugin?: string | null;
  get_next: boolean;
  errors: string[];
  warnings: string[];
  standalone: boolean; // rejected only for its place in the tree: still run alone
}

export interface DecoderFile {
  name: string;
  xml: string;
  decoders: number;
  errors: number;
}

export interface DecoderTreeSummary {
  files: DecoderFile[];
  decoders: DecoderInfo[];
  errors: string[];
  roots: number;
  children: number;
  invalid: number;
  stock_json: boolean;
}

export interface FieldStat {
  name: string;
  count: number;
  samples: string[];
  decoders: string[];
}

export interface DecoderHit {
  uid?: number | null;
  name: string;
  file?: string | null;
  line?: number | null;
  lines: number;
}

export interface GapItem {
  kind: IssueKind;
  key: string;
  count: number;
  lines: number;
  samples: string[];
  sample_lines: number[];
  value_shape: string;
  reason: string;
  decoder?: string | null;
  decoder_file?: string | null;
  decoder_line?: number | null;
  suggestion?: Suggestion | null;
}

export interface FormatItem {
  signature: string;
  count: number;
  sample_line: number;
  sample: string;
  program_name?: string | null;
  keys: string[];
  suggestion?: Suggestion | null;
}

export interface CorpusProfileReport {
  lines_scanned: number;
  total_lines: number;
  decoded_lines: number;
  parent_only_lines: number;
  no_decoder_lines: number;
  avg_coverage_pct: number;
  field_occurrences: number;
  missing_occurrences: number;
  decoders: DecoderHit[];
  fields: FieldStat[];
  gaps: GapItem[];
  formats: FormatItem[];
  generated_xml: string;
  markdown_report: string;
  elapsed_ms: number;
}

export interface LogFileStats {
  path: string;
  name: string;
  file_size_bytes: number;
  total_lines: number;
}

export interface AppStateResponse {
  decoder_tree: DecoderTreeSummary;
  log_file: LogFileStats;
  corpus_profile?: CorpusProfileReport | null;
}

export type FilterMode = "all" | "missing" | "broken" | "no_decoder";

export interface PatchRequest {
  action: "add_decoder" | "replace_regex";
  xml?: string;
  insert_after?: string | null;
  parent?: string | null;
  target_uid?: number | null;
  regex?: string | null;
}
