import { useCallback, useEffect, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { api } from "../api";
import type { AnalyzedLine, FilterMode } from "../types";
import { TOKEN_CLASS, cn, formatNumber } from "../ui";
import LogLine from "./LogLine";

const CHUNK = 100;
const PAGE = 200;

interface Props {
  totalLines: number;
  filter: FilterMode;
  filterKey: string | null;
  reloadToken: number;
  selected: number | null;
  onSelect: (line: AnalyzedLine) => void;
}

/** Virtualized log view: plain mode pages 100-line chunks; filter mode asks the server to scan. */
export default function LogList({ totalLines, filter, filterKey, reloadToken, selected, onSelect }: Props) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const generation = useRef(0);
  const requested = useRef(new Set<number>());
  const [rows, setRows] = useState<Record<number, AnalyzedLine>>({});
  const [filtered, setFiltered] = useState<AnalyzedLine[]>([]);
  const [hasMore, setHasMore] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isFiltered = filter !== "all" || Boolean(filterKey);
  const count = isFiltered ? filtered.length : totalLines;
  const virtualizer = useVirtualizer({
    count,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => 48,
    overscan: 10,
  });

  const loadChunk = useCallback(async (start: number) => {
    if (requested.current.has(start)) return;
    requested.current.add(start);
    const gen = generation.current;
    try {
      const lines = await api.chunk(start, CHUNK, "all", null);
      if (gen !== generation.current) return;
      setRows((prev) => {
        const next = { ...prev };
        for (const line of lines) next[line.line_number] = line;
        return next;
      });
    } catch (cause) {
      requested.current.delete(start);
      if (gen === generation.current) setError((cause as Error).message);
    }
  }, []);

  const loadFiltered = useCallback(
    async (start: number, append: boolean) => {
      const gen = generation.current;
      setLoading(true);
      try {
        const lines = await api.chunk(start, PAGE, filter, filterKey);
        if (gen !== generation.current) return;
        setFiltered((prev) => (append ? [...prev, ...lines] : lines));
        setHasMore(lines.length === PAGE);
      } catch (cause) {
        if (gen === generation.current) setError((cause as Error).message);
      } finally {
        if (gen === generation.current) setLoading(false);
      }
    },
    [filter, filterKey],
  );

  useEffect(() => {
    generation.current += 1;
    requested.current = new Set();
    setRows({});
    setFiltered([]);
    setHasMore(false);
    setError(null);
    virtualizer.scrollToOffset(0);
    if (isFiltered) void loadFiltered(0, false);
    else if (totalLines > 0) void loadChunk(0);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filter, filterKey, reloadToken, totalLines]);

  const items = virtualizer.getVirtualItems();
  const first = items[0]?.index ?? 0;
  const last = items[items.length - 1]?.index ?? 0;
  useEffect(() => {
    if (isFiltered || totalLines === 0) return;
    for (let s = Math.floor(first / CHUNK) * CHUNK; s <= last; s += CHUNK) void loadChunk(s);
  }, [first, last, isFiltered, totalLines, loadChunk, reloadToken]);

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      {error ? (
        <div className="border-b border-bad/20 bg-bad/[0.07] px-4 py-2 text-xs text-bad">{error}</div>
      ) : null}
      <div ref={scrollRef} className="relative min-h-0 flex-1 overflow-y-auto bg-canvas">
        {count === 0 ? (
          <div className="p-12 text-center text-sm text-fg-muted">
            {loading
              ? "Scanning the log…"
              : totalLines === 0
                ? "No log file is open."
                : "No line matches this filter in the scanned range."}
          </div>
        ) : (
          <div style={{ height: virtualizer.getTotalSize() }} className="relative w-full">
            {items.map((item) => {
              const line = isFiltered ? filtered[item.index] : rows[item.index + 1];
              return (
                <div
                  key={item.key}
                  data-index={item.index}
                  ref={virtualizer.measureElement}
                  className="absolute left-0 top-0 w-full"
                  style={{ transform: `translateY(${item.start}px)` }}
                >
                  {line ? (
                    <Row line={line} selected={selected === line.line_number} onSelect={onSelect} />
                  ) : (
                    <div className="flex h-12 items-center border-b border-line-muted pl-2 font-mono text-[11px] text-fg-subtle">
                      {item.index + 1}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
      <div className="flex h-8 shrink-0 items-center gap-4 border-t border-line-muted bg-surface px-4 text-xs text-fg-muted">
        <span className="tabular-nums">
          {isFiltered
            ? `${formatNumber(filtered.length)} matching line${filtered.length === 1 ? "" : "s"}`
            : `${formatNumber(totalLines)} lines`}
        </span>
        <span className="ml-auto flex items-center gap-3 font-mono text-[11px]">
          {LEGEND.map(([s, label]) => (
            <span key={s} className={cn("px-0.5", TOKEN_CLASS[s])}>
              {label}
            </span>
          ))}
        </span>
        {isFiltered && hasMore ? (
          <button
            className="btn-link"
            disabled={loading}
            onClick={() => void loadFiltered(filtered[filtered.length - 1]?.line_number ?? 0, true)}
          >
            {loading ? "Loading…" : "Load more"}
          </button>
        ) : null}
      </div>
    </div>
  );
}

const STATUS_LABEL = { decoded: "", parent_only: "parent only", no_decoder: "no decoder" } as const;

const LEGEND: Array<[keyof typeof TOKEN_CLASS, string]> = [
  ["CAPTURED", "decoded"],
  ["TEST", "tested alone"],
  ["MISSING", "not decoded"],
  ["BROKEN", "broken"],
];

function Row({ line, selected, onSelect }: { line: AnalyzedLine; selected: boolean; onSelect: (l: AnalyzedLine) => void }) {
  const problems = line.counts.missing + line.counts.broken + line.counts.values;
  const test = line.decoder?.test;
  return (
    <div
      role="button"
      tabIndex={0}
      onClick={() => onSelect(line)}
      onKeyDown={(event) => event.key === "Enter" && onSelect(line)}
      className={cn(
        "grid cursor-pointer grid-cols-[48px_168px_1fr] gap-4 border-b border-line-muted py-2 pl-2 pr-4 transition-colors hover:bg-surface",
        selected && "bg-raised shadow-[inset_2px_0_0_#ecebe8] hover:bg-raised",
      )}
    >
      <span className="pt-px text-right font-mono text-[11px] tabular-nums text-fg-subtle">{line.line_number}</span>
      <span className="min-w-0 text-[11.5px] leading-[18px]">
        <span
          className={cn(
            "flex items-center gap-1.5 truncate font-medium",
            test ? "text-test" : line.status === "decoded" ? "text-fg" : "text-bad",
          )}
          title={line.decoder ? `${line.decoder.xml_name} (${line.decoder.file}:${line.decoder.xml_line})` : undefined}
        >
          <span className="truncate">{line.decoder?.name ?? STATUS_LABEL[line.status]}</span>
          {test ? <span className="badge h-4 shrink-0 bg-test/15 px-1 text-[9px] text-test">test</span> : null}
        </span>
        <span className="block text-fg-muted">
          {line.counts.fields} fields
          {problems ? <span className="text-warn"> · {problems} not decoded</span> : null}
          {line.status === "parent_only" ? " · parent only" : ""}
        </span>
      </span>
      <LogLine line={line} />
    </div>
  );
}
