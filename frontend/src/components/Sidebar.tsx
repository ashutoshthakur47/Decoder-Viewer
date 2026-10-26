import { useState } from "react";
import { ChevronRight } from "lucide-react";
import type { AppStateResponse, FilterMode, GapItem, Suggestion } from "../types";
import { KIND_META, cn, formatNumber } from "../ui";
import SuggestionBox from "./SuggestionBox";

type Tab = "gaps" | "fields" | "decoders" | "formats";

interface Props {
  state: AppStateResponse;
  activeKey: string | null;
  busy: boolean;
  onFilter: (filter: FilterMode, key: string | null) => void;
  onApply: (suggestion: Suggestion) => void;
  onCopy: (text: string) => void;
}

const FILTER_OF: Record<GapItem["kind"], FilterMode> = {
  missing: "missing",
  json: "missing",
  value: "missing",
  broken: "broken",
};

/** Corpus view: what is not decoded, what is, and which decoders / formats show up. */
export default function Sidebar({ state, activeKey, busy, onFilter, onApply, onCopy }: Props) {
  const [tab, setTab] = useState<Tab>("gaps");
  const profile = state.corpus_profile;
  const tree = state.decoder_tree;
  const tabs: Array<[Tab, string, number]> = [
    ["gaps", "Not decoded", profile?.gaps.length ?? 0],
    ["fields", "Fields", profile?.fields.length ?? 0],
    ["decoders", "Decoders", profile?.decoders.length ?? 0],
    ["formats", "No decoder", profile?.formats.length ?? 0],
  ];

  return (
    <aside className="flex h-full w-full flex-col border-r border-line-muted bg-surface">
      <nav className="grid shrink-0 grid-cols-4 border-b border-line-muted">
        {tabs.map(([id, label, count]) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={cn(
              "-mb-px border-b-[1.5px] px-2.5 py-2 text-left transition-colors hover:bg-raised/50",
              tab === id ? "border-fg" : "border-transparent",
            )}
          >
            <span className={cn("block font-mono text-sm tabular-nums", tab === id ? "text-fg" : "text-fg-muted")}>{count}</span>
            <span className={cn("label block whitespace-nowrap", tab === id && "text-fg-soft")}>{label}</span>
          </button>
        ))}
      </nav>

      <div className="min-h-0 flex-1 overflow-y-auto">
        {!profile ? (
          <p className="p-4 text-xs text-fg-muted">Open a log to profile it.</p>
        ) : tab === "gaps" ? (
          profile.gaps.length ? (
            <ul>
              {profile.gaps.map((gap) => (
                <GapRow
                  key={`${gap.kind}:${gap.key}`}
                  gap={gap}
                  active={activeKey === gap.key}
                  busy={busy}
                  onFilter={onFilter}
                  onApply={onApply}
                  onCopy={onCopy}
                />
              ))}
            </ul>
          ) : (
            <p className="p-4 text-xs text-ok">Nothing left undecoded in the profiled lines.</p>
          )
        ) : tab === "fields" ? (
          <table className="w-full text-xs">
            <thead className="sticky top-0 border-b border-line-muted bg-surface text-left text-[11px] text-fg-muted">
              <tr>
                <th className="px-3 py-1.5 font-medium">Field</th>
                <th className="px-3 py-1.5 text-right font-medium">Lines</th>
              </tr>
            </thead>
            <tbody>
              {profile.fields.map((f) => (
                <tr
                  key={f.name}
                  className={cn("cursor-pointer border-t border-line-muted hover:bg-raised", activeKey === f.name && "bg-raised")}
                  onClick={() => onFilter("all", f.name)}
                  title={`samples: ${f.samples.join(" | ")}\ndecoders: ${f.decoders.join(", ")}`}
                >
                  <td className="px-3 py-1.5">
                    <span className="block truncate font-mono text-fg">{f.name}</span>
                    <span className="block truncate font-mono text-[11px] text-fg-muted">{f.samples.join(" · ")}</span>
                  </td>
                  <td className="px-3 py-1.5 text-right tabular-nums text-fg-muted">{formatNumber(f.count)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : tab === "decoders" ? (
          <div className="text-xs">
            {tree.invalid || tree.errors.length ? (
              <div className="m-3 rounded-lg border border-bad/25 bg-bad/[0.07] p-3 text-bad">
                <p className="font-medium">Wazuh would refuse to load {tree.invalid} decoder(s):</p>
                <ul className="mt-1.5 space-y-1.5">
                  {tree.decoders
                    .filter((d) => d.errors.length)
                    .slice(0, 30)
                    .map((d) => (
                      <li key={d.uid} className="break-all">
                        <span className="font-mono">{d.name}</span> ({d.file}:{d.line})
                        {d.standalone ? <span className="text-test"> · tested alone</span> : null} — {d.errors.join("; ")}
                      </li>
                    ))}
                  {tree.errors.slice(0, 10).map((e) => (
                    <li key={e} className="break-all">{e}</li>
                  ))}
                </ul>
              </div>
            ) : null}
            <table className="w-full">
              <thead className="sticky top-0 border-b border-line-muted bg-surface text-left text-[11px] text-fg-muted">
                <tr>
                  <th className="px-3 py-1.5 font-medium">Decoder that matched</th>
                  <th className="px-3 py-1.5 text-right font-medium">Lines</th>
                </tr>
              </thead>
              <tbody>
                {profile.decoders.map((d) => (
                  <tr key={`${d.uid}:${d.name}`} className="border-t border-line-muted">
                    <td className="px-3 py-1.5">
                      <span className="block truncate font-mono text-fg">{d.name}</span>
                      <span className="block text-[11px] text-fg-muted">{d.file ? `${d.file}:${d.line}` : "built in"}</span>
                    </td>
                    <td className="px-3 py-1.5 text-right tabular-nums text-fg-muted">{formatNumber(d.lines)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : profile.formats.length ? (
          <ul className="text-xs">
            {profile.formats.map((f) => (
              <li key={f.signature} className="border-b border-line-muted px-3 py-2">
                <div className="flex items-baseline justify-between gap-2">
                  <span className="min-w-0 break-all font-mono text-fg">{f.signature}</span>
                  <span className="shrink-0 tabular-nums text-fg-muted">{formatNumber(f.count)}</span>
                </div>
                <p className="mt-1 line-clamp-2 break-all font-mono text-[11px] text-fg-muted">{f.sample}</p>
                {f.suggestion ? (
                  <details className="mt-2">
                    <summary className="cursor-pointer text-xs font-medium text-fg">Generated decoder for this format</summary>
                    <div className="mt-2">
                      <SuggestionBox suggestion={f.suggestion} busy={busy} onApply={onApply} onCopy={onCopy} />
                    </div>
                  </details>
                ) : null}
                <button className="btn-link mt-1" onClick={() => onFilter("no_decoder", null)}>
                  Show lines without a decoder
                </button>
              </li>
            ))}
          </ul>
        ) : (
          <p className="p-4 text-xs text-ok">Every profiled line matched a decoder.</p>
        )}
      </div>
    </aside>
  );
}

function GapRow({
  gap,
  active,
  busy,
  onFilter,
  onApply,
  onCopy,
}: {
  gap: GapItem;
  active: boolean;
  busy: boolean;
  onFilter: (filter: FilterMode, key: string | null) => void;
  onApply: (s: Suggestion) => void;
  onCopy: (text: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const meta = KIND_META[gap.kind];
  // Free-text value groups ("ip after 'from'") filter on the value kind.
  const filterKey = gap.kind === "value" ? gap.key.split(" ")[0] : gap.key;
  const showLines = (
    <button className="btn" onClick={() => onFilter(FILTER_OF[gap.kind], filterKey)}>
      Show lines
    </button>
  );
  return (
    <li className={cn("border-b border-line-muted", active && "bg-raised")}>
      <button className="flex w-full items-center gap-2 px-3 py-2 text-left hover:bg-raised" onClick={() => setOpen(!open)}>
        <ChevronRight className={cn("h-3.5 w-3.5 shrink-0 text-fg-muted transition-transform", open && "rotate-90")} />
        <span className={cn("badge shrink-0", meta.badge)} title={meta.help}>
          {meta.label}
        </span>
        <span className="min-w-0 flex-1 truncate font-mono text-xs text-fg">{gap.key}</span>
        <span className="shrink-0 text-xs tabular-nums text-fg-muted" title="occurrences / lines">
          {formatNumber(gap.lines)}
        </span>
      </button>
      {open ? (
        <div className="space-y-2 px-3 pb-3 pl-8 text-xs">
          <p className="leading-5 text-fg-muted">{gap.reason}</p>
          <p className="text-fg-muted">
            {formatNumber(gap.count)} occurrences on {formatNumber(gap.lines)} lines
            {gap.value_shape ? ` · ${gap.value_shape}` : ""}
          </p>
          {gap.samples.length ? (
            <div className="flex flex-wrap gap-1">
              {gap.samples.map((v) => (
                <code key={v} className="max-w-full truncate rounded bg-raised px-1.5 py-0.5 text-[11px] text-fg-soft">
                  {v}
                </code>
              ))}
            </div>
          ) : null}
          {gap.suggestion ? (
            <SuggestionBox
              suggestion={gap.suggestion}
              busy={busy}
              onApply={onApply}
              onCopy={onCopy}
              extra={showLines}
            />
          ) : (
            showLines
          )}
        </div>
      ) : null}
    </li>
  );
}
