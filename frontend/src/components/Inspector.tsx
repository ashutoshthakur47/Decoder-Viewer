import { useState } from "react";
import { X } from "lucide-react";
import type { AnalyzedLine, Issue, Suggestion } from "../types";
import { KIND_META, STOCK_SUFFIX, cn } from "../ui";
import LogLine from "./LogLine";
import SuggestionBox from "./SuggestionBox";

interface Props {
  line: AnalyzedLine;
  busy: boolean;
  onClose: () => void;
  onApply: (suggestion: Suggestion) => void;
  onCopy: (text: string) => void;
}

/** Everything about one line: what Wazuh pre-decodes, decodes, and what it leaves behind. */
export default function Inspector({ line, busy, onClose, onApply, onCopy }: Props) {
  const [focus, setFocus] = useState<number | null>(null);
  const [showTrace, setShowTrace] = useState(false);
  const decoded = line.fields.filter((f) => f.source !== "predecoder");
  const dec = line.decoder;

  return (
    <aside className="flex h-full w-full flex-col border-l border-line-muted bg-surface">
      <header className="flex h-12 shrink-0 items-center gap-3 border-b border-line-muted px-4">
        <h2 className="text-sm font-semibold text-fg">{line.line_number ? `Line ${line.line_number}` : "Tested line"}</h2>
        <span className="h-1 w-16 overflow-hidden rounded-full bg-line" title={`${line.coverage_pct}% of the values are decoded`}>
          <span className="block h-full rounded-full bg-ok" style={{ width: `${line.coverage_pct}%` }} />
        </span>
        <span className="font-mono text-xs tabular-nums text-fg-muted">{line.coverage_pct}%</span>
        <button className="icon-btn ml-auto" onClick={onClose} title="Close">
          <X className="h-4 w-4" />
        </button>
      </header>

      <div className="min-h-0 flex-1 space-y-6 overflow-y-auto p-4">
        <div className="panel p-3">
          <LogLine line={line} onIssue={setFocus} />
        </div>

        <Section title="Decoder">
          {dec ? (
            <p className="mb-3 text-xs leading-5 text-fg-muted">
              <b className={cn("font-mono font-medium", dec.test ? "text-test" : "text-fg")}>{dec.name}</b>
              {dec.test ? (
                <> · tested alone: no parent in the loaded set, so Wazuh rejects it until one is loaded</>
              ) : (
                <>
                  {dec.parent ? <> · parent <span className="font-mono">{dec.parent}</span></> : null}
                  {dec.builtin
                    ? " · built into Wazuh"
                    : dec.file?.endsWith(STOCK_SUFFIX)
                      ? " · Wazuh's default JSON decoder, added because no loaded file reads JSON (every manager has it). " +
                        "It decodes every JSON key; untick it in Decoders to test only your own decoders."
                      : ` · ${dec.xml_name === dec.name ? "" : dec.xml_name + " "}(${dec.file}:${dec.xml_line})`}
                </>
              )}
            </p>
          ) : (
            <p className="mb-3 text-xs leading-5 text-fg-muted">
              <b className="font-medium text-bad">No decoder matched this line</b>
              {": " + (line.trace.find((t) => t.step === "result")?.detail ?? "")}. Open the trace to see each
              prematch that was tried.
            </p>
          )}
          <KeyValues
            rows={[
              ...(["timestamp", "hostname", "program_name"] as const).map(
                (k) => [k, line.predecoded[k], "header"] as [string, string | undefined, string],
              ),
              ...decoded.map((f) => [f.name, f.value, f.source === "test" ? "test" : ""] as [string, string, string]),
            ]}
          />
        </Section>

        {line.new_decoder ? (
          <Section title="Suggested decoder">
            <SuggestionBox suggestion={line.new_decoder} busy={busy} onApply={onApply} onCopy={onCopy} />
          </Section>
        ) : null}

        <Section title={`Not decoded · ${line.issues.length}`}>
          {line.issues.length === 0 ? (
            <p className="text-xs text-ok">Every value on this line is decoded.</p>
          ) : (
            <ul className="space-y-2">
              {line.issues.map((issue, index) => (
                <IssueCard key={index} issue={issue} focused={focus === index} busy={busy} onApply={onApply} onCopy={onCopy} />
              ))}
            </ul>
          )}
        </Section>

        <Section
          title="Trace"
          action={
            <button className="btn-link" onClick={() => setShowTrace((v) => !v)}>
              {showTrace ? "Hide" : `Show ${line.trace.length} steps`}
            </button>
          }
        >
          {showTrace ? (
            <ol className="space-y-1.5 text-[11px]">
              {line.trace.map((step, i) => (
                <li key={i} className="grid grid-cols-[60px_1fr] gap-2">
                  <span
                    className={cn(
                      "font-medium",
                      step.result === "match" ? "text-ok" : step.result === "no match" ? "text-fg-subtle" : "text-fg-soft",
                    )}
                  >
                    {step.result}
                  </span>
                  <span className="min-w-0 text-fg-muted">
                    <span className="font-mono text-fg">{step.decoder}</span> {step.step}
                    {step.file ? <span className="text-fg-subtle"> ({step.file}:{step.line})</span> : null}
                    {step.detail ? <span className="block break-all font-mono text-fg-muted">{step.detail}</span> : null}
                  </span>
                </li>
              ))}
            </ol>
          ) : null}
        </Section>
      </div>
    </aside>
  );
}

function IssueCard({
  issue,
  focused,
  busy,
  onApply,
  onCopy,
}: {
  issue: Issue;
  focused: boolean;
  busy: boolean;
  onApply: (s: Suggestion) => void;
  onCopy: (text: string) => void;
}) {
  const meta = KIND_META[issue.kind];
  return (
    <li
      ref={(el) => {
        if (focused) el?.scrollIntoView({ block: "nearest", behavior: "smooth" });
      }}
      className={cn("rounded-lg border p-3 transition-colors", focused ? "border-fg-muted bg-raised/40" : "border-line-muted")}
    >
      <div className="flex items-center gap-2">
        <span className={cn("badge shrink-0", meta.badge)}>{meta.label}</span>
        <span className="min-w-0 truncate font-mono text-xs text-fg">
          {issue.key ?? issue.value_kind}
          {issue.value ? <span className="text-fg-muted"> = {issue.value}</span> : null}
        </span>
      </div>
      <p className="mt-2 text-xs leading-5 text-fg-muted">{issue.reason}</p>
      {issue.decoder_regex ? <p className="mt-1 break-all font-mono text-[11px] text-fg-subtle">current: {issue.decoder_regex}</p> : null}
      {issue.suggestion ? (
        <div className="mt-2.5">
          <SuggestionBox suggestion={issue.suggestion} busy={busy} onApply={onApply} onCopy={onCopy} />
        </div>
      ) : null}
    </li>
  );
}

function Section({ title, action, children }: { title: string; action?: React.ReactNode; children: React.ReactNode }) {
  return (
    <section>
      <div className="mb-2 flex h-5 items-center justify-between">
        <h3 className="label">{title}</h3>
        {action}
      </div>
      {children}
    </section>
  );
}

/** name / value rows; tag = header | test | "". */
function KeyValues({ rows }: { rows: Array<[string, string | undefined, string]> }) {
  const present = rows.filter(([, v]) => v);
  if (!present.length) return <p className="text-xs text-fg-muted">No fields extracted.</p>;
  return (
    <div className="overflow-hidden rounded-lg border border-line-muted">
      <table className="w-full table-fixed text-xs">
        <tbody>
          {present.map(([k, v, tag], i) => (
            <tr key={i} className="border-t border-line-muted align-top first:border-t-0">
              <td className="w-2/5 bg-canvas/60 px-2.5 py-1.5 font-mono text-fg-muted break-all">
                {k}
                {tag ? (
                  <span className={cn("badge ml-1.5 h-4 px-1 text-[9px]", tag === "test" ? "bg-test/15 text-test" : "bg-hover text-fg-subtle")}>
                    {tag}
                  </span>
                ) : null}
              </td>
              <td className="px-2.5 py-1.5 font-mono text-fg break-all">
                {v}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
