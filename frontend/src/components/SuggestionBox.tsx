import type { Suggestion } from "../types";

/** Generated decoder XML / regex fix with Apply and Copy. */
export default function SuggestionBox({
  suggestion: s,
  busy,
  onApply,
  onCopy,
  extra,
}: {
  suggestion: Suggestion;
  busy: boolean;
  onApply: (s: Suggestion) => void;
  onCopy: (text: string) => void;
  extra?: React.ReactNode;
}) {
  const code = s.action === "replace_regex" ? `<regex>${s.regex}</regex>` : s.xml;
  return (
    <div className="space-y-1.5">
      <pre className="max-h-72 overflow-auto rounded-lg border border-line-muted bg-canvas p-2.5 font-mono text-[11px] leading-[17px] text-fg-soft">{code}</pre>
      {s.note ? <p className="text-[11px] text-fg-muted">{s.note}</p> : null}
      <div className="flex flex-wrap gap-2">
        {extra}
        <button className="btn btn-primary" disabled={busy} onClick={() => onApply(s)}>
          {s.action === "replace_regex" ? "Apply regex fix" : "Add decoder"}
        </button>
        <button className="btn" onClick={() => onCopy(code)}>
          Copy
        </button>
      </div>
    </div>
  );
}
