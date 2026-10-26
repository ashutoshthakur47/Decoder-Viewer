import type { AnalyzedLine, TokenState } from "../types";
import { TOKEN_CLASS, cn } from "../ui";

const STATE_TITLE: Partial<Record<TokenState, (field?: string | null) => string>> = {
  CAPTURED: (f) => `field: ${f}`,
  TEST: (f) => `field: ${f} (decoder tested alone)`,
  HEADER: () => "envelope / syslog header (pre-decoder)",
};

/** One raw log line with every character colored by what the decoders did with it. */
export default function LogLine({ line, onIssue }: { line: AnalyzedLine; onIssue?: (index: number) => void }) {
  return (
    <span className="font-mono text-[12px] leading-[20px] break-all whitespace-pre-wrap">
      {line.tokens.map((token) => {
        const issue = token.issue != null ? line.issues[token.issue] : undefined;
        const title = issue
          ? `${issue.kind}: ${issue.key ?? issue.value_kind ?? ""}\n${issue.reason}`
          : STATE_TITLE[token.state]?.(token.field);
        return (
          <span
            key={token.start}
            title={title}
            className={cn(TOKEN_CLASS[token.state], issue && onIssue && "cursor-pointer")}
            onClick={issue && onIssue ? (event) => (event.stopPropagation(), onIssue(token.issue!)) : undefined}
          >
            {token.text}
          </span>
        );
      })}
    </span>
  );
}
