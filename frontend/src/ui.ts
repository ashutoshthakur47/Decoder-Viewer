import type { IssueKind, TokenState } from "./types";

/** Name suffix of the stock JSON decoder file the backend adds when no loaded file reads JSON. */
export const STOCK_SUFFIX = " (Wazuh default)";

export function cn(...values: Array<string | false | null | undefined>): string {
  return values.filter(Boolean).join(" ");
}

export const formatNumber = (value: number) => new Intl.NumberFormat("en-US").format(value);

export function formatBytes(bytes: number): string {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = bytes;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size.toFixed(size >= 100 || unit === 0 ? 0 : 1)} ${units[unit]}`;
}

/** Inline highlight per token state. Colour means only what the decoders did; the rest stays neutral. */
export const TOKEN_CLASS: Record<TokenState, string> = {
  HEADER: "text-fg-subtle",
  TEXT: "text-fg-soft",
  MATCHED: "text-fg-muted",
  CAPTURED: "text-ok underline decoration-ok/40 underline-offset-[3px]",
  TEST: "text-test underline decoration-dashed decoration-test/70 underline-offset-[3px]",
  MISSING: "rounded-[3px] bg-warn/15 text-warn",
  BROKEN: "rounded-[3px] bg-bad/15 text-bad",
};

export const KIND_META: Record<IssueKind, { label: string; badge: string; help: string }> = {
  missing: { label: "Missing", badge: "bg-warn/15 text-warn", help: "key=value in the log, no decoder extracts it" },
  json: { label: "JSON", badge: "bg-warn/15 text-warn", help: "JSON key in the log, no JSON decoder ran" },
  value: { label: "Value", badge: "bg-hover text-fg-soft", help: "IP, number, path, user… left in free text" },
  broken: { label: "Broken", badge: "bg-bad/15 text-bad", help: "a decoder targets this key but did not capture it" },
};

export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

export function downloadText(filename: string, content: string, mime: string): void {
  const url = URL.createObjectURL(new Blob([content], { type: `${mime};charset=utf-8` }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1500);
}
