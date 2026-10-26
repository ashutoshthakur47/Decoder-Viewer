import type { AnalyzedLine, AppStateResponse, CorpusProfileReport, FilterMode, PatchRequest } from "./types";

const RAW_BASE = (import.meta.env.VITE_API_BASE as string | undefined) ?? "http://127.0.0.1:8000";
export const API_BASE = RAW_BASE.replace(/\/+$/, "");

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers: init?.body instanceof FormData ? undefined : { "Content-Type": "application/json" },
    });
  } catch {
    throw new Error(`Cannot reach the backend at ${API_BASE}. Start it with start.bat (Windows) or start.sh.`);
  }
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`;
    try {
      const body = (await response.json()) as { detail?: unknown };
      if (body.detail) detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {
      // keep the status line
    }
    throw new Error(detail);
  }
  return (await response.json()) as T;
}

const post = <T,>(path: string, body: unknown) =>
  request<T>(path, { method: "POST", body: body instanceof FormData ? body : JSON.stringify(body) });

function form(field: string, files: File[]): FormData {
  const data = new FormData();
  files.forEach((file) => data.append(field, file));
  return data;
}

export const api = {
  state: () => request<AppStateResponse>("/api/state"),
  loadDecoderFiles: (files: File[]) => post<AppStateResponse>("/api/decoders/load", form("files", files)),
  saveDecoderFile: (name: string, xml: string) => post<AppStateResponse>("/api/decoders/load", { name, xml }),
  removeDecoderFile: (name: string) => post<AppStateResponse>("/api/decoders/load", { remove: name }),
  setStockJson: (enabled: boolean) => post<AppStateResponse>("/api/decoders/load", { stock_json: enabled }),
  patch: (body: PatchRequest) => post<AppStateResponse>("/api/decoders/patch", body),
  openLogFile: (file: File) => post<AppStateResponse>("/api/logs/open", form("file", [file])),
  profile: (maxLines: number | "full") =>
    post<CorpusProfileReport>(`/api/profile/run?max_lines=${maxLines}`, {}),
  analyze: (rawLine: string) => post<AnalyzedLine>("/api/analyze/single", { raw_line: rawLine }),
  chunk: (start: number, limit: number, filter: FilterMode, key: string | null) => {
    const q = new URLSearchParams({ start: String(start), limit: String(limit), filter_mode: filter });
    if (key) q.set("target_key", key);
    return request<AnalyzedLine[]>(`/api/logs/chunk?${q}`);
  },
};
