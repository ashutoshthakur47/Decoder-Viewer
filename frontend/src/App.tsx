import { useCallback, useEffect, useRef, useState } from "react";
import { Download, FileCode2, FileText, Play } from "lucide-react";
import { api } from "./api";
import type { AnalyzedLine, AppStateResponse, DecoderFile, FilterMode, Suggestion } from "./types";
import { cn, copyText, downloadText, formatBytes, formatNumber } from "./ui";
import Sidebar from "./components/Sidebar";
import LogList from "./components/LogList";
import Inspector from "./components/Inspector";
import { LoadDecodersDialog, OpenLogDialog, XmlEditorDialog } from "./components/Dialogs";

type Dialog = null | "decoders" | "log" | { edit: DecoderFile };

const PASTED = "pasted_decoders.xml";

const FILTERS: Array<[FilterMode, string]> = [
  ["all", "All"],
  ["missing", "Not decoded"],
  ["broken", "Broken"],
  ["no_decoder", "No decoder"],
];

export default function App() {
  const [state, setState] = useState<AppStateResponse | null>(null);
  const [bootError, setBootError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [toast, setToast] = useState<{ ok: boolean; text: string } | null>(null);
  const [filter, setFilter] = useState<FilterMode>("all");
  const [filterKey, setFilterKey] = useState<string | null>(null);
  const [selected, setSelected] = useState<AnalyzedLine | null>(null);
  const [reloadToken, setReloadToken] = useState(0);
  const [dialog, setDialog] = useState<Dialog>(null);
  const [profileLines, setProfileLines] = useState("20000");
  const [testLine, setTestLine] = useState("");
  const toastTimer = useRef<number>();

  const notify = useCallback((ok: boolean, text: string) => {
    setToast({ ok, text });
    window.clearTimeout(toastTimer.current);
    toastTimer.current = window.setTimeout(() => setToast(null), ok ? 4000 : 9000);
  }, []);

  const boot = useCallback(() => {
    setBootError(null);
    api.state().then(setState, (e: Error) => setBootError(e.message));
  }, []);
  useEffect(boot, [boot]);

  const logName = state?.log_file.name;
  useEffect(() => {
    document.title = logName || "No log open";
  }, [logName]);

  /** Run a state-changing call, refresh the view and re-check the open line against the new decoders. */
  const run = async (
    label: string,
    call: () => Promise<AppStateResponse>,
    done: (s: AppStateResponse) => string,
    resetView = false,
    keepDialog = false,
  ) => {
    setBusy(label);
    try {
      const next = await call();
      setState(next);
      setReloadToken((t) => t + 1);
      if (!keepDialog) setDialog(null);
      if (resetView) {
        setFilter("all");
        setFilterKey(null);
        setSelected(null);
      } else if (selected) {
        const raw = selected.raw_line;
        const number = selected.line_number;
        api.analyze(raw).then((l) => setSelected({ ...l, line_number: number }), () => setSelected(null));
      }
      notify(true, done(next));
    } catch (error) {
      notify(false, (error as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const applySuggestion = (s: Suggestion) =>
    void run(
      "patch",
      () =>
        api.patch(
          s.action === "replace_regex"
            ? { action: "replace_regex", target_uid: s.target_uid, regex: s.regex }
            : { action: "add_decoder", xml: s.xml, insert_after: s.insert_after, parent: s.parent },
        ),
      () => (s.action === "replace_regex" ? "Regex replaced · log re-checked" : "Decoder added · log re-checked"),
    );

  const copy = async (text: string) => notify(await copyText(text), "Copied to clipboard");

  const runProfile = async () => {
    setBusy("profile");
    try {
      const report = await api.profile(profileLines === "full" ? "full" : Number(profileLines));
      setState((prev) => (prev ? { ...prev, corpus_profile: report } : prev));
      notify(true, `Profiled ${formatNumber(report.lines_scanned)} lines in ${(report.elapsed_ms / 1000).toFixed(1)} s`);
    } catch (error) {
      notify(false, (error as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const testOneLine = async () => {
    if (!testLine.trim()) return;
    try {
      setSelected({ ...(await api.analyze(testLine)), line_number: 0 });
    } catch (error) {
      notify(false, (error as Error).message);
    }
  };

  const changeFilter = (mode: FilterMode, key: string | null) => {
    setFilter(mode);
    setFilterKey(key);
  };

  if (!state) {
    return (
      <div className="grid h-screen place-items-center bg-canvas text-sm text-fg-muted">
        {bootError ? (
          <div className="w-[380px] rounded-xl border border-line bg-surface p-5">
            <p className="font-medium text-fg">Backend not reachable</p>
            <p className="mt-1 text-xs leading-5">{bootError}</p>
            <button className="btn btn-primary mt-4" onClick={boot}>
              Retry
            </button>
          </div>
        ) : (
          "Loading…"
        )}
      </div>
    );
  }

  const tree = state.decoder_tree;
  const rejected = tree.decoders.filter((d) => d.errors.length);
  const alone = rejected.filter((d) => d.standalone);
  const dead = rejected.filter((d) => !d.standalone);
  const profile = state.corpus_profile;
  const log = state.log_file;
  const gapTotal = (kinds: string[]) =>
    profile?.gaps.filter((g) => kinds.includes(g.kind)).reduce((n, g) => n + g.count, 0) ?? 0;
  const notDecoded = gapTotal(["missing", "json", "value"]);
  const pasted = tree.files.find((f) => f.name === PASTED);

  return (
    <div className="flex h-screen flex-col bg-canvas text-fg">
      <header className="flex h-14 shrink-0 items-center gap-2 border-b border-line-muted bg-surface px-3">
        <SourceButton
          icon={<FileCode2 className="h-4 w-4" />}
          label="Decoders"
          value={tree.files.length === 1 ? tree.files[0].name : `${tree.files.length} files`}
          meta={`${formatNumber(tree.decoders.length)} decoders`}
          onClick={() => setDialog("decoders")}
        />
        <SourceButton
          icon={<FileText className="h-4 w-4" />}
          label="Log"
          value={log.name || "none open"}
          meta={log.total_lines ? `${formatNumber(log.total_lines)} lines · ${formatBytes(log.file_size_bytes)}` : ""}
          onClick={() => setDialog("log")}
        />
        <div className="ml-auto flex items-center gap-2">
          <select
            className="input h-8 pr-7"
            value={profileLines}
            onChange={(e) => setProfileLines(e.target.value)}
            title="How many lines to profile"
          >
            <option value="5000">First 5,000 lines</option>
            <option value="20000">First 20,000 lines</option>
            <option value="100000">First 100,000 lines</option>
            <option value="full">Whole file</option>
          </select>
          <button className="btn btn-primary h-8" disabled={busy !== null || !log.total_lines} onClick={() => void runProfile()}>
            <Play className="h-3.5 w-3.5" />
            {busy === "profile" ? "Profiling…" : "Profile"}
          </button>
          <button
            className="btn h-8"
            disabled={!profile}
            onClick={() => {
              if (!profile) return;
              downloadText("decoder_coverage_report.md", profile.markdown_report, "text/markdown");
              // a second download in the same tick is often blocked by the browser
              window.setTimeout(() => downloadText("suggested_decoders.xml", profile.generated_xml, "application/xml"), 300);
            }}
            title="Markdown report + suggested decoder XML"
          >
            <Download className="h-3.5 w-3.5" />
            Export
          </button>
        </div>
      </header>

      {profile ? (
        <div className="flex h-14 shrink-0 items-center gap-9 border-b border-line-muted px-5">
          <div>
            <p className="label">Field coverage</p>
            <div className="mt-1 flex items-center gap-2.5">
              <span className="font-mono text-[15px] font-medium tabular-nums">{profile.avg_coverage_pct.toFixed(1)}%</span>
              <span className="h-1 w-28 overflow-hidden rounded-full bg-line">
                <span className="block h-full rounded-full bg-ok" style={{ width: `${profile.avg_coverage_pct}%` }} />
              </span>
            </div>
          </div>
          <Metric label="Lines profiled" value={`${formatNumber(profile.lines_scanned)} / ${formatNumber(profile.total_lines)}`} />
          <Metric label="Not decoded" value={formatNumber(notDecoded)} tone={notDecoded ? "text-warn" : undefined} />
          <Metric label="Broken" value={formatNumber(gapTotal(["broken"]))} tone={gapTotal(["broken"]) ? "text-bad" : undefined} />
          <Metric
            label="No decoder"
            value={formatNumber(profile.no_decoder_lines + profile.parent_only_lines)}
            tone={profile.no_decoder_lines ? "text-warn" : undefined}
          />
        </div>
      ) : null}

      {alone.length ? (
        <Banner tone="test" onFix={() => setDialog("decoders")}>
          <b className="font-medium">{alone.length} decoder{alone.length === 1 ? "" : "s"} tested alone</b> (dashed underline):
          no parent in the loaded set, e.g. <span className="font-mono">{alone[0].name}</span>. Wazuh rejects{" "}
          {alone.length === 1 ? "it" : "them"} until the parent is loaded.
        </Banner>
      ) : null}
      {dead.length ? (
        <Banner tone="bad" onFix={() => setDialog("decoders")}>
          <b className="font-medium">
            {dead.length} decoder{dead.length === 1 ? "" : "s"} rejected
          </b>{" "}
          · <span className="font-mono">{dead[0].name}</span> ({dead[0].file}:{dead[0].line}): {dead[0].errors[0]}
        </Banner>
      ) : null}

      <div className="relative flex min-h-0 flex-1">
        <div className="w-[340px] shrink-0 xl:w-[360px]">
          <Sidebar
            state={state}
            activeKey={filterKey}
            busy={busy !== null}
            onFilter={changeFilter}
            onApply={applySuggestion}
            onCopy={(t) => void copy(t)}
          />
        </div>

        <main className="flex min-w-0 flex-1 flex-col">
          <div className="flex h-11 shrink-0 items-center gap-3 border-b border-line-muted px-3">
            <div className="inline-flex rounded-lg border border-line bg-canvas p-0.5">
              {FILTERS.map(([mode, label]) => (
                <button
                  key={mode}
                  onClick={() => changeFilter(mode, mode === "all" ? null : filterKey)}
                  className={cn(
                    "h-6 whitespace-nowrap rounded-md px-2.5 text-xs font-medium transition-colors",
                    filter === mode ? "bg-raised text-fg shadow-[inset_0_0_0_1px_#2c2f35]" : "text-fg-muted hover:text-fg",
                  )}
                >
                  {label}
                </button>
              ))}
            </div>
            {filterKey ? (
              <span className="inline-flex h-7 items-center gap-1.5 rounded-md border border-line bg-raised pl-2.5 pr-1 text-xs">
                <span className="text-fg-muted">key</span>
                <span className="font-mono text-fg">{filterKey}</span>
                <button className="icon-btn h-5 w-5" onClick={() => setFilterKey(null)} title="Clear key filter">
                  ×
                </button>
              </span>
            ) : null}
            <form
              className="ml-auto flex w-full max-w-md"
              onSubmit={(event) => {
                event.preventDefault();
                void testOneLine();
              }}
            >
              <input
                className="input w-full font-mono"
                placeholder="Test one line: paste and press Enter"
                value={testLine}
                onChange={(e) => setTestLine(e.target.value)}
              />
            </form>
          </div>
          <LogList
            totalLines={log.total_lines}
            filter={filter}
            filterKey={filterKey}
            reloadToken={reloadToken}
            selected={selected?.line_number ?? null}
            onSelect={setSelected}
          />
        </main>

        {selected ? (
          // Below 1536px the inspector floats over the log list instead of squeezing it.
          <div className="absolute inset-y-0 right-0 z-20 w-[min(500px,100%)] shadow-[-24px_0_48px_-24px_rgba(0,0,0,0.8)] 2xl:static 2xl:z-auto 2xl:shrink-0 2xl:shadow-none">
            <Inspector
              key={`${selected.line_number}:${selected.raw_line}`}
              line={selected}
              busy={busy !== null}
              onClose={() => setSelected(null)}
              onApply={applySuggestion}
              onCopy={(t) => void copy(t)}
            />
          </div>
        ) : null}
      </div>

      {dialog === "decoders" ? (
        <LoadDecodersDialog
          files={tree.files}
          decoders={tree.decoders}
          busy={busy !== null}
          onClose={() => setDialog(null)}
          onFiles={(files) => void run("xml", () => api.loadDecoderFiles(files), (s) => `Loaded ${s.decoder_tree.decoders.length} decoders`, true)}
          onEdit={(file) => setDialog({ edit: file })}
          onRemove={(name) => void run("xml", () => api.removeDecoderFile(name), () => `Removed ${name} · log re-checked`, false, true)}
          stockJson={tree.stock_json}
          onStockJson={(on) =>
            void run("xml", () => api.setStockJson(on), () => `Wazuh default JSON decoder ${on ? "on" : "off"} · log re-checked`, false, true)
          }
          // Each paste is appended, so decoders can be added one at a time.
          onPasteAdd={(xml) =>
            void run(
              "xml",
              () => api.saveDecoderFile(PASTED, pasted ? `${pasted.xml.trimEnd()}\n\n${xml.trim()}\n` : xml),
              (s) => `Added to ${PASTED} · ${s.decoder_tree.decoders.length} decoders`,
            )
          }
        />
      ) : dialog === "log" ? (
        <OpenLogDialog
          busy={busy !== null}
          onClose={() => setDialog(null)}
          onFile={(file) => void run("log", () => api.openLogFile(file), (s) => `Opened ${s.log_file.name}: ${formatNumber(s.log_file.total_lines)} lines`, true)}
        />
      ) : dialog ? (
        <XmlEditorDialog
          file={dialog.edit}
          busy={busy !== null}
          onClose={() => setDialog(null)}
          onSave={(xml) => void run("xml", () => api.saveDecoderFile(dialog.edit.name, xml), () => `${dialog.edit.name} applied · log re-checked`)}
        />
      ) : null}

      {toast ? (
        <div
          role="status"
          className={cn(
            "fixed bottom-5 right-5 z-50 max-w-md animate-rise rounded-lg border px-3.5 py-2.5 text-xs shadow-[0_12px_32px_-8px_rgba(0,0,0,0.6)]",
            toast.ok ? "border-line bg-raised text-fg" : "border-bad/40 bg-[#2a1715] text-bad",
          )}
        >
          {toast.text}
        </div>
      ) : null}
    </div>
  );
}

function SourceButton({ icon, label, value, meta, onClick }: { icon: React.ReactNode; label: string; value: string; meta: string; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      aria-label={`${label}: ${value}`}
      className="flex h-10 min-w-0 max-w-[340px] items-center gap-2.5 rounded-lg border border-transparent px-2.5 text-left transition-colors hover:border-line hover:bg-raised"
    >
      <span className="grid h-7 w-7 shrink-0 place-items-center rounded-md border border-line bg-canvas text-fg-muted">{icon}</span>
      <span className="min-w-0">
        <span className="label block leading-3">{label}</span>
        <span className="mt-0.5 block truncate text-xs">
          <span className="font-medium text-fg">{value}</span>
          {meta ? <span className="text-fg-muted"> · {meta}</span> : null}
        </span>
      </span>
    </button>
  );
}

function Metric({ label, value, tone }: { label: string; value: string; tone?: string }) {
  return (
    <div>
      <p className="label">{label}</p>
      <p className={cn("mt-1 font-mono text-[15px] font-medium tabular-nums", tone ?? "text-fg")}>{value}</p>
    </div>
  );
}

function Banner({ tone, onFix, children }: { tone: "test" | "bad"; onFix: () => void; children: React.ReactNode }) {
  return (
    <div
      role="status"
      className={cn(
        "flex shrink-0 items-center gap-3 border-b px-5 py-2 text-xs leading-5",
        tone === "test" ? "border-test/20 bg-test/[0.06] text-test" : "border-bad/20 bg-bad/[0.07] text-bad",
      )}
    >
      <span className="min-w-0 flex-1">{children}</span>
      <button className="shrink-0 font-medium underline underline-offset-2" onClick={onFix}>
        Open decoders
      </button>
    </div>
  );
}
