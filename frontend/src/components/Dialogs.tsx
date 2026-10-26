import { useEffect, useState } from "react";
import { ClipboardPaste, Download, FileCode2, Pencil, Trash2, Upload, X } from "lucide-react";
import type { DecoderFile, DecoderInfo } from "../types";
import { cn, downloadText } from "../ui";

const STOCK_SUFFIX = " (Wazuh default)"; // backend name of the auto-added stock JSON decoder file
const PASTE_LIMIT = 5_000_000; // characters; a browser text box gets sluggish beyond a few MB

function Modal({
  title,
  subtitle,
  onClose,
  wide,
  children,
}: {
  title: string;
  subtitle?: string;
  onClose: () => void;
  wide?: boolean;
  children: React.ReactNode;
}) {
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => event.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <div className="fixed inset-0 z-50 flex animate-fade items-start justify-center bg-black/70 p-6 backdrop-blur-[2px]" onMouseDown={onClose}>
      <div
        role="dialog"
        aria-label={title}
        className={cn(
          "mt-[8vh] flex max-h-[84vh] w-full animate-rise flex-col overflow-hidden rounded-xl border border-line bg-surface shadow-[0_24px_64px_-12px_rgba(0,0,0,0.7)]",
          wide ? "max-w-5xl" : "max-w-2xl",
        )}
        onMouseDown={(event) => event.stopPropagation()}
      >
        <header className="flex items-center gap-3 px-5 pb-3 pt-4">
          <h2 className="text-[15px] font-semibold tracking-tight text-fg">{title}</h2>
          {subtitle ? <span className="text-xs text-fg-muted">{subtitle}</span> : null}
          <button className="icon-btn ml-auto" onClick={onClose} title="Close (Esc)">
            <X className="h-4 w-4" />
          </button>
        </header>
        <div className="min-h-0 flex-1 overflow-y-auto px-5 pb-5">{children}</div>
      </div>
    </div>
  );
}

type Source = "paste" | "upload";
const SOURCES: Array<[Source, string, typeof ClipboardPaste]> = [
  ["paste", "Paste", ClipboardPaste],
  ["upload", "Upload", Upload],
];

/** Paste or upload: one input at a time. */
function SourcePicker({
  busy,
  pastePlaceholder,
  pasteHint,
  pasteActions,
  accept,
  multiple,
  onFiles,
  uploadHint,
}: {
  busy: boolean;
  pastePlaceholder: string;
  pasteHint: string;
  pasteActions: Array<[string, (text: string) => void, boolean?]>;
  accept?: string;
  multiple?: boolean;
  onFiles: (files: File[]) => void;
  uploadHint: string;
}) {
  const [source, setSource] = useState<Source>("paste");
  const [text, setText] = useState("");
  const tooBig = text.length > PASTE_LIMIT;

  return (
    <div className="space-y-3">
      <div className="inline-flex rounded-lg border border-line bg-canvas p-0.5" role="tablist">
        {SOURCES.map(([id, label, Icon]) => (
          <button
            key={id}
            role="tab"
            aria-selected={source === id}
            onClick={() => setSource(id)}
            className={cn(
              "inline-flex h-7 items-center gap-1.5 rounded-md px-3 text-xs font-medium transition-colors",
              source === id ? "bg-raised text-fg shadow-[inset_0_0_0_1px_#2c2f35]" : "text-fg-muted hover:text-fg",
            )}
          >
            <Icon className="h-3.5 w-3.5" />
            {label}
          </button>
        ))}
      </div>

      {source === "paste" ? (
        <div className="space-y-2">
          <textarea
            className="textarea h-60"
            spellCheck={false}
            placeholder={pastePlaceholder}
            value={text}
            onChange={(e) => setText(e.target.value)}
            autoFocus
          />
          <div className="flex items-center gap-3">
            <span className={cn("text-xs", tooBig ? "text-bad" : "text-fg-muted")}>
              {tooBig ? "Over 5 MB: upload the file instead" : pasteHint}
            </span>
            <span className="ml-auto font-mono text-[11px] tabular-nums text-fg-subtle">
              {(text.length / 1_000_000).toFixed(2)} / 5 MB
            </span>
            {pasteActions.map(([name, act, primary]) => (
              <button
                key={name}
                className={cn("btn", primary && "btn-primary")}
                disabled={busy || !text.trim() || tooBig}
                onClick={() => act(text)}
              >
                {name}
              </button>
            ))}
          </div>
        </div>
      ) : (
        <label
          className={cn(
            "relative grid h-60 cursor-pointer place-items-center rounded-lg border border-dashed border-line bg-canvas text-center transition-colors hover:border-fg-subtle hover:bg-raised/40",
            busy && "pointer-events-none opacity-50",
          )}
        >
          <span>
            <Upload className="mx-auto mb-3 h-5 w-5 text-fg-muted" />
            <span className="block text-sm font-medium text-fg">Drop {multiple ? "files" : "a file"} here or click to choose</span>
            <span className="mt-1 block text-xs text-fg-muted">{uploadHint}</span>
          </span>
          <input
            type="file"
            accept={accept}
            multiple={multiple}
            className="absolute inset-0 cursor-pointer opacity-0"
            onChange={(e) => {
              const picked = Array.from(e.target.files ?? []).sort((a, b) => a.name.localeCompare(b.name));
              if (picked.length) onFiles(picked);
            }}
          />
        </label>
      )}
    </div>
  );
}

export function LoadDecodersDialog({
  files,
  decoders,
  busy,
  onClose,
  onFiles,
  onEdit,
  onPasteAdd,
  onRemove,
  stockJson,
  onStockJson,
}: {
  files: DecoderFile[];
  decoders: DecoderInfo[];
  busy: boolean;
  onClose: () => void;
  onFiles: (files: File[]) => void;
  onEdit: (file: DecoderFile) => void;
  onPasteAdd: (xml: string) => void;
  onRemove: (name: string) => void;
  stockJson: boolean;
  onStockJson: (enabled: boolean) => void;
}) {
  const total = files.reduce((n, f) => n + f.decoders, 0);
  return (
    <Modal title="Decoders" subtitle={`${files.length} file${files.length === 1 ? "" : "s"} · ${total} decoders`} onClose={onClose}>
      <div className="space-y-6">
        <section>
          <p className="label mb-2">Loaded, in load order</p>
          <ul className="divide-y divide-line-muted overflow-hidden rounded-lg border border-line-muted">
            {files.map((f) => {
              const stock = f.name.endsWith(STOCK_SUFFIX);
              const alone = decoders.filter((d) => d.file === f.name && d.standalone).length;
              return (
                <li key={f.name} className="group flex h-10 items-center gap-3 bg-canvas pl-3 pr-1.5">
                  <FileCode2 className="h-4 w-4 shrink-0 text-fg-subtle" />
                  <span className="min-w-0 flex-1 truncate font-mono text-xs text-fg" title={f.name}>
                    {f.name}
                  </span>
                  {alone ? <span className="badge bg-test/15 text-test">{alone} tested alone</span> : null}
                  {f.errors > alone ? <span className="badge bg-bad/15 text-bad">{f.errors - alone} rejected</span> : null}
                  <span className="text-xs tabular-nums text-fg-muted">{f.decoders}</span>
                  <span className="flex opacity-60 transition-opacity group-hover:opacity-100">
                    {stock ? null : (
                      <button className="icon-btn" title="Edit" onClick={() => onEdit(f)}>
                        <Pencil className="h-3.5 w-3.5" />
                      </button>
                    )}
                    <button
                      className="icon-btn"
                      title="Download"
                      onClick={() => downloadText(f.name.replace(STOCK_SUFFIX, ""), f.xml, "application/xml")}
                    >
                      <Download className="h-3.5 w-3.5" />
                    </button>
                    <button
                      className="icon-btn hover:text-bad"
                      title="Remove"
                      disabled={busy}
                      onClick={() =>
                        (stock || window.confirm(`Remove ${f.name}? Edits made here are lost (the file on disk is not touched).`)) &&
                        onRemove(f.name)
                      }
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </span>
                </li>
              );
            })}
            {!files.length ? <li className="bg-canvas px-3 py-3 text-xs text-fg-muted">No decoders loaded.</li> : null}
          </ul>
          <label className="mt-2.5 flex cursor-pointer items-center gap-2.5 text-xs text-fg-muted">
            <input
              type="checkbox"
              className="h-3.5 w-3.5 accent-[#ecebe8]"
              checked={stockJson}
              disabled={busy}
              onChange={(e) => onStockJson(e.target.checked)}
            />
            Add Wazuh's default JSON decoder when no loaded file decodes JSON
          </label>
        </section>

        <section>
          <p className="label mb-2">Add decoders</p>
          <SourcePicker
            busy={busy}
            pastePlaceholder={'<decoder name="my-app">\n  <regex>user=(\\S+) from (\\S+)</regex>\n  <order>srcuser, srcip</order>\n</decoder>'}
            pasteHint="Name + regex is enough: without a parent it is tested alone."
            pasteActions={[
              ["Replace all", (xml) => onFiles([new File([xml], "pasted_decoders.xml")])],
              ["Add", onPasteAdd, true],
            ]}
            accept=".xml"
            multiple
            onFiles={onFiles}
            uploadHint="One or many .xml files · replaces the loaded set"
          />
        </section>
      </div>
    </Modal>
  );
}

export function OpenLogDialog({ busy, onClose, onFile }: { busy: boolean; onClose: () => void; onFile: (f: File) => void }) {
  return (
    <Modal title="Open log" subtitle="raw lines, archives.log, archives.json or JSON" onClose={onClose}>
      <SourcePicker
        busy={busy}
        pastePlaceholder={"Oct 23 10:00:00 host sshd[1]: Failed password for root from 10.0.0.1 port 22 ssh2\n{\"event\":\"login\",\"user\":\"bob\"}"}
        pasteHint="One event per line"
        pasteActions={[["Analyze", (text) => onFile(new File([text], "pasted.log")), true]]}
        onFiles={(files) => onFile(files[0])}
        uploadHint="Streamed to the backend · practical up to ~1 GB · gzip: extract first"
      />
    </Modal>
  );
}

export function XmlEditorDialog({ file, busy, onClose, onSave }: { file: DecoderFile; busy: boolean; onClose: () => void; onSave: (xml: string) => void }) {
  const [xml, setXml] = useState(file.xml);
  return (
    <Modal title={file.name} subtitle="edit" onClose={onClose} wide>
      <textarea className="textarea h-[60vh] text-xs leading-5" spellCheck={false} value={xml} onChange={(e) => setXml(e.target.value)} />
      <div className="mt-3 flex items-center gap-2">
        <span className="text-xs text-fg-muted">Changes stay in this tool until you download the file.</span>
        <button className="btn ml-auto" onClick={onClose}>
          Cancel
        </button>
        <button className="btn btn-primary" disabled={busy || xml === file.xml} onClick={() => onSave(xml)}>
          Apply
        </button>
      </div>
    </Modal>
  );
}
