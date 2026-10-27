"""FastAPI application: decoders + logs in, decoded / not-decoded fields out."""
from __future__ import annotations

import os
import re
import shutil
import tempfile
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from typing import List, Optional, Tuple

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware

from .corpus_profiler import CorpusGapProfiler
from .decoder_tree import DecoderTree, build_tree, read_decoder_path
from .log_indexer import MmapLogIndexer
from .schemas import (
    AnalyzedLine,
    AppStateResponse,
    CorpusProfileReport,
    DecoderFile,
    DecoderInfo,
    DecoderPatchRequest,
    DecoderTreeSummary,
    LogFileStats,
    SingleLineRequest,
)
from .span_engine import WazuhSpanEngine

BASE_DIR = Path(__file__).resolve().parent.parent
SAMPLE_DIR = BASE_DIR.parent / "samples" / "demo"
DEFAULT_XML = SAMPLE_DIR / "demo_decoders.xml"
DEFAULT_LOG = SAMPLE_DIR / "demo.log"
LOCAL_FILE = "local_decoder.xml"  # where new root/child decoders go, loaded last (like etc/decoders)
# Wazuh's ruleset/decoders/0006-json_decoders.xml (4.11.2). Every manager loads it before custom files,
# so JSON logs decode even when only custom decoders are loaded here.
STOCK_JSON_NAME = "0006-json_decoders.xml (Wazuh default)"
STOCK_JSON_XML = r"""<decoder name="json-msgraph">
  <prematch>"integration":"ms-graph"</prematch>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
  <json_null_field>discard</json_null_field>
</decoder>

<decoder name="json">
  <prematch>^{\s*"</prematch>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
"""
AUTO_PROFILE_LINES = 5_000
FILTERS = {"all", "missing", "broken", "no_decoder"}


class Runtime:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.initialized = False
        self.files: List[Tuple[str, str]] = []
        self.tree: Optional[DecoderTree] = None
        self.engine: Optional[WazuhSpanEngine] = None
        self.indexer: Optional[MmapLogIndexer] = None
        self.profile: Optional[CorpusProfileReport] = None
        self.temp_paths: List[str] = []
        self.stock_json = True  # user can switch the automatic default JSON decoder off

    def load_decoders(self, files: List[Tuple[str, str]]) -> None:
        files = [f for f in files if f[0] != STOCK_JSON_NAME]
        tree = build_tree(files)
        if self.stock_json and not any(d.plugin == "JSON_Decoder" for d in tree.valid):
            files = [(STOCK_JSON_NAME, STOCK_JSON_XML)] + files
            tree = build_tree(files)
        self.files, self.tree, self.engine = list(files), tree, WazuhSpanEngine(tree)

    def open_log(self, path: str) -> None:
        new = MmapLogIndexer(path)
        old, self.indexer = self.indexer, new
        if old is not None:
            old.close()

    def profile_now(self, max_lines: Optional[int]) -> Optional[CorpusProfileReport]:
        if self.engine is None or self.indexer is None:
            self.profile = None
        else:
            self.profile = CorpusGapProfiler(self.engine, self.indexer).run(max_lines=max_lines)
        return self.profile

    def state(self) -> AppStateResponse:
        assert self.tree is not None
        tree = self.tree
        counts = {name: [0, 0] for name, _ in self.files}
        for d in tree.decoders:
            counts.setdefault(d.file, [0, 0])
            counts[d.file][0] += 1
            counts[d.file][1] += bool(d.errors)
        summary = DecoderTreeSummary(
            files=[DecoderFile(name=n, xml=x, decoders=counts[n][0], errors=counts[n][1]) for n, x in self.files],
            decoders=[DecoderInfo(
                uid=d.uid, name=d.name, parent=d.parent, file=d.file, line=d.line,
                program_name=d.program_name_raw, prematch=d.prematch_raw, prematch_offset=d.prematch_offset,
                regex=d.regex_raw, regex_type=d.regex_type, regex_offset=d.regex_offset, order=d.order,
                plugin=d.plugin, get_next=d.get_next, use_own_name=d.use_own_name, target_key=d.target_key,
                unanchored=d.unanchored, errors=d.errors, warnings=d.warnings, standalone=d.standalone,
            ) for d in tree.decoders],
            errors=tree.errors,
            roots=len(tree.roots_pn) + len(tree.roots_nopn),
            children=sum(1 for d in tree.decoders if d.parent and not d.errors),
            invalid=sum(1 for d in tree.decoders if d.errors),
            stock_json=self.stock_json,
        )
        ix = self.indexer
        log = LogFileStats(path=ix.path if ix else "", name=os.path.basename(ix.path) if ix else "",
                           file_size_bytes=ix.file_size_bytes if ix else 0, total_lines=ix.total_lines if ix else 0)
        return AppStateResponse(decoder_tree=summary, log_file=log, corpus_profile=self.profile)

    def close(self) -> None:
        if self.indexer is not None:
            self.indexer.close()
            self.indexer = None
        for path in self.temp_paths:
            try:
                os.unlink(path)
            except OSError:
                pass
        self.temp_paths = []


runtime = Runtime()


def _initialize_once() -> None:
    with runtime.lock:
        if not runtime.initialized:
            runtime.initialized = True
            runtime.load_decoders(read_decoder_path(str(DEFAULT_XML)) if DEFAULT_XML.exists() else [])
        # A TestClient lifespan shutdown closes the indexer; reopen the sample so the API stays usable.
        if runtime.indexer is None and DEFAULT_LOG.exists():
            runtime.open_log(str(DEFAULT_LOG))
            runtime.profile_now(AUTO_PROFILE_LINES)


@asynccontextmanager
async def lifespan(app: FastAPI):
    _initialize_once()
    yield
    runtime.close()


app = FastAPI(title="decoder-viewer API", version="2.0.0", lifespan=lifespan)
# Only the UI may call the API from a browser: other sites must not read what is loaded here.
app.add_middleware(CORSMiddleware, allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
                   allow_methods=["*"], allow_headers=["*"])


@app.middleware("http")
async def _ensure_state(request: Request, call_next):
    _initialize_once()
    return await call_next(request)


async def _json(request: Request) -> dict:
    try:
        body = await request.json()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"Invalid JSON body: {exc}") from exc
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="JSON body must be an object")
    return body


def _decode_bytes(data: bytes) -> str:
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def _decoder_block(xml: str, line: int) -> Tuple[int, int]:
    """(start, end) offsets of the <decoder> element that starts on ``line`` (1-based)."""
    lines = xml.splitlines(keepends=True)
    start = sum(len(x) for x in lines[: line - 1])
    start = xml.find("<decoder", start)
    end = xml.find("</decoder>", start)
    if start == -1 or end == -1:
        raise HTTPException(status_code=400, detail=f"no <decoder> block at line {line}")
    return start, end + len("</decoder>")


def _apply_patch(files: List[Tuple[str, str]], tree: DecoderTree, patch: DecoderPatchRequest) -> List[Tuple[str, str]]:
    files = list(files)
    index = {name: i for i, (name, _) in enumerate(files)}
    if patch.action == "replace_regex":
        dec = tree.by_uid(patch.target_uid or -1)
        if dec is None or patch.regex is None:
            raise HTTPException(status_code=400, detail="replace_regex needs a valid target_uid and regex")
        name, xml = files[index[dec.file]]
        start, end = _decoder_block(xml, dec.line)
        block = xml[start:end]
        regexes = list(re.finditer(r"<regex\b([^>]*)>.*?</regex>", block, flags=re.S))
        if not regexes:
            raise HTTPException(status_code=400, detail=f"decoder '{dec.name}' has no <regex>")
        new_block = block[: regexes[0].start()] + f"<regex{regexes[0].group(1)}>{patch.regex}</regex>"
        tail = block[regexes[0].end():]
        for extra in regexes[1:]:  # several <regex> elements are concatenated by Wazuh: keep only the new one
            tail = tail.replace(extra.group(0), "", 1)
        files[index[dec.file]] = (name, xml[:start] + new_block + tail + xml[end:])
        return files
    if patch.action != "add_decoder" or not (patch.xml or "").strip():
        raise HTTPException(status_code=400, detail="action must be add_decoder (with xml) or replace_regex")
    snippet = patch.xml.strip()
    if patch.insert_after:
        # Siblings only chain when they are adjacent: insert after the last member of that chain.
        anchors = [d for d in tree.decoders if d.name == patch.insert_after and d.parent == patch.parent]
        if anchors:
            last = anchors[-1]
            name, xml = files[index[last.file]]
            _, end = _decoder_block(xml, last.line)
            files[index[last.file]] = (name, xml[:end] + "\n\n" + snippet + "\n" + xml[end:])
            return files
    first = re.search(r'<decoder name="([^"]+)">(?:(?!</decoder>).)*</decoder>', snippet, flags=re.S)
    users = [d for d in tree.decoders if first and "<parent>" not in first.group(0) and d.parent == first.group(1)]
    if users:  # a root must be loaded before the decoders that name it as <parent>
        name, xml = files[index[users[0].file]]
        start, _ = _decoder_block(xml, users[0].line)
        files[index[users[0].file]] = (name, xml[:start] + snippet + "\n\n" + xml[start:])
        return files
    if LOCAL_FILE in index:
        name, xml = files[index[LOCAL_FILE]]
        files[index[LOCAL_FILE]] = (name, xml.rstrip() + "\n\n" + snippet + "\n")
    else:
        files.append((LOCAL_FILE, snippet + "\n"))
    return files


# ---------------------------------------------------------------------- routes
@app.get("/api/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/api/state", response_model=AppStateResponse)
def get_state() -> AppStateResponse:
    with runtime.lock:
        return runtime.state()


@app.post("/api/decoders/load", response_model=AppStateResponse)
async def load_decoders(request: Request) -> AppStateResponse:
    """Replace the decoder set: multipart ``files`` (in load order), JSON ``{name, xml}`` to replace / add
    one file (XML editor, paste), ``{remove: name}`` to drop a file, or ``{stock_json: bool}`` to switch the
    automatic Wazuh default JSON decoder on / off. No server paths: the API never reads files it is pointed at."""
    if request.headers.get("content-type", "").startswith("multipart/form-data"):
        form = await request.form()
        uploads = form.getlist("files") or form.getlist("file")
        files = [(getattr(u, "filename", None) or "decoders.xml", _decode_bytes(await u.read()))
                 for u in uploads if hasattr(u, "read")]
        if not files:
            raise HTTPException(status_code=400, detail="multipart upload needs one or more 'files'")
    else:
        body = await _json(request)
        if isinstance(body.get("xml"), str) and isinstance(body.get("name"), str):
            with runtime.lock:
                files = [(n, body["xml"] if n == body["name"] else x) for n, x in runtime.files]
                if body["name"] not in {n for n, _ in files}:
                    files.append((body["name"], body["xml"]))
        elif isinstance(body.get("remove"), str):
            with runtime.lock:
                if body["remove"] not in {n for n, _ in runtime.files}:
                    raise HTTPException(status_code=400, detail=f"no loaded file named {body['remove']}")
                if body["remove"] == STOCK_JSON_NAME:
                    runtime.stock_json = False
                files = [f for f in runtime.files if f[0] != body["remove"]]
        elif isinstance(body.get("stock_json"), bool):
            with runtime.lock:
                runtime.stock_json = body["stock_json"]
                files = list(runtime.files)
        else:
            raise HTTPException(status_code=400, detail="send files (multipart), {name, xml}, {remove} or {stock_json}")
    with runtime.lock:
        runtime.load_decoders(files)
        runtime.profile_now(AUTO_PROFILE_LINES)
        return runtime.state()


@app.post("/api/decoders/patch", response_model=AppStateResponse)
async def patch_decoders(request: Request) -> AppStateResponse:
    try:
        patch = DecoderPatchRequest.model_validate(await _json(request))
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001 - pydantic validation error
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    with runtime.lock:
        assert runtime.tree is not None
        runtime.load_decoders(_apply_patch(runtime.files, runtime.tree, patch))
        runtime.profile_now(AUTO_PROFILE_LINES)
        return runtime.state()


@app.post("/api/logs/open", response_model=AppStateResponse)
async def open_log(request: Request) -> AppStateResponse:
    if not request.headers.get("content-type", "").startswith("multipart/form-data"):
        raise HTTPException(status_code=400, detail="upload the log as multipart 'file'")
    form = await request.form()
    upload = form.get("file")
    if upload is None or not hasattr(upload, "read"):
        raise HTTPException(status_code=400, detail="multipart upload must contain a 'file' field")
    safe = re.sub(r"[^A-Za-z0-9_.\-]", "_", getattr(upload, "filename", None) or "uploaded.log")
    path = os.path.join(tempfile.mkdtemp(prefix="decoder-viewer-"), safe)
    with open(path, "wb") as handle:
        shutil.copyfileobj(upload.file, handle, 16 * 1024 * 1024)  # stream: RAM stays flat for big uploads
    runtime.temp_paths.append(path)
    with runtime.lock:
        try:
            runtime.open_log(path)
        except (OSError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=f"Cannot open log file: {exc}") from exc
        runtime.profile_now(AUTO_PROFILE_LINES)
        return runtime.state()


@app.get("/api/logs/chunk", response_model=List[AnalyzedLine])
def get_log_chunk(
    start: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=2000),
    filter_mode: str = Query(default="all"),
    target_key: Optional[str] = Query(default=None),
) -> List[AnalyzedLine]:
    if filter_mode not in FILTERS:
        raise HTTPException(status_code=400, detail=f"filter_mode must be one of {sorted(FILTERS)}")
    with runtime.lock:
        indexer, engine = runtime.indexer, runtime.engine
    if indexer is None or engine is None:
        raise HTTPException(status_code=503, detail="No log file is open")
    if filter_mode == "all" and not target_key:
        return [engine.analyze(text, n) for n, text in indexer.get_lines(start, limit)]
    return indexer.search_and_filter_lines(engine, filter_mode, target_key, start, limit, max_scan_lines=1_000_000)


@app.post("/api/profile/run", response_model=CorpusProfileReport)
def run_profile(max_lines: str = Query(default="20000")) -> CorpusProfileReport:
    raw = (max_lines or "").strip().lower()
    if raw in ("full", "all", "0", ""):
        parsed = None
    elif raw.isdigit():
        parsed = int(raw)
    else:
        raise HTTPException(status_code=400, detail="max_lines must be a positive integer or 'full'")
    with runtime.lock:
        if runtime.engine is None or runtime.indexer is None:
            raise HTTPException(status_code=503, detail="No log file is open")
        report = runtime.profile_now(parsed)
        assert report is not None
        return report


@app.post("/api/analyze/single", response_model=AnalyzedLine)
def analyze_single(payload: SingleLineRequest) -> AnalyzedLine:
    with runtime.lock:
        engine = runtime.engine
    if engine is None:
        raise HTTPException(status_code=503, detail="No decoders loaded")
    return engine.analyze(payload.raw_line.rstrip("\r\n"), 1)
