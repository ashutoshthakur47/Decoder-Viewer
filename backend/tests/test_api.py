"""API integration tests using FastAPI's TestClient."""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app

SAMPLE_DIR = Path(__file__).resolve().parents[2] / "samples" / "demo"
XML_PATH = SAMPLE_DIR / "demo_decoders.xml"
LOG_PATH = SAMPLE_DIR / "demo.log"

ROOT_XML = '<decoder name="fw"><prematch>^device=</prematch></decoder>\n'
CHILD_XML = r"""<decoder name="fw">
  <parent>fw</parent>
  <regex>rule_id="(\.*)"</regex>
  <order>rule_id</order>
</decoder>
"""
LINE = 'device="x" fw_rule_id="102" new_key=5'


@pytest.fixture()
def client():
    with TestClient(app) as test_client:
        files = [("files", (XML_PATH.name, XML_PATH.read_bytes()))]
        assert test_client.post("/api/decoders/load", files=files).status_code == 200
        assert test_client.post("/api/logs/open", files={"file": (LOG_PATH.name, LOG_PATH.read_bytes())}).status_code == 200
        yield test_client


def test_state(client: TestClient):
    data = client.get("/api/state").json()
    tree = data["decoder_tree"]
    # Wazuh's stock JSON decoder is added first (as on a manager) because the sample has none.
    assert [f["name"] for f in tree["files"]] == ["0006-json_decoders.xml (Wazuh default)", "demo_decoders.xml"]
    assert tree["invalid"] == 0 and tree["roots"] == 4 and tree["children"] == 9
    assert data["log_file"]["total_lines"] == 11
    assert data["corpus_profile"]["lines_scanned"] == 11


def test_chunk_and_filters(client: TestClient):
    rows = client.get("/api/logs/chunk", params={"start": 0, "limit": 10}).json()
    assert [r["line_number"] for r in rows] == list(range(1, 11))
    for row in rows:
        assert "".join(t["text"] for t in row["tokens"]) == row["raw_line"]
    for mode in ("missing", "broken", "no_decoder"):
        resp = client.get("/api/logs/chunk", params={"filter_mode": mode, "limit": 5})
        assert resp.status_code == 200, mode
    assert client.get("/api/logs/chunk", params={"filter_mode": "bogus"}).status_code == 400


def test_profile(client: TestClient):
    report = client.post("/api/profile/run", params={"max_lines": "full"}).json()
    assert report["lines_scanned"] == 11
    assert report["decoded_lines"] + report["parent_only_lines"] + report["no_decoder_lines"] == 11
    assert report["fields"] and "## Not decoded" in report["markdown_report"]


def test_patch_add_and_replace(client: TestClient):
    client.post("/api/decoders/load", json={"name": "fw.xml", "xml": ROOT_XML + CHILD_XML})
    res = client.post("/api/analyze/single", json={"raw_line": LINE}).json()
    issues = {i["key"]: i for i in res["issues"]}
    assert set(issues) == {"device", "new_key"}  # fw_rule_id's value is captured (as rule_id)

    state = client.post("/api/decoders/patch", json=issues["new_key"]["suggestion"]).json()
    assert "new_key" in next(f["xml"] for f in state["decoder_tree"]["files"] if f["name"] == "fw.xml")
    uid = next(d["uid"] for d in state["decoder_tree"]["decoders"] if d["file"] == "fw.xml" and d["order"] == ["rule_id"])
    client.post("/api/decoders/patch", json={"action": "replace_regex", "target_uid": uid, "regex": '\\srule_id="(\\.*)"'})
    res = client.post("/api/analyze/single", json={"raw_line": LINE}).json()
    assert {i["key"] for i in res["issues"]} == {"device", "fw_rule_id"}  # no decoder targets these
    assert {f["name"]: f["value"] for f in res["fields"]} == {"new_key": "5"}


def test_load_multipart_files_in_order(client: TestClient):
    files = [("files", ("a.xml", ROOT_XML.encode())), ("files", ("b.xml", CHILD_XML.encode()))]
    tree = client.post("/api/decoders/load", files=files).json()["decoder_tree"]
    assert [f["name"] for f in tree["files"]][1:] == ["a.xml", "b.xml"] and tree["invalid"] == 0


def test_open_log_upload(client: TestClient):
    state = client.post("/api/logs/open", files={"file": ("x.log", b"one\ntwo\n")}).json()
    assert state["log_file"]["total_lines"] == 2
    # no server paths: the API must never open a file it is pointed at
    assert client.post("/api/logs/open", json={"file_path": str(LOG_PATH)}).status_code == 400
    assert client.post("/api/decoders/load", json={"path": str(XML_PATH)}).status_code == 400


def test_json_decodes_with_custom_decoders_only(client: TestClient):
    res = client.post("/api/analyze/single", json={"raw_line": '{"user":"bob","src":{"ip":"1.2.3.4"}}'}).json()
    assert res["decoder"]["name"] == "json"
    assert {f["name"]: f["value"] for f in res["fields"]} == {"user": "bob", "src.ip": "1.2.3.4"}


def test_new_format_decoder_round_trip(client: TestClient):
    line = "Oct 23 10:00:00 h myapp[1]: user=bob action=login from 10.0.0.9"
    sug = client.post("/api/analyze/single", json={"raw_line": line}).json()["new_decoder"]
    client.post("/api/decoders/patch", json={"action": "add_decoder", "xml": sug["xml"]})
    res = client.post("/api/analyze/single", json={"raw_line": line}).json()
    assert res["status"] == "decoded" and res["issues"] == []
    assert {f["name"]: f["value"] for f in res["fields"] if f["source"] != "predecoder"} == {
        "dstuser": "bob", "action": "login", "srcip": "10.0.0.9"}


def test_remove_file_and_default_json_switch(client: TestClient):
    stock = "0006-json_decoders.xml (Wazuh default)"
    tree = client.post("/api/decoders/load", json={"remove": stock}).json()["decoder_tree"]
    assert [f["name"] for f in tree["files"]] == ["demo_decoders.xml"] and tree["stock_json"] is False
    assert client.post("/api/analyze/single", json={"raw_line": '{"a":1}'}).json()["status"] == "no_decoder"
    tree = client.post("/api/decoders/load", json={"stock_json": True}).json()["decoder_tree"]
    assert [f["name"] for f in tree["files"]] == [stock, "demo_decoders.xml"]
    tree = client.post("/api/decoders/load", json={"remove": "demo_decoders.xml"}).json()["decoder_tree"]
    assert [f["name"] for f in tree["files"]] == [stock]
    assert client.post("/api/decoders/load", json={"remove": "nope.xml"}).status_code == 400


def test_children_without_parent_get_the_parent_suggested_and_added(client: TestClient):
    """Paste children one by one, no root yet: they are tested alone, the line suggests the missing parent,
    and adding it (placed before them) makes them real children."""
    children = "".join(
        rf'<decoder name="fw-fields"><parent>my-fw</parent><regex>\s{k}=(\S+)</regex><order>{k}</order></decoder>'
        for k in ("srcip", "dstip"))
    client.post("/api/decoders/load", files=[("files", ("kids.xml", children.encode()))])
    line = "date=2026-10-27 time=10:00:00 devname=fw1 srcip=10.0.0.1 dstip=10.0.0.2"
    res = client.post("/api/analyze/single", json={"raw_line": line}).json()
    assert res["status"] == "no_decoder" and res["decoder"]["test"] is True
    sug = res["new_decoder"]
    assert '<decoder name="my-fw">' in sug["xml"] and r"<prematch>^date=\S+ time=</prematch>" in sug["xml"]
    state = client.post("/api/decoders/patch", json={"action": "add_decoder", "xml": sug["xml"]}).json()
    assert state["decoder_tree"]["invalid"] == 0
    assert state["decoder_tree"]["files"][-1]["xml"].startswith('<decoder name="my-fw">')  # root first
    res = client.post("/api/analyze/single", json={"raw_line": line}).json()
    assert res["status"] == "decoded" and res["decoder"]["name"] == "my-fw" and not res["decoder"]["test"]
    assert {f["name"]: (f["value"], f["source"]) for f in res["fields"]} == {
        "srcip": ("10.0.0.1", "regex"), "dstip": ("10.0.0.2", "regex")}
