"""Engine tests: Wazuh decoding semantics + what-was-missed detection."""
from __future__ import annotations

from pathlib import Path

import pytest

from app.decoder_tree import build_tree, read_decoder_path
from app.os_regex import ExpressionError, compile_os_regex, group_keys
from app.schemas import TokenState
from app.span_engine import WazuhSpanEngine
from app import wazuh_xml

SAMPLE_DIR = Path(__file__).resolve().parents[2] / "samples" / "demo"

FULL_LINE = ('date=2026-10-20 time=10:00:01 devname="edge-fw01" action="accept" srcip=10.0.0.15 '
             'dstip=198.51.100.20 sentbyte=1520 dstport=443')

FW_XML = r"""
<decoder name="fw">
  <prematch>^device=</prematch>
</decoder>
<decoder name="fw">
  <parent>fw</parent>
  <regex>rule_id="(\.*)"</regex>
  <order>rule_id</order>
</decoder>
<decoder name="fw">
  <parent>fw</parent>
  <regex>\sbytes=(\d+)\s</regex>
  <order>bytes</order>
</decoder>
"""

JSON_XML = r"""
<decoder name="json">
  <prematch>^{\s*"</prematch>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
"""


def engine_for(xml: str) -> WazuhSpanEngine:
    return WazuhSpanEngine(build_tree([("test.xml", xml)]))


@pytest.fixture(scope="module")
def demo() -> WazuhSpanEngine:
    return WazuhSpanEngine(build_tree(read_decoder_path(str(SAMPLE_DIR / "demo_decoders.xml"))))


def fields(res) -> dict:
    return {f.name: f.value for f in res.fields if f.source != "predecoder"}


def test_demo_line_fully_decoded(demo):
    res = demo.analyze(FULL_LINE)
    assert res.status == "decoded" and res.decoder.name == "acme-fw"
    assert fields(res) == {"date": "2026-10-20", "time": "10:00:01", "devname": "edge-fw01", "action": "accept",
                           "srcip": "10.0.0.15", "dstip": "198.51.100.20", "dstport": "443", "sentbyte": "1520"}
    assert res.issues == [] and res.coverage_pct == 100.0


def test_tokens_rebuild_every_sample_line(demo):
    for raw in (SAMPLE_DIR / "demo.log").read_text(encoding="utf-8").splitlines():
        res = demo.analyze(raw)
        assert "".join(t.text for t in res.tokens) == res.raw_line


def test_decoder_outside_the_tree_is_tested_alone():
    # Wazuh rejects both (unknown parent; root without prematch, no <order>): they run alone, the tree is untouched.
    orphan = r'<decoder name="c"><parent>missing</parent><regex>\suser=(\S+)</regex><order>user</order></decoder>'
    bare = r'<decoder name="b"><regex>port (\d+)</regex></decoder>'
    res = engine_for(orphan + bare).analyze("login ok user=alice from 10.0.0.1 port 22")
    assert res.status == "no_decoder" and res.decoder.test and res.decoder.name == "c"
    assert {f.name: (f.value, f.source) for f in res.fields} == {"dstuser": ("alice", "test"), "port": ("22", "test")}
    assert [i.value for i in res.issues] == ["10.0.0.1"] and {t.text for t in res.tokens if t.state == TokenState.TEST} == {"alice", "22"}
    res = engine_for(FW_XML + orphan).analyze('device="x" bytes=5 user=bob end')
    assert res.decoder.name == "fw" and not res.decoder.test and fields(res) == {"bytes": "5", "dstuser": "bob"}


def test_value_inside_a_longer_key_counts_as_decoded():
    # rule_id="..." also matches inside fw_rule_id=: Wazuh stores it as rule_id. Intent is unknown, so no issue.
    res = engine_for(FW_XML).analyze('device="x" fw_rule_id="102" bytes=5 end')
    assert fields(res)["rule_id"] == "102"
    assert [i.key for i in res.issues] == ["device"]
    assert any(t.state == TokenState.CAPTURED and t.text == "102" for t in res.tokens)


def test_no_decoder_trace_lists_the_root_prematches_that_failed():
    res = engine_for(FW_XML).analyze("other=1 device=x")  # prematch is ^device=
    assert res.status == "no_decoder"
    assert [(t.decoder, t.step, t.result) for t in res.trace][:1] == [("fw", "prematch", "no match")]


def test_missing_key_suggestion_joins_sibling_chain():
    res = engine_for(FW_XML).analyze('device="x" new_key=5 bytes=7 end')
    issue = next(i for i in res.issues if i.key == "new_key")
    assert issue.kind == "missing"
    s = issue.suggestion
    assert s.action == "add_decoder" and s.insert_after == "fw" and s.parent == "fw"
    assert r"<regex>\snew_key=(\d+)</regex>" in s.xml


def test_broken_decoder_trailing_space_at_end_of_line():
    res = engine_for(FW_XML).analyze('device="x" bytes=4096')
    issue = next(i for i in res.issues if i.key == "bytes")
    assert issue.kind == "broken" and "trailing" in issue.reason
    assert issue.suggestion.regex == r"\sbytes=(\d+)"


def test_chain_stops_at_failed_non_sibling_regex():
    xml = r"""
    <decoder name="p"><prematch>^p:</prematch></decoder>
    <decoder name="a"><parent>p</parent><regex>\sa=(\d+)</regex><order>a</order></decoder>
    <decoder name="b"><parent>p</parent><regex>\sb=(\d+)</regex><order>b</order></decoder>
    """
    res = engine_for(xml).analyze("p: b=2")
    # child 'a' has no prematch: it is selected, fails, is not chained -> 'b' never runs (DecodeEvent)
    assert fields(res) == {}
    issue = next(i for i in res.issues if i.key == "b")
    assert issue.kind == "broken" and "not evaluated" in issue.reason


def test_program_name_hides_decoders_without_program_name():
    xml = r'<decoder name="kv"><prematch>^date=</prematch></decoder>'
    eng = engine_for(xml)
    assert eng.analyze("date=1 x=2").status != "no_decoder"
    res = eng.analyze("Oct 23 10:00:00 host app: date=1 x=2")
    assert res.status == "no_decoder"
    assert res.predecoded == {"timestamp": "Oct 23 10:00:00", "hostname": "host", "program_name": "app"}
    assert any("program_name" in t.detail for t in res.trace)


def test_predecoder_formats():
    eng = engine_for(r'<decoder name="s"><program_name>^sshd$</program_name></decoder>')
    for raw, ts in (
        ("Mar 16 11:58:05 localhost sshd[2219]: Accepted", "Mar 16 11:58:05"),
        ("2022-12-19T15:02:53.288+00:00 localhost sshd[1]: Accepted", "2022-12-19T15:02:53.288+00:00"),
        ("<34>Mar 16 11:58:05 localhost sshd: Accepted", "Mar 16 11:58:05"),
        ("2026 Sep 10 14:07:41 (agent) 10.0.0.1->/var/log/secure Mar 16 11:58:05 localhost sshd[1]: Accepted",
         "Mar 16 11:58:05"),
    ):
        res = eng.analyze(raw)
        assert res.predecoded["timestamp"] == ts and res.predecoded["program_name"] == "sshd", raw
        assert res.decoder.name == "s" and res.raw_line[res.log_offset:] == "Accepted"


def test_predecoder_squid_and_macos_asl():
    eng = engine_for(r'<decoder name="sq"><prematch>^\d+ \S+ TCP_</prematch></decoder>'
                     r'<decoder name="s"><program_name>^sshd$</program_name></decoder>')
    res = eng.analyze("1140701044.525   1231 192.168.1.201 TCP_DENIED/400 1536 GET ahmet - NONE/- text/html")
    assert res.decoder.name == "sq" and res.raw_line[res.log_offset:].startswith("1231 ")
    res = eng.analyze("[Time 2006.12.28 15:53:55 UTC] [Facility auth] [Sender sshd] [PID 483] "
                      "[Message error: PAM: auth failure] [Level 3] [Host mac1]")
    assert res.decoder.name == "s" and res.predecoded == {"hostname": "mac1", "program_name": "sshd"}
    assert "".join(t.text for t in res.tokens) == res.raw_line


def test_pcre2_ungreedy_flag():
    from app.os_regex import compile_pcre2
    m = compile_pcre2(r"(?mUs)ACTION :(.*)(?:^[A-Z\s]+:)").search("ACTION :[1] x\nUSER :y\nOTHER :z")
    assert m[2] == [(8, 14)]


def test_json_decoder_flattens_like_wazuh():
    res = engine_for(JSON_XML).analyze('{"a":{"b":"x","n":5,"f":1.5,"z":null,"t":true},"l":[1,2]}')
    assert fields(res) == {"a.b": "x", "a.n": "5", "a.f": "1.500000", "a.t": "true", "l": "[1,2]"}
    assert res.issues == []


def test_json_without_json_decoder_is_reported():
    res = engine_for(FW_XML).analyze('{"user":"bob","src":"1.2.3.4"}')
    assert res.status == "no_decoder"
    assert {i.key for i in res.issues if i.kind == "json"} == {"user", "src"}


def test_eventchannel_archive_line_uses_builtin_decoder():
    raw = '2026 Oct 23 10:00:00 (win10) any->EventChannel {"win":{"system":{"eventID":"4688"}}}'
    res = engine_for("").analyze(raw)
    assert res.decoder.name == "windows_eventchannel" and fields(res) == {"win.system.eventID": "4688"}


def test_cef_header_after_syslog_predecoding():
    raw = "Oct 23 10:00:00 edr01 CEF:0|Vendor|Product|1.0|100|Bad thing|8|src=10.0.0.9 msg=two words"
    res = engine_for("").analyze(raw)
    keys = {i.key: i.value for i in res.issues if i.kind == "missing"}
    assert keys["device_vendor"] == "Vendor" and keys["name"] == "Bad thing" and keys["msg"] == "two words"


def test_free_text_values_are_reported():
    res = engine_for("").analyze("Oct 23 10:00:00 h app[1]: user a@b.com from 10.1.2.3 port 22")
    kinds = {i.value_kind: i.value for i in res.issues if i.kind == "value"}
    assert kinds == {"email": "a@b.com", "ip": "10.1.2.3", "number": "22"}


@pytest.mark.parametrize("raw,expect", [
    ('date=2019-05-15 srcip=10.1.1.5 msg="two words" n=7', {"date": "2019-05-15", "srcip": "10.1.1.5", "msg": "two words", "n": "7"}),
    ("Oct 23 10:00:00 h app: user=bob action=login", {"dstuser": "bob", "action": "login"}),  # user = Wazuh alias of dstuser
    ("Oct 23 10:00:00 h app[4]: user alice@example.com downloaded /srv/f.pdf from 172.16.0.4 size 20480",
     {"dstuser": "alice@example.com", "downloaded": "/srv/f.pdf", "srcip": "172.16.0.4", "size": "20480"}),
    ('Oct 23 10:00:00 h app: {"a":1,"b":"x"}', {"a": "1", "b": "x"}),
    ('INFO 2026-10-23 {"a":1}', {"a": "1"}),
    ('{"a":{"b":2}}', {"a.b": "2"}),
    ("Oct 23 10:00:00 edr CEF:0|Vend|Prod|1.0|100|Bad thing|8|src=10.0.0.9 msg=two words",
     {"cef_version": "0", "device_vendor": "Vend", "name": "Bad thing", "src": "10.0.0.9", "msg": "two words"}),
    ("LEEF:1.0|Panda|paps|02.47|registrym|sev=1\tusrName=SYSTEM X", {"vendor": "Panda", "sev": "1", "usrName": "SYSTEM X"}),
    ("type=SYSCALL syscall=59 SYSCALL=execve uid=0 UID=root", {"syscall": "59", "SYSCALL": "execve", "UID": "root"}),
    ("rate is 9 per second, max rate is 10 now", {"is": "9", "rate_is": "10"}),
])
def test_generated_decoder_really_decodes(raw, expect):
    """No decoders -> generated root + children -> loaded -> the line decodes with those fields."""
    sug = engine_for("").analyze(raw).new_decoder
    assert sug is not None and sug.action == "add_decoder"
    tree = build_tree([("gen.xml", sug.xml)])
    assert [d.errors for d in tree.decoders if d.errors] == []
    res = WazuhSpanEngine(tree).analyze(raw)
    assert res.status == "decoded"
    got = fields(res)
    assert {k: got.get(k) for k in expect} == expect, sug.xml


SONICWALL = [
    'id=firewall sn=0A1B time="2026-10-23 23:22:46" fw=203.0.113.30 pri=6 c=0 m=1431 msg="ICMPv6 packet received" '
    'n=1386419 srcV6=2001:db8:600::304:b07:0 src=::X0 dstV6=ff02::1 srcMac=00:00:5e:00:53:28 proto=ipv6-icmp type=130 fw_action="NA"',
    'id=firewall sn=0A1B time="2026-10-23 23:23:07" fw=203.0.113.30 pri=6 c=16 m=33 msg="User login denied" sess="Portal" '
    'n=398483 usr="jdoe" src=198.51.100.13:25701:X1 dst=203.0.113.30:4433:X1 proto=tcp/4433 fw_action="NA"',
]


def test_format_decoder_learns_from_all_sample_lines():
    sug = engine_for("").format_suggestion(SONICWALL)
    assert "<prematch>^id=firewall sn=</prematch>" in sug.xml and "learned from 2 sample lines" in sug.note
    eng = WazuhSpanEngine(build_tree([("gen.xml", sug.xml)]))
    for raw in SONICWALL:
        res = eng.analyze(raw)
        assert res.status == "decoded" and res.issues == [], [i.key for i in res.issues]
    assert fields(eng.analyze(SONICWALL[1]))["usr"] == "jdoe"


def test_children_without_root_or_previous_regex_are_rejected_and_explained():
    child = r'<decoder name="sw"><parent>sw</parent><regex offset="after_regex">src=(\S+)</regex><order>src</order></decoder>'
    tree = build_tree([("t.xml", child)])
    assert "parent decoder 'sw' not found" in tree.decoders[0].errors[0]
    res = WazuhSpanEngine(tree).analyze(SONICWALL[1])
    assert "1 loaded decoder(s) were rejected" in next(t.detail for t in res.trace if t.step == "result")
    root = '<decoder name="sw"><prematch>^id=</prematch></decoder>'
    assert "after_regex" in build_tree([("t.xml", root + child)]).decoders[1].errors[0]
    first = r'<decoder name="sw"><parent>sw</parent><regex>^id=(\S+)</regex><order>id</order></decoder>'
    tree = build_tree([("t.xml", root + first + child)])
    assert [d.errors for d in tree.decoders] == [[], [], []]


def test_value_on_decoded_line_gets_a_working_child():
    xml = r'<decoder name="app"><program_name>^app$</program_name></decoder>'
    raw = "Oct 23 10:00:00 h app: login from 10.0.0.7 ok"
    issue = next(i for i in engine_for(xml).analyze(raw).issues if i.kind == "value")
    assert issue.suggestion.parent == "app"
    res = engine_for(xml + issue.suggestion.xml).analyze(raw)
    assert fields(res) == {"srcip": "10.0.0.7"} and res.issues == []


def test_os_regex_semantics():
    assert compile_os_regex(r"a\sb").search("a\tb") is None  # \s is a space only
    assert compile_os_regex(r"(\w+)").search("user@x-y")[2] == [(0, 8)]  # \w has @ and -
    assert compile_os_regex(r"a+").search("aa") is None and compile_os_regex(r"a+").search("a+")
    assert compile_os_regex("RULE").search("rule")  # case-insensitive
    assert compile_os_regex("b|a").search("a b")[0] == 2  # alternatives tried in order, not leftmost
    assert compile_os_regex("^b").search("ab", 1) is not None  # ^ anchors at the search offset
    assert compile_os_regex(r'x="(\.+)"').search('x="1" y="2"')[2] == [(3, 4)]  # run stops at next token
    with pytest.raises(ExpressionError):
        compile_os_regex(r"\-")
    assert group_keys(r'\sSPT=(\d+) DPT=(\d+)|fw_x="(\.*)"') == [["SPT", "DPT"], ["fw_x"]]


def test_wazuh_xml_reader_keeps_escaped_lt_and_ampersand():
    elems = wazuh_xml.parse(r"<decoder name='x'><prematch>\<log>\.+\</log></prematch><regex>a&b</regex></decoder>")
    assert [(c.name, c.content) for c in elems[0].children] == [("prematch", r"\<log>\.+\</log>"), ("regex", "a&b")]


def test_invalid_decoder_is_reported_not_loaded():
    tree = build_tree([("t.xml", r'<decoder name="x"><prematch>a\-b</prematch></decoder>')])
    assert tree.decoders[0].errors and not tree.roots_nopn

