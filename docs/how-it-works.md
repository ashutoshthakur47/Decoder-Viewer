# How it works

```
browser (React, :5173)  ──HTTP──>  backend (FastAPI, :8000)
                                     ├─ wazuh_xml.py     Wazuh's XML reader
                                     ├─ decoder_tree.py  decoder lists, parents, sibling chains
                                     ├─ os_regex.py      OS_Regex / OS_Match / PCRE2
                                     ├─ predecoder.py    syslog header (OS_CleanMSG)
                                     ├─ json_fields.py   JSON_Decoder plugin
                                     ├─ span_engine.py   decode one line + find what was missed
                                     ├─ log_indexer.py   memory-mapped line index
                                     └─ corpus_profiler.py  whole-file profile
```

Nothing is vendor-specific: the engine runs whatever decoder XML you load.

## 1. Decoding: a port of Wazuh's C code

Each line goes through the same steps as `wazuh-analysisd` 4.11.2:

1. **Pre-decoding** (`OS_CleanMSG`): the syslog header gives `timestamp`,
   `hostname` and `program_name`; other date formats (ISO, xferlog, snort,
   suricata, apache, squid, macOS ASL) are cut the same way.
2. **Root decoders**: when a `program_name` was pre-decoded, Wazuh only tries
   decoders that have `<program_name>`; otherwise only the others. The first
   matching root (load order) wins.
3. **Children**: the first child whose `<prematch>` matches, or the first one
   without a prematch. Same-name siblings next to each other run as a chain
   (`get_next`); a non-chained regex that fails stops the chain.
4. **Regex and offsets**: `after_parent`, `after_prematch`, `after_regex`
   exactly as in C. OS_Regex is case-insensitive, `\s` is a space only, `+` /
   `*` are lazy except at the end of the pattern, `|` alternatives are tried in
   order. `type="pcre2"` uses PCRE2 semantics.
5. **Plugins**: `JSON_Decoder` (dot paths, null / array options). The PF,
   SonicWall, SymantecWS and OSSECAlert plugins are not emulated: the decoder
   name is right, their fields show as not decoded.

The XML reader is Wazuh's own: `\<` stays literal and entities are not decoded,
which standard XML parsers get wrong on several stock files.

Decoders Wazuh would refuse to load (bad OS_Regex escape, unknown parent…) are
reported with the reason and never used in the tree.

## 2. Decoders tested alone

A decoder rejected **only for its place in the tree** (no parent and no
prematch, a parent that is not loaded, `after_regex` with no earlier regex,
`<regex>` without `<order>`) still has a working regex. It is run alone on every
line, from the start of the message (after the syslog header):

- `<program_name>` and `<prematch>` must match if present;
- the regex runs from the start, or after the prematch for
  `offset="after_prematch"`;
- captures get the `<order>` names, else the word in front of the value.

These captures are marked `test`. They never change what the real tree
decoded, and a line they cover still counts as "no decoder" in the totals,
because that is what Wazuh would do.

## 3. Finding what is not decoded

After decoding, every character the decoders captured is known. The rest of
the message is scanned with generic patterns:

| Kind | Found by |
|---|---|
| missing | `key=value` / `key="value"` pairs, CEF/LEEF headers, and `Key: value` pairs separated by two spaces or a tab (Windows, Sysmon) with no capture |
| broken | a missing key that a decoder for this log format targets (not one selected by another child's prematch); the reason is diagnosed (not reached, regex did not match, trailing `\s` at end of line…) |
| json | JSON keys when no JSON decoder ran, and every key of a second JSON event on the same line (Wazuh decodes only the first object of a line) |
| value | IPs, IPv6, MACs, e-mails, URLs, paths, hashes, quoted text and numbers left in free text, and the fields of a positional `a: b: c: d:` header at the start of the message (WinEvtLog: channel, level, provider, user, domain, computer) |

A value captured from inside a longer key (`rule_id="` matching inside
`fw_rule_id="`) counts as decoded: the tool cannot know whether that was meant.

## 4. Generating decoders

For each value left over, a regex is built from what surrounds it:

- `key=value`: quoted → `\skey="(\.*)"`, digits → `\skey=(\d+)`, else
  `\skey=(\S+)`; the `\s` keeps it from matching inside a longer key;
- keys that differ only by case (auditd `SYSCALL=` / `syscall=`) get a
  case-sensitive PCRE2 regex, because OS_Regex ignores case;
- CEF / LEEF: a header regex plus one regex per extension key;
- free text: the word(s) in front of the value, e.g. `\sfrom (\d+.\d+.\d+.\d+)`
  → `srcip`.

**Every generated regex is checked**: it must capture exactly that value on the
sample line (or on every sample of a format); otherwise a longer context or a
case-sensitive form is tried, and if nothing works no regex is offered.

For a format with no decoder, a root decoder comes first (by `<program_name>`,
a constant first key such as `^id=firewall sn=`, the CEF/LEEF header, or the
first words). In the profile's "No decoder" tab it is learned from up to 25
lines of that format, so keys only some lines have are covered too.

New children are placed where Wazuh will run them: a new sibling goes right
after the last member of its chain, otherwise into `local_decoder.xml`, loaded
last.

## 5. Accuracy

- Real `wazuh-logtest` 4.11.2 output on more than 20,000 firewall events: the
  decoder name and every field identical.
- Wazuh's own `ruleset/testing` suite with the stock decoders: 1,490 / 1,490
  lines get the expected decoder; all 1,568 stock decoders load.
- Starting from no decoders, on 1,664 lines of Wazuh's test logs, the generated
  decoders fully decode 87 % of the lines. The rest is genuinely hard for a
  generated regex: CSV columns with no word in front, keys repeated in one line
  (Wazuh keeps one), text after a JSON object (Wazuh ignores it too).
- Automated tests in `backend/tests`.

## 6. Size and speed

Uploads are streamed to a temp file, then memory-mapped: memory stays flat.
Measured: 1 GB / 2 million lines indexed in 1.2 s, any line opens instantly,
1–6 ms per distinct line when profiling (identical lines are analysed once).

The API never opens a file path it is sent, and only the UI's own origin may
call it from a browser.
