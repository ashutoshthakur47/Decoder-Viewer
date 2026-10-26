# Usage

## 1. Load decoders

Click **Decoders** (top left).

| Action | What it does |
|---|---|
| **Paste → Add** | Appends the pasted XML to `pasted_decoders.xml`. Paste one decoder, look at the log, paste the next one: they add up. |
| **Paste → Replace all** | Drops every loaded file and keeps only the pasted XML. |
| **Upload** | One or many `.xml` files (for example Wazuh's `ruleset/decoders` plus your `etc/decoders`). Replaces the loaded set; files load in name order, like Wazuh. |
| Edit / Download / Remove | Per loaded file. Edits stay in the tool until you download the file; your files on disk are never changed. |
| Default JSON decoder | When no loaded file uses `JSON_Decoder`, Wazuh's stock `json` decoder is added, as on a real manager. Untick to test only your own files. |

## 2. Test a single decoder

You do not need a full decoder set. This is enough:

```xml
<decoder name="my-test">
  <regex>ProcessId: (\d+)\s+Image: (\S+)</regex>
</decoder>
```

Wazuh would reject it (a root decoder needs `<prematch>` or
`<program_name>`, and `<regex>` needs `<order>`), so the tool runs it **alone**
on every line instead:

- its captures are shown with a **dashed cyan underline** and a `test` tag;
- without `<order>`, each value is named after the word in front of it
  (`ProcessId`, `Image`), else `field1`, `field2`…;
- a banner lists how many decoders run alone.

The same applies to a child whose `<parent>` is not loaded yet, or a sibling
with `offset="after_regex"` and no earlier regex. Add the parent later and the
decoder joins the tree; the `test` tag disappears.

A decoder tested alone never changes what the real tree decodes: if a loaded
decoder already captures a value, that wins.

## 3. Open logs

Click **Log** (top left): paste lines (up to 5 MB) or upload a file (streamed,
practical up to ~1 GB).

Accepted: raw syslog / firewall / EDR lines, Wazuh `archives.log` (the
`YYYY Mon DD hh:mm:ss host->location` header is stripped), `archives.json`
(`full_log` is used) and JSON events. Windows events from archives (location
`EventChannel`) use Wazuh's built-in Windows decoder.

## 4. Read the view

Each line shows the decoder Wazuh would pick and every character colored by
what happened to it:

| Color | Meaning |
|---|---|
| green, underlined | decoded: stored in a field |
| cyan, dashed underline | captured by a decoder tested alone |
| amber | not decoded: no decoder reads it |
| red | broken: a decoder targets this key but did not capture it on this line |
| grey | matched as fixed text (prematch, regex literals) or syslog header |

Hover a value for its field name. Click a line to open the **inspector**:

- **Decoder**: which decoder matched, the header fields (timestamp, hostname,
  program_name) and every decoded field;
- **Suggested decoder for this format**: when no decoder matched at all;
- **Not decoded**: each value left behind, why, and a fix;
- **Trace**: every decoder tried, in Wazuh's order, and whether it matched.
  When no decoder matches, the root prematches that failed are listed, so a
  prematch that is too strict (for example one that expects fields in a fixed
  order) is easy to spot. See the FortiGate sample in [samples](../samples/).

Left panel (counts are for the profiled lines):

| Tab | Shows |
|---|---|
| Not decoded | each missing key / broken decoder / free-text value, how often, a fix, "Show lines" |
| Fields | every decoded field with sample values; click to filter lines |
| Decoders | which decoders matched how many lines, and any rejected decoders with the reason |
| No decoder | log formats no decoder handles, each with a generated decoder set |

Filters above the log: All / Not decoded / Broken / No decoder. **Test one
line** (top right of the log) analyzes a pasted line without opening a file.

## 5. Fix

- **Add decoder** inserts a suggestion where Wazuh will actually run it (a new
  sibling goes right after its chain) and re-checks the log at once.
- **Apply regex fix** replaces a broken decoder's regex.
- **Copy** gives you the XML to put in your own files.

Review generated field names before installing: the tool names fields after the
key (`srcip=` → `srcip`) or the word in front of a value (`from 10.0.0.1` →
`srcip`).

## 6. Profile and export

**Profile** runs the first 5,000 / 20,000 / 100,000 lines or the whole file
(identical lines are analysed once). **Export** downloads a Markdown report and
every suggested decoder as one XML file.
