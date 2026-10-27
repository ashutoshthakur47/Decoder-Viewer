# Samples

Each folder has a decoder file and a log file. In the app: **Decoders → Upload**
the `.xml`, then **Log → Upload** the `.log` (or paste either).

All log lines here are made up or come from public test data. IP addresses are
from the documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).

## demo

Loaded automatically when the app starts. A made-up firewall (`acme-fw`), sshd,
JSON events and a backup job, with gaps on purpose:

| Line | What you see |
|---|---|
| 1 | fully decoded |
| 2, 3, 4 | `policy`, `app`, `proto`, `fw_rule_id` not decoded: no decoder reads them |
| 2, 3 | `sentbyte` broken: its regex needs a space after the number, and here it is the last key |
| 5, 6 | the port after `port` is left in free text |
| 7 | parent only: the sshd child regex expects "invalid user" |
| 8, 9 | decoded by Wazuh's default JSON decoder |
| 10, 11 | no decoder at all; the inspector suggests a root + child decoder set |

## fortigate

`fortigate_v7_decoders.xml` is a public FortiGate decoder set (738 decoders, by
Alexander Tibor Assenheimer, GPLv2; header kept). `fortigate_synthetic.log` has
15 synthetic FortiGate lines.

Expected: 14 of 15 lines decoded with nothing left over. **Line 9 has no
decoder**, and real Wazuh behaves the same: the root decoder's prematch expects

```
devid="..." eventtime=... tz="..." logid="..."
```

in that order, but line 9 has `logid=` right after `devid=` (the older FortiOS
field order). No root matches, so none of the 737 field decoders run. Open line
9 and the trace shows the prematch that failed.

Fix: end the prematch after `devid`:

```xml
<prematch type="pcre2">^date=\d{4}-\d{2}-\d{2}\s+time=\d{2}:\d{2}:\d{2}\s+devname="[^"]*"\s+devid="[^"]*"</prematch>
```

With it, all 15 lines decode and line 9 gets 35 fields.

## windows-sysmon

Shows decoders **tested alone**. `sysmon_decoders.xml` holds:

- `Sysmon-EventID#1`, copied from Wazuh's `0380-windows_decoders.xml`, without
  its parent `windows`;
- `my-test`: just a name and a regex.

Wazuh would reject both. The tool runs each alone and marks what they capture
with a dashed cyan underline and a `test` tag: `sysmon.image`, `srcuser`,
`sysmon.hash`, `sysmon.parentImage`, `ProcessId`, `Image` on the two Sysmon lines.
Everything else is marked not decoded: the `Key: value` pairs (`UtcTime`,
`ProcessGuid`, `LogonId`, ...) and the WinEvtLog header fields (channel, level,
provider, user, domain, computer). The third line (an Application event) matches
neither decoder.

The line also suggests the missing parent, Wazuh's `windows` root
(`<program_name>^WinEvtLog$</program_name>`). Add it and `Sysmon-EventID#1`
decodes for real; `my-test` has no parent and stays a test.

The log lines are from Wazuh's `ruleset/testing` suite (GPLv2).
