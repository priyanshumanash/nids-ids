# nids — a signature-based network intrusion detection engine (C++17)

A small, dependency-free IDS core. It reads a pcap capture, decodes each frame,
and matches every packet's payload against a set of signatures in a single pass
using an Aho-Corasick automaton — the same shape Snort and Suricata are built
around, written from scratch so every part is inspectable.

This is a working **vertical slice**, not a finished product: one clean path
from raw bytes to alerts, with the seams left obvious so it's straightforward to
grow into the full system (flow reassembly, anomaly detection, richer rules).

## Build

No external dependencies — the pcap format is parsed by hand. Any C++17 compiler:

```sh
g++ -std=c++17 -O2 -Wall -Wextra -Wpedantic -Iinclude \
    src/*.cpp -o nids
```

or, with CMake:

```sh
cmake -S . -B build && cmake --build build
```

## Run

```sh
python3 test/make_pcap.py test/test.pcap      # synthesize a capture
./nids rules/starter.rules test/test.pcap     # detect
```

Expected output includes alerts for the admin probe, the SQLi tautology, the
path-traversal + `/etc/passwd` packet, and the crafted DNS payload — while the
benign request and the same `/admin` string on the wrong port stay silent.

## Architecture

Data flows one direction; each stage compiles and can be tested on its own.

```
 capture.pcap
     │
     ▼
 PcapReader        parse the classic pcap file format, bounds-checked
     │  RawRecord
     ▼
 decode()          Ethernet → IPv4 → TCP/UDP into a Packet (payload is a view)
     │  Packet
     ▼
 Engine            one Aho-Corasick scan over the payload matches ALL rules'
     │             contents at once; hits are filtered by each rule's proto/port
     ▼
 Alert(s)          printed by main
```

| File | Role |
|------|------|
| `pcap_reader.{h,cpp}` | Reads and validates the classic libpcap file format (handles byte-order swap, truncation). |
| `decode.{h,cpp}` | Frame decoder: Ethernet/IPv4/TCP/UDP, every layer length-checked. |
| `ac.{h,cpp}` | Aho-Corasick multi-pattern matcher — build once, scan in O(payload). The core. |
| `rules.{h,cpp}` | A small Snort-flavoured rule language + parser (`\xHH` escapes, `msg:`). |
| `engine.{h,cpp}` | Registers every rule's content in the automaton, evaluates packets, emits alerts. |
| `main.cpp` | CLI glue. |

## Rule format

```
alert <proto> <dst_port|any> "<content>" ; msg:"<text>"
```

`content` supports `\xHH` hex, `\\`, `\"`, `\n`, `\r`, `\t`. See
`rules/starter.rules`.

## Known simplifications (i.e. the roadmap)

These are deliberate — each is a real next module, and where the interesting
work is:

- **No flow state.** Each packet is judged alone; there's no TCP stream
  reassembly, so a signature split across two segments is missed. A `flow`
  tracker (connection table + reassembly) is the natural next module.
- **Content-only matching.** No PCRE, no `offset`/`depth`/`within`, no `nocase`.
  The rule struct has room for these; the parser and engine are where they'd go.
- **Per-occurrence alerts.** Aho-Corasick reports every occurrence of a pattern,
  so a payload with three `../` fires three times. Production IDSs dedupe per
  rule per packet — a small, worthwhile addition.
- **IPv4 + TCP/UDP only.** No IPv6, ICMP, or VLAN tags yet.
- **Statistical anomaly detection** (payload entropy, scan/beacon heuristics) is
  a separate detector that would run alongside the signature engine.

## License

Yours to use, modify, and build on.
