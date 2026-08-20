<div align="center">

# 🛡️ nids

**A signature-based network intrusion detection engine, written from scratch in C++17.**

Reads a pcap capture, decodes every frame, and matches all signatures against each packet in a single pass with an Aho-Corasick automaton — the same architecture Snort and Suricata are built on, with no external dependencies.

![Language](https://img.shields.io/badge/C%2B%2B-17-00599C?logo=cplusplus&logoColor=white)
![Build](https://img.shields.io/badge/build-passing-brightgreen)
![Dependencies](https://img.shields.io/badge/dependencies-none-blue)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

</div>

---

## Overview

`nids` is a compact, inspectable IDS **core**. Every layer — the pcap file
parser, the packet decoder, the multi-pattern matcher, the rule language — is
hand-written so you can read exactly how a signature engine turns raw bytes into
alerts.

It is a working **vertical slice**: one clean path from capture to alert, with
the seams left deliberately visible so it's easy to grow into the full system
(flow reassembly, PCRE, statistical anomaly detection).

```
[ALERT] pkt#1  TCP 10.0.0.5:51000 -> 93.184.216.34:80  "HTTP admin path probe"  (match@10)
[ALERT] pkt#2  TCP 10.0.0.5:51002 -> 93.184.216.34:8080 "classic SQL injection tautology" (match@27)
[ALERT] pkt#4  TCP 10.0.0.5:51006 -> 93.184.216.34:80  "path traversal sequence"  (match@8)
[ALERT] pkt#6  UDP 10.0.0.5:51010 -> 8.8.8.8:53        "suspicious DNS payload bytes" (match@8)
```

## Features

- **Single-pass matching** — one Aho-Corasick scan of a payload evaluates *every*
  rule's content at once, so cost scales with traffic, not with rule count.
- **Zero dependencies** — the classic libpcap file format is parsed by hand; any
  C++17 compiler builds it.
- **Snort-flavoured rules** — a readable rule language with `\xHH` hex escapes
  and `msg:` annotations.
- **Bounds-checked decoding** — Ethernet -> IPv4 -> TCP/UDP, every layer length-
  validated so malformed or truncated captures can't read out of bounds.
- **Byte-order aware** — handles both little- and big-endian pcap files.

## Quick start

```sh
# Build (no dependencies)
g++ -std=c++17 -O2 -Wall -Wextra -Wpedantic -Iinclude src/*.cpp -o nids

# or with CMake
cmake -S . -B build && cmake --build build

# Generate a sample capture and run detection
python3 test/make_pcap.py test/test.pcap
./nids rules/starter.rules test/test.pcap
```

The sample capture is crafted so the benign request and a signature seen on the
wrong port stay **silent**, while genuine probes fire — a quick correctness
check you can eyeball.

## Architecture

Data flows one direction; every stage compiles and can be tested on its own.

```
 capture.pcap
     |
     v
 PcapReader        parse the classic pcap file format, bounds-checked
     |  RawRecord
     v
 decode()          Ethernet -> IPv4 -> TCP/UDP into a Packet (payload is a view)
     |  Packet
     v
 Engine            one Aho-Corasick scan matches ALL rules' contents at once;
     |             hits are then filtered by each rule's proto / dst-port
     v
 Alert(s)          printed by main
```

| Module | Role |
|--------|------|
| `pcap_reader.{h,cpp}` | Reads & validates the classic libpcap file format (endianness, truncation). |
| `decode.{h,cpp}` | Frame decoder — Ethernet / IPv4 / TCP / UDP, every layer length-checked. |
| `ac.{h,cpp}` | **Aho-Corasick** multi-pattern matcher: build once, scan in `O(payload)`. The core. |
| `rules.{h,cpp}` | A small Snort-flavoured rule language and parser. |
| `engine.{h,cpp}` | Registers rule contents in the automaton, evaluates packets, emits alerts. |
| `main.cpp` | CLI glue. |

## Rule format

```
alert <proto> <dst_port|any> "<content>" ; msg:"<text>"
```

- **proto** — `tcp` / `udp` / `ip`(any)
- **port** — a number, or `any`
- **content** — a quoted byte string; supports `\xHH`, `\\`, `\"`, `\n`, `\r`, `\t`

```
alert tcp 80  "GET /admin"       ; msg:"HTTP admin path probe"
alert tcp any "' OR '1'='1"      ; msg:"classic SQL injection tautology"
alert udp 53  "\xff\xff\xff\xff" ; msg:"suspicious DNS payload bytes"
```

See [`rules/starter.rules`](rules/starter.rules) for the full starter set.

## Roadmap

These are deliberate simplifications — each is a real next module, and where the
interesting work lives:

- [ ] **Flow / stream reassembly** — a TCP connection table so signatures split
      across segments are caught (today each packet is judged alone).
- [ ] **Richer rule matching** — PCRE, `offset` / `depth` / `within`, `nocase`.
- [ ] **Per-packet-per-rule alert dedup** — currently every occurrence of a
      pattern fires (Aho-Corasick reports them all).
- [ ] **Statistical anomaly detection** — payload entropy, port-scan and
      beaconing heuristics, running alongside the signature engine.
- [ ] **More protocols** — IPv6, ICMP, VLAN tags.

## Project layout

```
nids/
|- include/        # public headers
|- src/            # implementation
|- rules/          # starter.rules
|- test/           # make_pcap.py -- synthesize a test capture
|- CMakeLists.txt
|- README.md
```

## License

Released under the MIT License — yours to use, modify, and build on.
