#!/usr/bin/env python3
"""Write a tiny classic-pcap file with a few crafted TCP/UDP packets so we can
verify the engine detects (and correctly ignores) known payloads."""
import struct, sys

def ip_to_int(s):
    return struct.unpack(">I", bytes(int(x) for x in s.split(".")))[0]

def eth(dst=b"\xaa"*6, src=b"\xbb"*6, etype=0x0800):
    return dst + src + struct.pack(">H", etype)

def ipv4(src, dst, proto, payload_len):
    ver_ihl = 0x45
    total = 20 + payload_len
    return struct.pack(">BBHHHBBH4s4s",
        ver_ihl, 0, total, 0, 0, 64, proto, 0,
        struct.pack(">I", ip_to_int(src)), struct.pack(">I", ip_to_int(dst)))

def tcp(sport, dport, payload):
    # minimal 20-byte header, data offset = 5 (5*4=20)
    hdr = struct.pack(">HHIIBBHHH", sport, dport, 0, 0, (5 << 4), 0, 0, 0, 0)
    return hdr + payload

def udp(sport, dport, payload):
    hdr = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0)
    return hdr + payload

def frame_tcp(src, sport, dst, dport, data):
    seg = tcp(sport, dport, data)
    return eth() + ipv4(src, dst, 6, len(seg)) + seg

def frame_udp(src, sport, dst, dport, data):
    seg = udp(sport, dport, data)
    return eth() + ipv4(src, dst, 17, len(seg)) + seg

packets = [
    # should ALERT: admin path probe on port 80
    frame_tcp("10.0.0.5", 51000, "93.184.216.34", 80, b"GET /admin HTTP/1.1\r\nHost: x\r\n\r\n"),
    # should ALERT: SQL injection tautology (any port)
    frame_tcp("10.0.0.5", 51002, "93.184.216.34", 8080, b"user=admin&pass=' OR '1'='1"),
    # should NOT alert: benign traffic
    frame_tcp("10.0.0.5", 51004, "93.184.216.34", 80, b"GET /index.html HTTP/1.1\r\n\r\n"),
    # should ALERT: path traversal + passwd (two rules on one packet)
    frame_tcp("10.0.0.5", 51006, "93.184.216.34", 80, b"GET /../../../etc/passwd HTTP/1.1\r\n\r\n"),
    # should NOT alert: content present but wrong port for the :80-only admin rule
    frame_tcp("10.0.0.5", 51008, "93.184.216.34", 443, b"GET /admin HTTP/1.1\r\n\r\n"),
    # should ALERT: UDP/53 suspicious bytes
    frame_udp("10.0.0.5", 51010, "8.8.8.8", 53, b"\x00\x00\x01\x00\xff\xff\xff\xff"),
]

out = sys.argv[1] if len(sys.argv) > 1 else "test.pcap"
with open(out, "wb") as f:
    # global header: magic, ver 2.4, zone 0, sig 0, snaplen 65535, linktype 1 (eth)
    f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for i, p in enumerate(packets):
        f.write(struct.pack("<IIII", 1700000000 + i, 0, len(p), len(p)))
        f.write(p)
print(f"wrote {len(packets)} packets to {out}")
