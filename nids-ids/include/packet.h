#pragma once
// packet.h — decoded representation of a single frame.
//
// The decoder fills one of these out per captured frame. Everything the rule
// engine needs to reason about a packet lives here, so the engine never has to
// re-parse raw bytes.

#include <cstdint>
#include <string>

namespace nids {

enum class L4Proto : uint8_t {
    Unknown = 0,
    TCP     = 6,
    UDP     = 17,
};

// A parsed packet. `payload` points into the capture buffer owned by the
// PcapReader — it is a view, not a copy, and is valid only for as long as the
// reader keeps the underlying record alive (which, for our file reader, is the
// whole run). Keep it that way: copying payloads per-packet is exactly the
// overhead a line-rate IDS is built to avoid.
struct Packet {
    // Timestamps straight from the capture record.
    uint32_t ts_sec  = 0;
    uint32_t ts_usec = 0;

    // Network layer (IPv4 only for now).
    uint32_t src_ip = 0;   // host byte order
    uint32_t dst_ip = 0;

    // Transport layer.
    L4Proto  proto    = L4Proto::Unknown;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;

    // Application payload — the bytes after the L4 header.
    const uint8_t* payload     = nullptr;
    uint32_t       payload_len = 0;

    bool decoded = false;  // false if we bailed out mid-parse (truncated, non-IPv4, ...)
};

// Pretty-print a.b.c.d from a host-order 32-bit address.
std::string ip_to_string(uint32_t ip);

}  // namespace nids
