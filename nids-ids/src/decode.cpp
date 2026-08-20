#include "decode.h"

#include <arpa/inet.h>  // ntohs / ntohl
#include <cstdio>
#include <cstring>

namespace nids {

namespace {
constexpr size_t kEthHeaderLen = 14;
constexpr uint16_t kEtherTypeIPv4 = 0x0800;
}  // namespace

std::string ip_to_string(uint32_t ip) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                  (ip >> 24) & 0xff, (ip >> 16) & 0xff,
                  (ip >> 8) & 0xff, ip & 0xff);
    return buf;
}

bool decode(const RawRecord& rec, Packet& out) {
    out = Packet{};
    out.ts_sec  = rec.ts_sec;
    out.ts_usec = rec.ts_usec;

    const uint8_t* p = rec.data;
    uint32_t remaining = rec.len;

    // --- Ethernet ---
    if (remaining < kEthHeaderLen) return false;
    uint16_t ethertype = (p[12] << 8) | p[13];
    if (ethertype != kEtherTypeIPv4) return false;  // IPv6/ARP/etc. skipped for now
    p += kEthHeaderLen;
    remaining -= kEthHeaderLen;

    // --- IPv4 ---
    if (remaining < 20) return false;
    uint8_t version = p[0] >> 4;
    uint8_t ihl     = (p[0] & 0x0f) * 4;   // header length in bytes
    if (version != 4 || ihl < 20 || ihl > remaining) return false;

    uint8_t  ip_proto = p[9];
    uint32_t saddr, daddr;
    std::memcpy(&saddr, p + 12, 4);
    std::memcpy(&daddr, p + 16, 4);
    out.src_ip = ntohl(saddr);
    out.dst_ip = ntohl(daddr);

    // total_len lets us clamp payloads even if the capture has trailing padding.
    uint16_t total_len = (p[2] << 8) | p[3];
    uint32_t ip_span = (total_len && total_len <= remaining) ? total_len : remaining;

    const uint8_t* l4 = p + ihl;
    uint32_t l4_remaining = ip_span - ihl;

    // --- TCP / UDP ---
    if (ip_proto == static_cast<uint8_t>(L4Proto::TCP)) {
        if (l4_remaining < 20) return false;
        out.proto    = L4Proto::TCP;
        out.src_port = (l4[0] << 8) | l4[1];
        out.dst_port = (l4[2] << 8) | l4[3];
        uint8_t data_off = (l4[12] >> 4) * 4;
        if (data_off < 20 || data_off > l4_remaining) return false;
        out.payload     = l4 + data_off;
        out.payload_len = l4_remaining - data_off;
    } else if (ip_proto == static_cast<uint8_t>(L4Proto::UDP)) {
        if (l4_remaining < 8) return false;
        out.proto    = L4Proto::UDP;
        out.src_port = (l4[0] << 8) | l4[1];
        out.dst_port = (l4[2] << 8) | l4[3];
        out.payload     = l4 + 8;
        out.payload_len = l4_remaining - 8;
    } else {
        return false;  // ICMP and friends: decoded to IP layer only
    }

    out.decoded = true;
    return true;
}

}  // namespace nids
