#include "pcap_reader.h"

#include <cstring>
#include <fstream>
#include <stdexcept>

namespace nids {

namespace {

// The classic pcap global header is 24 bytes:
//   u32 magic, u16 version_major, u16 version_minor,
//   i32 thiszone, u32 sigfigs, u32 snaplen, u32 network
constexpr size_t kGlobalHeaderLen = 24;
constexpr size_t kRecordHeaderLen = 16;  // ts_sec, ts_usec, incl_len, orig_len

constexpr uint32_t kMagicLE = 0xa1b2c3d4;  // written little-endian, read straight
constexpr uint32_t kMagicBE = 0xd4c3b2a1;  // written big-endian -> we must swap

uint32_t rd32(const uint8_t* p, bool swap) {
    uint32_t v;
    std::memcpy(&v, p, sizeof(v));
    if (swap) v = __builtin_bswap32(v);
    return v;
}

}  // namespace

PcapReader::PcapReader(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("cannot open capture file: " + path);

    buffer_.assign(std::istreambuf_iterator<char>(in),
                   std::istreambuf_iterator<char>());

    if (buffer_.size() < kGlobalHeaderLen)
        throw std::runtime_error("file too small to hold a pcap global header");

    uint32_t magic;
    std::memcpy(&magic, buffer_.data(), sizeof(magic));
    if (magic == kMagicLE) {
        swapped_ = false;
    } else if (magic == kMagicBE) {
        swapped_ = true;
    } else {
        throw std::runtime_error("not a classic pcap file (bad magic number)");
    }

    link_type_ = rd32(buffer_.data() + 20, swapped_);
    if (link_type_ != 1)  // LINKTYPE_ETHERNET
        throw std::runtime_error("unsupported link type; only Ethernet (1) is handled");

    // Walk the per-record headers, bounds-checking every step so a truncated or
    // malformed file can never make us read past the buffer.
    size_t off = kGlobalHeaderLen;
    while (off + kRecordHeaderLen <= buffer_.size()) {
        const uint8_t* h = buffer_.data() + off;
        RawRecord rec;
        rec.ts_sec   = rd32(h + 0,  swapped_);
        rec.ts_usec  = rd32(h + 4,  swapped_);
        uint32_t incl = rd32(h + 8,  swapped_);
        rec.orig_len = rd32(h + 12, swapped_);

        off += kRecordHeaderLen;
        if (off + incl > buffer_.size()) break;  // truncated final record

        rec.data = buffer_.data() + off;
        rec.len  = incl;
        records_.push_back(rec);
        off += incl;
    }
}

}  // namespace nids
