#pragma once
// pcap_reader.h — a minimal reader for the classic libpcap capture format.
//
// We parse the on-disk format by hand rather than link libpcap. That keeps the
// build dependency-free and means the file-format parsing itself is real,
// reviewable work rather than a call into someone else's library.

#include <cstdint>
#include <string>
#include <vector>

namespace nids {

// One raw capture record: a slice of the file plus its timestamp/length header.
struct RawRecord {
    uint32_t ts_sec  = 0;
    uint32_t ts_usec = 0;
    uint32_t orig_len = 0;          // length on the wire
    const uint8_t* data = nullptr;  // points into PcapReader's file buffer
    uint32_t len = 0;               // captured length (may be < orig_len)
};

class PcapReader {
public:
    // Loads and validates the whole file up front. Throws std::runtime_error
    // on a bad magic number, truncated header, or unsupported link type.
    explicit PcapReader(const std::string& path);

    // Link-layer type from the global header. 1 = Ethernet (LINKTYPE_ETHERNET).
    uint32_t link_type() const { return link_type_; }

    // True if the file's byte order differed from ours and we swapped fields.
    bool byte_swapped() const { return swapped_; }

    const std::vector<RawRecord>& records() const { return records_; }

private:
    std::vector<uint8_t> buffer_;      // owns the file bytes
    std::vector<RawRecord> records_;   // views into buffer_
    uint32_t link_type_ = 0;
    bool swapped_ = false;
};

}  // namespace nids
