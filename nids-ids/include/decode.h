#pragma once
// decode.h — turn raw Ethernet frames into a Packet.

#include "packet.h"
#include "pcap_reader.h"

namespace nids {

// Decode a single captured record into `out`. Returns true if we reached at
// least the transport layer for a protocol we understand (TCP/UDP over IPv4).
// On any truncation or unsupported layer we set out.decoded = false and return
// false — the caller can still see whatever fields we managed to fill.
bool decode(const RawRecord& rec, Packet& out);

}  // namespace nids
