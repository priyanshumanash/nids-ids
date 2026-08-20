#pragma once
// rules.h — a deliberately small, Snort-flavoured rule format.
//
// One rule per line:
//
//     <action> <proto> <dst_port> "<content>" ; msg:"<message>"
//
// examples:
//     alert tcp 80  "GET /admin"      ; msg:"admin path probe"
//     alert tcp any "../"             ; msg:"path traversal attempt"
//     alert udp 53  "\x00\x01\x00\x00"; msg:"suspicious DNS flags"
//
//   action : only `alert` for now (the hook is here to grow drop/log later)
//   proto  : tcp | udp | ip(any)
//   port   : a number, or `any`
//   content: a double-quoted byte string; supports \xHH hex escapes and \\ \"
//
// This is intentionally a subset of real Snort syntax — enough to be a working,
// honest signature engine and a clean base to extend (pcre, offsets, flow
// state, thresholds) without hand-waving over the parts that matter.

#include <cstdint>
#include <string>
#include <vector>

#include "packet.h"

namespace nids {

constexpr uint16_t kPortAny = 0xffff;  // sentinel: matches any destination port

struct Rule {
    L4Proto     proto = L4Proto::Unknown;  // Unknown == match tcp or udp
    uint16_t    dst_port = kPortAny;
    std::string content;                   // decoded (post-escape) match bytes
    std::string msg;                       // human-readable alert text
    int         content_pattern_id = -1;   // filled in when registered with the AC automaton
};

// Parse a single rule line. Returns false (and sets `error`) on malformed input.
// Blank lines and lines beginning with '#' are treated as comments: the function
// returns false but leaves `error` empty, so the caller can distinguish
// "skip this line" from "reject this file".
bool parse_rule(const std::string& line, Rule& out, std::string& error);

// Load every rule from a file. Throws std::runtime_error with a line-numbered
// message on the first genuine parse error.
std::vector<Rule> load_rules(const std::string& path);

}  // namespace nids
