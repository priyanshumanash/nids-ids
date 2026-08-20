#include "engine.h"

namespace nids {

Engine::Engine(std::vector<Rule> rules) : rules_(std::move(rules)) {
    pattern_to_rule_.reserve(rules_.size());
    for (size_t i = 0; i < rules_.size(); ++i) {
        int pid = automaton_.add_pattern(rules_[i].content);
        rules_[i].content_pattern_id = pid;
        // pid equals the current size of pattern_to_rule_, so push in order.
        pattern_to_rule_.push_back(static_cast<int>(i));
    }
    automaton_.build();
}

void Engine::evaluate(const Packet& pkt, std::vector<Alert>& out) const {
    if (!pkt.decoded || pkt.payload == nullptr || pkt.payload_len == 0)
        return;

    auto hits = automaton_.scan(pkt.payload, pkt.payload_len);
    for (const auto& hit : hits) {
        int rule_idx = pattern_to_rule_[hit.pattern_id];
        const Rule& r = rules_[rule_idx];

        // Non-content constraints. Unknown proto means "tcp or udp".
        if (r.proto != L4Proto::Unknown && r.proto != pkt.proto) continue;
        if (r.dst_port != kPortAny && r.dst_port != pkt.dst_port) continue;

        Alert a;
        a.rule      = &r;
        a.packet    = pkt;
        a.packet.payload = nullptr;   // don't retain the payload view in the alert
        a.packet.payload_len = 0;
        a.match_end = hit.end_offset;
        out.push_back(a);
    }
}

}  // namespace nids
