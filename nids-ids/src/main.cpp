// main.cpp — CLI: read a pcap, run the rule engine, print alerts.
//
//   nids <rules-file> <capture.pcap>
//
// Reads the whole capture, decodes each frame, evaluates it against the rules,
// and prints one line per alert plus a short summary.

#include <cstdio>
#include <exception>
#include <vector>

#include "decode.h"
#include "engine.h"
#include "packet.h"
#include "pcap_reader.h"
#include "rules.h"

using namespace nids;

static const char* proto_name(L4Proto p) {
    switch (p) {
        case L4Proto::TCP: return "TCP";
        case L4Proto::UDP: return "UDP";
        default:           return "?";
    }
}

int main(int argc, char** argv) {
    if (argc != 3) {
        std::fprintf(stderr, "usage: %s <rules-file> <capture.pcap>\n", argv[0]);
        return 2;
    }

    try {
        std::vector<Rule> rules = load_rules(argv[1]);
        Engine engine(std::move(rules));
        PcapReader reader(argv[2]);

        std::fprintf(stderr, "loaded %zu rules; %zu packets in capture\n",
                     engine.rule_count(), reader.records().size());

        std::vector<Alert> alerts;
        Packet pkt;
        size_t decoded = 0, pkt_no = 0;

        for (const auto& rec : reader.records()) {
            ++pkt_no;
            if (!decode(rec, pkt)) continue;
            ++decoded;

            size_t before = alerts.size();
            engine.evaluate(pkt, alerts);

            for (size_t i = before; i < alerts.size(); ++i) {
                const Alert& a = alerts[i];
                std::printf(
                    "[ALERT] pkt#%zu  %s %s:%u -> %s:%u  \"%s\"  (match@%u)\n",
                    pkt_no,
                    proto_name(a.packet.proto),
                    ip_to_string(a.packet.src_ip).c_str(), a.packet.src_port,
                    ip_to_string(a.packet.dst_ip).c_str(), a.packet.dst_port,
                    a.rule->msg.empty() ? "(no msg)" : a.rule->msg.c_str(),
                    a.match_end);
            }
        }

        std::fprintf(stderr,
                     "done: %zu/%zu packets decoded, %zu alert(s)\n",
                     decoded, pkt_no, alerts.size());
        return alerts.empty() ? 0 : 1;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "error: %s\n", e.what());
        return 3;
    }
}
