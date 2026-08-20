#pragma once
// engine.h — wires the rule set to the Aho-Corasick automaton and evaluates
// packets against it.
//
// Every rule's content is registered as one pattern in a shared automaton, so a
// packet's payload is scanned exactly once regardless of how many rules exist.
// When a content hit comes back, the engine checks that rule's non-content
// constraints (proto, dst port) against the packet before firing an alert.

#include <string>
#include <vector>

#include "ac.h"
#include "packet.h"
#include "rules.h"

namespace nids {

struct Alert {
    const Rule* rule;      // the rule that fired
    Packet      packet;    // a copy of the packet header fields (not the payload view)
    uint32_t    match_end; // offset in payload where the content matched
};

class Engine {
public:
    // Takes ownership of the rules and compiles the automaton. Rules whose
    // content is a duplicate still each get their own id, so every rule can fire.
    explicit Engine(std::vector<Rule> rules);

    // Evaluate one packet, appending any alerts it triggers to `out`.
    void evaluate(const Packet& pkt, std::vector<Alert>& out) const;

    size_t rule_count() const { return rules_.size(); }

private:
    std::vector<Rule> rules_;
    AhoCorasick automaton_;
    // pattern id -> index into rules_. Because add_pattern hands out ids in call
    // order, this is just a parallel vector.
    std::vector<int> pattern_to_rule_;
};

}  // namespace nids
