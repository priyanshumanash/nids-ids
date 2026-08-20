#pragma once
// ac.h — Aho-Corasick multi-pattern string matcher.
//
// Register N byte-string patterns, build once, then scan any buffer in a single
// O(text length) pass that reports every pattern that occurs anywhere in it.
// This is the heart of a signature IDS: instead of running each rule's content
// match separately, all contents share one automaton.

#include <cstdint>
#include <string>
#include <vector>

namespace nids {

class AhoCorasick {
public:
    // Register a pattern and get back its id (0-based, in insertion order).
    // Must be called before build(). Empty patterns are rejected (return -1).
    int add_pattern(const std::string& pattern);

    // Freeze the automaton: build goto edges' failure links and merged outputs.
    // Call exactly once, after all add_pattern() calls.
    void build();

    // One match hit: which pattern, and where it ends in the scanned buffer.
    struct Hit {
        int      pattern_id;
        uint32_t end_offset;  // index one past the last matched byte
    };

    // Scan `data` and return every hit. Safe to call repeatedly and from
    // multiple threads once build() has run (the automaton is read-only).
    std::vector<Hit> scan(const uint8_t* data, uint32_t len) const;

    size_t pattern_count() const { return pattern_lengths_.size(); }

private:
    // Transitions stored as a flat map per node keeps memory sane vs. a dense
    // 256-way table per node when the pattern set is small.
    struct Node {
        // goto edges: byte -> child index (256 slots, -1 = none).
        int32_t next[256];
        int32_t fail = 0;
        // pattern ids that end at this node (after failure-link merge).
        std::vector<int> outputs;
        Node() { for (int i = 0; i < 256; ++i) next[i] = -1; }
    };

    std::vector<Node> nodes_{1};          // node 0 is the root
    std::vector<uint32_t> pattern_lengths_;
    bool built_ = false;
};

}  // namespace nids
