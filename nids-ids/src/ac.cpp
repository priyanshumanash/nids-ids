#include "ac.h"

#include <queue>

namespace nids {

int AhoCorasick::add_pattern(const std::string& pattern) {
    if (built_ || pattern.empty()) return -1;

    int id = static_cast<int>(pattern_lengths_.size());
    int cur = 0;
    for (unsigned char c : pattern) {
        int& nxt = nodes_[cur].next[c];
        if (nxt == -1) {
            nxt = static_cast<int>(nodes_.size());
            nodes_.emplace_back();
        }
        cur = nxt;
    }
    nodes_[cur].outputs.push_back(id);
    pattern_lengths_.push_back(static_cast<uint32_t>(pattern.size()));
    return id;
}

void AhoCorasick::build() {
    // Standard BFS construction of failure links. The root's children fail to
    // the root; deeper nodes fail to the longest proper suffix that is also a
    // prefix of some pattern. We also merge outputs along failure links so a
    // single node's `outputs` lists every pattern that ends there.
    std::queue<int> q;

    for (int c = 0; c < 256; ++c) {
        int child = nodes_[0].next[c];
        if (child == -1) {
            nodes_[0].next[c] = 0;  // root loops to itself on a miss
        } else {
            nodes_[child].fail = 0;
            q.push(child);
        }
    }

    while (!q.empty()) {
        int u = q.front();
        q.pop();

        // Merge outputs reachable via this node's failure link.
        int f = nodes_[u].fail;
        for (int out_id : nodes_[f].outputs)
            nodes_[u].outputs.push_back(out_id);

        for (int c = 0; c < 256; ++c) {
            int v = nodes_[u].next[c];
            if (v == -1) {
                // Precompute the goto for a miss: follow the failure link's edge.
                nodes_[u].next[c] = nodes_[nodes_[u].fail].next[c];
            } else {
                nodes_[v].fail = nodes_[nodes_[u].fail].next[c];
                q.push(v);
            }
        }
    }

    built_ = true;
}

std::vector<AhoCorasick::Hit> AhoCorasick::scan(const uint8_t* data,
                                                uint32_t len) const {
    std::vector<Hit> hits;
    if (!built_ || data == nullptr) return hits;

    int state = 0;
    for (uint32_t i = 0; i < len; ++i) {
        state = nodes_[state].next[data[i]];
        const auto& outs = nodes_[state].outputs;
        if (!outs.empty()) {
            for (int pid : outs)
                hits.push_back({pid, i + 1});
        }
    }
    return hits;
}

}  // namespace nids
