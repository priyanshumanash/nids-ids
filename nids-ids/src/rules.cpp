#include "rules.h"

#include <cctype>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace nids {

namespace {

std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Decode a content string body (without the surrounding quotes), resolving
// \xHH, \\, and \" escapes into raw bytes.
bool decode_content(const std::string& raw, std::string& out, std::string& error) {
    out.clear();
    for (size_t i = 0; i < raw.size(); ++i) {
        char c = raw[i];
        if (c != '\\') { out.push_back(c); continue; }
        if (i + 1 >= raw.size()) { error = "dangling backslash in content"; return false; }
        char n = raw[++i];
        if (n == '\\') { out.push_back('\\'); }
        else if (n == '"') { out.push_back('"'); }
        else if (n == 'n') { out.push_back('\n'); }
        else if (n == 'r') { out.push_back('\r'); }
        else if (n == 't') { out.push_back('\t'); }
        else if (n == 'x') {
            if (i + 2 >= raw.size()) { error = "truncated \\xHH escape"; return false; }
            int hi = hex_val(raw[i + 1]), lo = hex_val(raw[i + 2]);
            if (hi < 0 || lo < 0) { error = "invalid hex in \\xHH escape"; return false; }
            out.push_back(static_cast<char>((hi << 4) | lo));
            i += 2;
        } else {
            error = std::string("unknown escape \\") + n;
            return false;
        }
    }
    if (out.empty()) { error = "content is empty"; return false; }
    return true;
}

}  // namespace

bool parse_rule(const std::string& line_in, Rule& out, std::string& error) {
    error.clear();
    std::string line = trim(line_in);
    if (line.empty() || line[0] == '#') return false;  // comment/blank: skip, no error

    out = Rule{};

    // Split off an optional "; msg:\"...\"" suffix first.
    size_t semi = line.find(';');
    std::string head = trim(semi == std::string::npos ? line : line.substr(0, semi));
    std::string tail = semi == std::string::npos ? "" : trim(line.substr(semi + 1));

    if (!tail.empty()) {
        size_t m = tail.find("msg:");
        if (m != std::string::npos) {
            size_t q1 = tail.find('"', m);
            size_t q2 = (q1 == std::string::npos) ? std::string::npos
                                                  : tail.find('"', q1 + 1);
            if (q1 != std::string::npos && q2 != std::string::npos)
                out.msg = tail.substr(q1 + 1, q2 - q1 - 1);
        }
    }

    // head = action proto port "content"
    std::istringstream is(head);
    std::string action, proto, port;
    if (!(is >> action >> proto >> port)) {
        error = "expected: <action> <proto> <port> \"content\"";
        return false;
    }
    if (action != "alert") { error = "unsupported action '" + action + "' (only 'alert')"; return false; }

    if (proto == "tcp") out.proto = L4Proto::TCP;
    else if (proto == "udp") out.proto = L4Proto::UDP;
    else if (proto == "ip" || proto == "any") out.proto = L4Proto::Unknown;
    else { error = "unknown proto '" + proto + "'"; return false; }

    if (port == "any") {
        out.dst_port = kPortAny;
    } else {
        try {
            int p = std::stoi(port);
            if (p < 0 || p > 65535) throw std::out_of_range("port");
            out.dst_port = static_cast<uint16_t>(p);
        } catch (...) { error = "bad port '" + port + "'"; return false; }
    }

    // The content is the remainder of head, between the first and last quote.
    size_t q1 = head.find('"');
    size_t q2 = head.rfind('"');
    if (q1 == std::string::npos || q1 == q2) { error = "missing quoted content"; return false; }
    std::string raw = head.substr(q1 + 1, q2 - q1 - 1);
    if (!decode_content(raw, out.content, error)) return false;

    return true;
}

std::vector<Rule> load_rules(const std::string& path) {
    std::ifstream in(path);
    if (!in) throw std::runtime_error("cannot open rules file: " + path);

    std::vector<Rule> rules;
    std::string line;
    int lineno = 0;
    while (std::getline(in, line)) {
        ++lineno;
        Rule r;
        std::string err;
        if (parse_rule(line, r, err)) {
            rules.push_back(std::move(r));
        } else if (!err.empty()) {
            throw std::runtime_error("rules:" + std::to_string(lineno) + ": " + err);
        }
    }
    return rules;
}

}  // namespace nids
