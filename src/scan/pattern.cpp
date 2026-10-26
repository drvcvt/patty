#include "patty/scan/pattern.h"
#include "patty/error.h"

#include <algorithm>
#include <cctype>
#include <cstdio>

namespace patty {

namespace {

int nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

} // namespace

void Pattern::finish() {
    const auto first = std::find(m_mask.begin(), m_mask.end(), uint8_t{0xFF});
    if (first == m_mask.end())
        throw Error(m_values.empty() ? "empty pattern" : "pattern has no fixed byte");
    m_anchor = static_cast<size_t>(first - m_mask.begin());
}

Pattern Pattern::aob(std::string_view text) {
    Pattern p;
    size_t i = 0;
    while (i < text.size()) {
        if (std::isspace(static_cast<unsigned char>(text[i]))) {
            ++i;
            continue;
        }
        const size_t start = i;
        while (i < text.size() && !std::isspace(static_cast<unsigned char>(text[i])))
            ++i;
        const auto token = text.substr(start, i - start);

        if (token == "?" || token == "??" || token == "*" || token == "**") {
            p.m_values.push_back(0);
            p.m_mask.push_back(0);
            continue;
        }
        const int hi = token.size() == 2 ? nibble(token[0]) : -1;
        const int lo = token.size() == 2 ? nibble(token[1]) : -1;
        if (hi < 0 || lo < 0)
            throw Error("invalid byte '" + std::string(token) + "' in pattern \"" +
                        std::string(text) + "\" (expected two hex digits or a wildcard)");
        p.m_values.push_back(static_cast<uint8_t>(hi << 4 | lo));
        p.m_mask.push_back(0xFF);
    }
    p.finish();
    return p;
}

Pattern Pattern::raw(std::span<const uint8_t> bytes, std::string_view mask) {
    if (!mask.empty() && mask.size() != bytes.size())
        throw Error("pattern mask length " + std::to_string(mask.size()) +
                    " does not match " + std::to_string(bytes.size()) + " bytes");
    Pattern p;
    for (size_t i = 0; i < bytes.size(); ++i) {
        const bool wildcard = !mask.empty() && (mask[i] == '?' || mask[i] == '.');
        p.m_values.push_back(wildcard ? 0 : bytes[i]);
        p.m_mask.push_back(wildcard ? 0 : 0xFF);
    }
    p.finish();
    return p;
}

Pattern Pattern::text(std::string_view text) {
    return raw({reinterpret_cast<const uint8_t*>(text.data()), text.size()});
}

Pattern Pattern::msvc_string(std::string_view text) {
    // MSVC x64 std::string, 32 bytes:
    //   [0..15]  inline characters + NUL when size < 16, else heap pointer + unused
    //   [16..23] size
    //   [24..31] capacity: 15 when inline, unknown otherwise
    std::vector<uint8_t> bytes(32, 0);
    std::string mask(32, '?');
    const uint64_t size = text.size();

    if (size < 16) {
        for (size_t i = 0; i <= size; ++i) {
            bytes[i] = i < size ? static_cast<uint8_t>(text[i]) : 0;
            mask[i] = 'x';
        }
        const uint64_t capacity = 15;
        std::memcpy(bytes.data() + 24, &capacity, 8);
        std::fill(mask.begin() + 24, mask.end(), 'x');
    }
    std::memcpy(bytes.data() + 16, &size, 8);
    std::fill(mask.begin() + 16, mask.begin() + 24, 'x');
    return raw(bytes, mask);
}

Pattern Pattern::integer(uint64_t value, size_t size) {
    if (size == 0 || size > 8)
        throw Error("integer pattern size must be 1..8, got " + std::to_string(size));
    uint8_t bytes[8];
    for (size_t i = 0; i < 8; ++i)
        bytes[i] = static_cast<uint8_t>(value >> (i * 8));
    return raw({bytes, size});
}

Pattern& Pattern::named(std::string_view name) {
    m_name = name;
    return *this;
}

Pattern& Pattern::add(int64_t offset) {
    m_steps.push_back({ResolveStep::Kind::Add, offset});
    return *this;
}

Pattern& Pattern::rip() {
    m_steps.push_back({ResolveStep::Kind::Rip, 0});
    return *this;
}

Pattern& Pattern::rip(int64_t operand_offset) {
    return add(operand_offset).rip();
}

Pattern& Pattern::deref() {
    m_steps.push_back({ResolveStep::Kind::Deref, 0});
    return *this;
}

std::string Pattern::to_string() const {
    std::string out;
    out.reserve(m_values.size() * 3);
    char hex[4];
    for (size_t i = 0; i < m_values.size(); ++i) {
        if (i) out.push_back(' ');
        if (m_mask[i] == 0) {
            out += "??";
        } else {
            std::snprintf(hex, sizeof(hex), "%02X", m_values[i]);
            out += hex;
        }
    }
    return out;
}

} // namespace patty
