#include "patty/core/pattern.h"
#include <algorithm>
#include <cctype>
#include <cstring>
#include <sstream>

namespace patty {

uint8_t Pattern::hexCharToNibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    throw std::invalid_argument(std::string("Invalid hex char: ") + c);
}

uint8_t Pattern::parseHexByte(char hi, char lo) {
    return (hexCharToNibble(hi) << 4) | hexCharToNibble(lo);
}

Pattern Pattern::fromAOB(std::string_view aob, std::string_view name) {
    Pattern p;
    p.name = name;

    std::string token;
    size_t i = 0;
    while (i < aob.size()) {
        // Skip whitespace
        if (std::isspace(static_cast<unsigned char>(aob[i]))) {
            ++i;
            continue;
        }

        // Collect token
        token.clear();
        while (i < aob.size() && !std::isspace(static_cast<unsigned char>(aob[i]))) {
            token += aob[i++];
        }

        if (token.empty()) continue;

        // Check for wildcard
        if (token == "?" || token == "??" || token == "**") {
            p.bytes.push_back({0, true});
        } else if (token.size() == 2) {
            p.bytes.push_back({parseHexByte(token[0], token[1]), false});
        } else if (token.size() == 1) {
            // Single hex digit — treat as 0X
            p.bytes.push_back({hexCharToNibble(token[0]), false});
        } else {
            throw std::invalid_argument("Invalid AOB token: " + token);
        }
    }

    return p;
}

Pattern Pattern::fromIDA(std::string_view sig, std::string_view name) {
    // IDA format is the same as AOB but uses single '?' for wildcards
    // We handle both in fromAOB already
    return fromAOB(sig, name);
}

Pattern Pattern::fromByteMask(std::span<const uint8_t> bytes,
                               std::string_view mask,
                               std::string_view name) {
    Pattern p;
    p.name = name;

    if (bytes.size() != mask.size()) {
        throw std::invalid_argument("Bytes and mask must be the same length");
    }

    for (size_t i = 0; i < bytes.size(); ++i) {
        if (mask[i] == '?' || mask[i] == '.') {
            p.bytes.push_back({0, true});
        } else {
            p.bytes.push_back({bytes[i], false});
        }
    }

    return p;
}

Pattern Pattern::fromString(std::string_view str, std::string_view name) {
    Pattern p;
    p.name = name;
    p.bytes.reserve(str.size());
    for (char c : str)
        p.bytes.push_back({static_cast<uint8_t>(c), false});
    return p;
}

Pattern Pattern::fromSSOString(std::string_view str, std::string_view name) {
    // MSVC x64 std::string SSO layout (32 bytes):
    //   [0..15]  inline buffer OR pointer to heap (if len >= 16)
    //   [16..23] size (uint64_t)
    //   [24..31] capacity (uint64_t)
    // If len < 16: data is inline in [0..15], capacity = 15
    // If len >= 16: [0..7] = heap pointer (wildcard), rest follows

    Pattern p;
    p.name = name;

    uint64_t len = str.size();

    if (len < 16) {
        // SSO inline: match the string bytes, wildcard the rest of the buffer
        for (size_t i = 0; i < 16; ++i) {
            if (i < len)
                p.bytes.push_back({static_cast<uint8_t>(str[i]), false});
            else if (i == len)
                p.bytes.push_back({0x00, false}); // null terminator
            else
                p.bytes.push_back({0, true});
        }
    } else {
        // Heap-allocated: pointer is unknown, wildcard it
        for (size_t i = 0; i < 8; ++i)
            p.bytes.push_back({0, true});
        // Pad to 16 bytes (unused inline buffer area)
        for (size_t i = 0; i < 8; ++i)
            p.bytes.push_back({0, true});
    }

    // Size field (8 bytes, little-endian)
    auto* len_bytes = reinterpret_cast<const uint8_t*>(&len);
    for (size_t i = 0; i < 8; ++i)
        p.bytes.push_back({len_bytes[i], false});

    // Capacity field: for SSO it's 15, for heap it's unknown
    if (len < 16) {
        uint64_t cap = 15;
        auto* cap_bytes = reinterpret_cast<const uint8_t*>(&cap);
        for (size_t i = 0; i < 8; ++i)
            p.bytes.push_back({cap_bytes[i], false});
    } else {
        for (size_t i = 0; i < 8; ++i)
            p.bytes.push_back({0, true});
    }

    return p;
}

bool Pattern::isValid() const {
    if (bytes.empty()) return false;
    // Must have at least one non-wildcard byte
    return std::any_of(bytes.begin(), bytes.end(),
                       [](const PatternByte& b) { return !b.wildcard; });
}

bool Pattern::matchAt(const uint8_t* data, size_t data_size) const {
    if (bytes.size() > data_size) return false;

    for (size_t i = 0; i < bytes.size(); ++i) {
        if (!bytes[i].wildcard && bytes[i].value != data[i])
            return false;
    }
    return true;
}

CompiledPattern Pattern::compile() const {
    CompiledPattern cp;
    cp.values.resize(bytes.size());
    cp.mask.resize(bytes.size());

    for (size_t i = 0; i < bytes.size(); ++i) {
        if (bytes[i].wildcard) {
            cp.values[i] = 0x00;
            cp.mask[i] = 0x00;
        } else {
            cp.values[i] = bytes[i].value;
            cp.mask[i] = 0xFF;
            if (!cp.has_fixed) {
                cp.first_fixed = i;
                cp.first_byte = bytes[i].value;
                cp.has_fixed = true;
            }
        }
    }

    return cp;
}

bool Pattern::matchCompiled(const uint8_t* data, const CompiledPattern& cp) {
    for (size_t i = 0; i < cp.values.size(); ++i) {
        if ((data[i] & cp.mask[i]) != cp.values[i])
            return false;
    }
    return true;
}

} // namespace patty
