#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <span>
#include <stdexcept>
#include <optional>

namespace patty {

struct PatternByte {
    uint8_t value = 0;
    bool wildcard = false;
};

enum class ResolveType {
    None,
    RIPRelative,    // addr + 4 + *(int32_t*)addr
    Dereference,    // *(uintptr_t*)addr
    Add,            // addr + extra_value
};

struct ResolveStep {
    ResolveType type = ResolveType::None;
    int64_t extra = 0; // used for Add type
};

// Compiled pattern for fast matching — separate value/mask arrays
// Match condition: (data[i] & mask[i]) == values[i] for all i
// Wildcard bytes have mask=0x00, fixed bytes have mask=0xFF
struct CompiledPattern {
    std::vector<uint8_t> values;
    std::vector<uint8_t> mask;
    size_t first_fixed = 0;     // Index of first non-wildcard byte
    uint8_t first_byte = 0;     // Value of first non-wildcard byte
    bool has_fixed = false;     // Has at least one non-wildcard
};

class Pattern {
public:
    std::string name;
    std::string description;
    std::vector<PatternByte> bytes;
    int32_t result_offset = 0;
    std::vector<ResolveStep> resolve_chain;

    Pattern() = default;

    static Pattern fromAOB(std::string_view aob, std::string_view name = "");
    static Pattern fromIDA(std::string_view sig, std::string_view name = "");
    static Pattern fromByteMask(std::span<const uint8_t> bytes,
                                 std::string_view mask,
                                 std::string_view name = "");
    static Pattern fromString(std::string_view str, std::string_view name = "");
    static Pattern fromSSOString(std::string_view str, std::string_view name = "");

    bool isValid() const;
    size_t size() const { return bytes.size(); }
    bool matchAt(const uint8_t* data, size_t data_size) const;
    CompiledPattern compile() const;
    static bool matchCompiled(const uint8_t* data, const CompiledPattern& cp);

    Pattern& withOffset(int32_t offset) {
        result_offset = offset;
        return *this;
    }

    Pattern& withResolve(ResolveType type, int64_t extra = 0) {
        resolve_chain.push_back({type, extra});
        return *this;
    }

    Pattern& withName(std::string_view n) {
        name = n;
        return *this;
    }

    Pattern& withDescription(std::string_view d) {
        description = d;
        return *this;
    }

private:
    static uint8_t parseHexByte(char hi, char lo);
    static uint8_t hexCharToNibble(char c);
};

} // namespace patty
