#pragma once

#include "../types.h"

#include "../memory/region.h"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace patty {

struct Match {
    Address address = 0;              // where the pattern starts
    std::optional<Address> resolved;  // after the pattern's resolve steps, if it has any
    bool resolve_failed = false;      // the pattern has steps, but a read on the way failed
    std::string pattern;              // name of the pattern that matched
    Region region;                    // region the match lies in

    // What the match points at: the resolved address, or the match itself.
    Address value() const { return resolved.value_or(address); }

    // value() as a typed pointer: match.as<Remote<Player>>() for a global
    // that holds the player pointer.
    template <typename T, typename Word = std::uint64_t>
    Remote<T, Word> as() const { return Remote<T, Word>(value()); }
};

// Matches of one pattern, sorted by address. Iterable like a vector.
struct ScanResult {
    std::string pattern;
    std::vector<Match> matches;
    size_t bytes_scanned = 0;
    double elapsed_ms = 0;
    bool cancelled = false;  // ScanOptions::cancel was raised; matches are partial

    auto begin() const { return matches.begin(); }
    auto end() const { return matches.end(); }
    size_t size() const { return matches.size(); }
    bool empty() const { return matches.empty(); }
    const Match& operator[](size_t i) const { return matches[i]; }
};

enum class FieldKind { Zero, Integer, Float, Pointer, VTable, String, Unknown };

// "zero", "small_int", "float", "pointer", "vtable", "string_ptr", "unknown"
std::string_view to_string(FieldKind kind);

struct ProbeField {
    size_t offset = 0;
    uint64_t raw = 0;
    FieldKind kind = FieldKind::Unknown;
    std::string detail;  // string contents, float value, pointer target, ...
};

// Pointer-sized fields of an object, each classified by what it looks like.
struct Probe {
    Address address = 0;
    size_t size = 0;  // bytes actually read, clipped to the containing region
    std::vector<ProbeField> fields;
};

} // namespace patty
