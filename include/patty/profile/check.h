#pragma once

#include "../types.h"

#include "../memory/region.h"
#include "../scan/match.h"

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace patty {

enum class CheckStatus {
    Ok,          // one match, or several that all resolve to the same value
    Ambiguous,   // several distinct values
    Missing,     // no match at all
    Unresolved,  // matches, but every resolve chain failed (e.g. a null global)
};

std::string_view to_string(CheckStatus status);

struct PatternCheck {
    std::string name;
    CheckStatus status = CheckStatus::Missing;
    std::vector<Match> matches;
    Address value = 0;           // when Ok
    std::optional<Address> rva;  // value - module base, when Ok and a module was given
};

struct CheckReport {
    std::vector<PatternCheck> patterns;
    std::optional<Module> module;
    size_t bytes_scanned = 0;
    double elapsed_ms = 0;
    bool cancelled = false;

    size_t count(CheckStatus status) const;
    bool all_ok() const { return count(CheckStatus::Ok) == patterns.size(); }
};

} // namespace patty
