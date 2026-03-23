#pragma once

#include "../region/region.h"
#include <cstdint>
#include <string>
#include <vector>

namespace patty {

struct Match {
    uintptr_t address = 0;      // Where the pattern matched
    uintptr_t resolved = 0;     // After applying resolve chain (0 if not resolved)
    std::string pattern_name;   // Which pattern matched
    MemoryRegion region;        // Which region it was found in

    bool hasResolved() const { return resolved != 0; }
};

struct ScanResult {
    std::string pattern_name;
    std::vector<Match> matches;
    double elapsed_ms = 0;
    size_t bytes_scanned = 0;
    size_t regions_scanned = 0;
};

struct MultiScanResult {
    std::vector<ScanResult> results;
    double total_elapsed_ms = 0;
    size_t total_bytes_scanned = 0;
};

} // namespace patty
