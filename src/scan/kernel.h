#pragma once

// The search kernels behind Scanner. Not installed.

#include "patty/scan/pattern.h"

#include <cstdint>
#include <span>
#include <vector>

namespace patty::detail {

enum class Kernel { Scalar, Sse2, Avx2 };

// A pattern prepared for searching: the two rarest fixed bytes (by how often
// they occur in real x86-64 binaries) are checked first, the full pattern only
// where both agree.
struct Needle {
    explicit Needle(const Pattern& pattern);

    const Pattern* pattern;
    size_t first = 0;
    size_t second = 0;
    uint8_t first_byte = 0;
    uint8_t second_byte = 0;
    bool has_second = false;  // false when the pattern has a single fixed byte
};

// The fastest kernel this CPU supports.
Kernel best_kernel();
const char* name(Kernel kernel);
bool supported(Kernel kernel);

// Appends every start s with s < limit and s + size <= data.size() where the
// pattern matches, in ascending order.
void find_matches(const Needle& needle, std::span<const uint8_t> data, size_t limit,
                  std::vector<size_t>& starts, Kernel kernel = best_kernel());

} // namespace patty::detail
