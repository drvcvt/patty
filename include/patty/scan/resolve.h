#pragma once

#include "../memory/target.h"
#include "pattern.h"

#include <cstdint>
#include <initializer_list>
#include <optional>
#include <span>

namespace patty {

// Target of a rel32 operand at `operand`: operand + operand_size + disp32.
// `operand_size` is 4 plus any immediate that follows the displacement.
std::optional<uintptr_t> rip_relative(Target& target, uintptr_t operand, int64_t operand_size = 4);

// Applies resolve steps to `address`. nullopt if a read fails or a
// dereferenced pointer is null.
std::optional<uintptr_t> resolve(Target& target, uintptr_t address,
                                 std::span<const ResolveStep> steps);

// Cheat Engine style pointer chain: base + o0 -> read -> + o1 -> read -> ... + oN.
// Every offset but the last is followed by a pointer read.
std::optional<uintptr_t> pointer_chain(Target& target, uintptr_t base,
                                       std::span<const int64_t> offsets);

inline std::optional<uintptr_t> pointer_chain(Target& target, uintptr_t base,
                                              std::initializer_list<int64_t> offsets) {
    return pointer_chain(target, base, std::span<const int64_t>(offsets.begin(), offsets.size()));
}

} // namespace patty
