#pragma once

#include "../memory/provider.h"
#include <cstdint>
#include <optional>

namespace patty::resolve {

// addr + instr_size + *(int32_t*)addr
inline std::optional<uintptr_t> ripRelative(IMemoryProvider& mem, uintptr_t addr,
                                             int32_t instr_size = 4) {
    auto disp = mem.read<int32_t>(addr);
    if (!disp) return std::nullopt;
    return addr + instr_size + static_cast<uintptr_t>(*disp);
}

} // namespace patty::resolve
