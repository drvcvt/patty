#pragma once

#include "../memory/provider.h"
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace patty::resolve {

inline std::optional<uintptr_t> pointerChain(IMemoryProvider& mem, uintptr_t base,
                                              std::span<const int64_t> offsets) {
    uintptr_t current = base;

    for (size_t i = 0; i < offsets.size(); ++i) {
        current += static_cast<uintptr_t>(offsets[i]);

        if (i < offsets.size() - 1) {
            std::optional<uint64_t> ptr;
            if (mem.is64Bit()) {
                ptr = mem.read<uint64_t>(current);
            } else {
                auto v32 = mem.read<uint32_t>(current);
                if (v32) ptr = static_cast<uint64_t>(*v32);
            }

            if (!ptr || *ptr == 0) return std::nullopt;
            current = static_cast<uintptr_t>(*ptr);
        }
    }

    return current;
}

inline std::optional<uintptr_t> pointerChain(IMemoryProvider& mem, uintptr_t base,
                                              std::initializer_list<int64_t> offsets) {
    std::vector<int64_t> v(offsets);
    return pointerChain(mem, base, std::span<const int64_t>(v));
}

} // namespace patty::resolve
