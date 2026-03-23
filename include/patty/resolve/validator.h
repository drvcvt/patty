#pragma once

#include "../memory/provider.h"
#include <cstdint>
#include <functional>

namespace patty::resolve {

using Validator = std::function<bool(IMemoryProvider& mem, uintptr_t addr)>;

inline Validator isReadable() {
    return [](IMemoryProvider& mem, uintptr_t addr) -> bool {
        uint8_t byte;
        return mem.read(addr, &byte, 1);
    };
}

inline Validator isValidPointer(bool require_aligned = true) {
    return [require_aligned](IMemoryProvider& mem, uintptr_t addr) -> bool {
        auto ptr = mem.read<uintptr_t>(addr);
        if (!ptr || *ptr == 0) return false;
        if (require_aligned && (*ptr % (mem.is64Bit() ? 8 : 4)) != 0) return false;
        uint8_t byte;
        return mem.read(*ptr, &byte, 1);
    };
}

inline Validator isAsciiString(size_t min_len = 1, size_t max_len = 256) {
    return [min_len, max_len](IMemoryProvider& mem, uintptr_t addr) -> bool {
        std::vector<char> buf(max_len + 1, 0);
        if (!mem.read(addr, buf.data(), max_len)) return false;

        size_t len = 0;
        for (size_t i = 0; i < max_len; ++i) {
            if (buf[i] == '\0') break;
            if (buf[i] < 0x20 || buf[i] > 0x7E) return false;
            ++len;
        }
        return len >= min_len;
    };
}

inline Validator allOf(std::initializer_list<Validator> validators) {
    std::vector<Validator> v(validators);
    return [v = std::move(v)](IMemoryProvider& mem, uintptr_t addr) -> bool {
        for (const auto& validator : v) {
            if (!validator(mem, addr)) return false;
        }
        return true;
    };
}

inline Validator anyOf(std::initializer_list<Validator> validators) {
    std::vector<Validator> v(validators);
    return [v = std::move(v)](IMemoryProvider& mem, uintptr_t addr) -> bool {
        for (const auto& validator : v) {
            if (validator(mem, addr)) return true;
        }
        return false;
    };
}

} // namespace patty::resolve
