#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <functional>

namespace patty {

struct MemoryRegion {
    uintptr_t base = 0;
    size_t size = 0;
    uint32_t protection = 0;
    uint32_t type = 0;
    std::string name;

    uintptr_t end() const { return base + size; }

    bool isExecutable() const {
        // PAGE_EXECUTE variants: 0x10, 0x20, 0x40, 0x80
        return (protection & 0xF0) != 0;
    }

    bool isWritable() const {
        // PAGE_READWRITE (0x04), PAGE_WRITECOPY (0x08),
        // PAGE_EXECUTE_READWRITE (0x40), PAGE_EXECUTE_WRITECOPY (0x80)
        return (protection & 0x04) || (protection & 0x08) ||
               (protection & 0x40) || (protection & 0x80);
    }

    bool isReadable() const {
        // Anything except PAGE_NOACCESS (0x01) and PAGE_GUARD
        return protection != 0 && !(protection & 0x01) && !(protection & 0x100);
    }
};

} // namespace patty
