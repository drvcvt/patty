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
        return protection != 0 && !(protection & 0x01) && !(protection & 0x100);
    }

    static MemoryRegion make(uintptr_t base, size_t size,
                              bool r = true, bool w = false, bool x = false,
                              const std::string& name = "") {
        MemoryRegion reg;
        reg.base = base;
        reg.size = size;
        reg.name = name;
        uint32_t prot = 0;
        if (x && w)      prot = 0x40; // PAGE_EXECUTE_READWRITE
        else if (x)      prot = 0x20; // PAGE_EXECUTE_READ
        else if (w)      prot = 0x04; // PAGE_READWRITE
        else if (r)      prot = 0x02; // PAGE_READONLY
        else             prot = 0x01; // PAGE_NOACCESS
        reg.protection = prot;
        return reg;
    }
};

} // namespace patty
