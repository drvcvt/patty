#pragma once

#include "../types.h"

#include <cstddef>
#include <cstdint>
#include <string>

namespace patty {

// A contiguous, readable piece of a target's address space.
struct Region {
    Address base = 0;
    size_t size = 0;
    bool readable = true;
    bool writable = false;
    bool executable = false;
    // File basename for mapped files ("Game.exe", "libc.so.6"), section name for
    // images (".text"), kernel pseudo names ("[heap]"), or empty for anonymous memory.
    std::string name;

    Address end() const { return base + size; }
    bool contains(Address address) const { return address >= base && address < end(); }
};

// A loaded module: the address range spanned by all regions of one mapped file.
struct Module {
    std::string name;
    Address base = 0;
    size_t size = 0;

    Address end() const { return base + size; }
    bool contains(Address address) const { return address >= base && address < end(); }
};

} // namespace patty
