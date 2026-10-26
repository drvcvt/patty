#pragma once

#include "region.h"

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace patty {

// Something with an address space that patty can read: a live process or a
// file image. Implementations only provide the virtual functions; everything
// else is built on top of them.
class Target {
public:
    virtual ~Target() = default;

    // Copies exactly `size` bytes starting at `address` into `buffer`.
    // Returns false if any of those bytes cannot be read.
    virtual bool read(uintptr_t address, void* buffer, size_t size) = 0;

    // Readable regions, sorted by base address. Live processes re-query this
    // on every call, so it reflects the current mappings.
    virtual std::vector<Region> regions() = 0;

    // Mapped files, sorted by base address. The default groups regions by
    // name and skips anonymous and "[pseudo]" regions.
    virtual std::vector<Module> modules();

    // 8 for 64-bit targets, 4 for 32-bit ones.
    virtual size_t pointer_size() const { return 8; }

    // Short human-readable label, e.g. "pid 4242 (Game.exe)" or "Game.exe (PE)".
    virtual std::string describe() const = 0;

    // Direct access to `size` bytes at `address` without copying, valid as
    // long as the target lives. Empty when the target cannot offer that
    // (live processes) or the range is not contiguous in memory; use read().
    virtual std::span<const uint8_t> view(uintptr_t /*address*/, size_t /*size*/) { return {}; }

    template <typename T>
    std::optional<T> read(uintptr_t address) {
        static_assert(std::is_trivially_copyable_v<T>, "read<T> needs a trivially copyable T");
        T value{};
        if (!read(address, &value, sizeof(T)))
            return std::nullopt;
        return value;
    }

    // Reads a pointer of the target's width.
    std::optional<uintptr_t> read_pointer(uintptr_t address);

    // Returns the bytes, or an empty vector if the range is not fully readable.
    std::vector<uint8_t> read_bytes(uintptr_t address, size_t size);

    // Reads up to the first NUL or `max_length` bytes, stopping early at the
    // end of readable memory. nullopt if not even the first byte is readable.
    std::optional<std::string> read_string(uintptr_t address, size_t max_length = 256);

    std::optional<Region> region_at(uintptr_t address);

    // Case-insensitive lookup by name.
    std::optional<Module> module(std::string_view name);
    std::optional<Module> module_at(uintptr_t address);

protected:
    Target() = default;
    Target(const Target&) = default;
    Target(Target&&) = default;
    Target& operator=(const Target&) = default;
    Target& operator=(Target&&) = default;
};

} // namespace patty
