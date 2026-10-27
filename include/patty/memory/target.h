#pragma once

#include "region.h"
#include "../types.h"

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
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
    virtual bool read(Address address, void* buffer, size_t size) = 0;

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
    virtual std::span<const uint8_t> view(Address /*address*/, size_t /*size*/) { return {}; }

    // A whole value: read<float>(address), read<Player>(address).
    template <Readable T>
    std::optional<T> read(Address address) {
        T value{};
        if (!read(address, &value, sizeof(T)))
            return std::nullopt;
        return value;
    }

    // Whatever a Remote points to: read(player.target) is an optional<Player>.
    template <Readable T, typename Word>
    std::optional<T> read(Remote<T, Word> pointer) {
        return read<T>(pointer.address());
    }

    // Follows members through Remote<> pointers and reads the last one:
    // read(player, &Player::target, &Player::health) is player->target->health.
    // Empty if any read fails or a pointer on the way is null.
    template <typename T, typename Word, typename M, typename... Rest>
    auto read(Remote<T, Word> object, M T::* member, Rest... rest) {
        const auto field = object[member];
        if constexpr (sizeof...(Rest) == 0) {
            return read(field);
        } else {
            static_assert(is_remote_v<M>, "only Remote<> members can be followed further");
            using Result = decltype(read(std::declval<M>(), rest...));
            const auto next = read(field);
            if (!next || !*next)
                return Result{};
            return read(*next, rest...);
        }
    }

    // `count` consecutive values, or nothing if they are not all readable.
    template <Readable T>
    std::vector<T> read_array(Address address, size_t count) {
        std::vector<T> values(count);
        if (count > 0 && !read(address, values.data(), count * sizeof(T)))
            return {};
        return values;
    }

    template <Readable T, typename Word>
    std::vector<T> read_array(Remote<T, Word> first, size_t count) {
        return read_array<T>(first.address(), count);
    }

    // Reads a pointer of the target's width.
    std::optional<Address> read_pointer(Address address);

    // Returns the bytes, or an empty vector if the range is not fully readable.
    std::vector<uint8_t> read_bytes(Address address, size_t size);

    // Reads up to the first NUL or `max_length` bytes, stopping early at the
    // end of readable memory. nullopt if not even the first byte is readable.
    std::optional<std::string> read_string(Address address, size_t max_length = 256);

    template <typename Word>
    std::optional<std::string> read_string(Remote<char, Word> text, size_t max_length = 256) {
        return read_string(text.address(), max_length);
    }

    std::optional<Region> region_at(Address address);

    // Case-insensitive lookup by name.
    std::optional<Module> module(std::string_view name);
    std::optional<Module> module_at(Address address);

protected:
    Target() = default;
    Target(const Target&) = default;
    Target(Target&&) = default;
    Target& operator=(const Target&) = default;
    Target& operator=(Target&&) = default;
};

} // namespace patty
