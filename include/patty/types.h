#pragma once

#include <compare>
#include <cstddef>
#include <cstdint>
#include <type_traits>
#include <version>

#ifdef __cpp_lib_format
#include <format>
#endif

namespace patty {

// An address in the target's address space. Not something you can
// dereference here; read it through a Target.
using Address = std::uintptr_t;

// Types that can be copied out of another process byte for byte. Raw
// pointers are excluded on purpose: a pointer read from the target is only
// meaningful there, use Remote<T> for it.
template <typename T>
concept Readable = std::is_trivially_copyable_v<T> && !std::is_pointer_v<T> && !std::is_reference_v<T>;

// A pointer as it is stored in the target, typed by what it points to. It has
// the size and layout of the target's pointer, so it can sit in the structs
// you read:
//
//   struct Player {
//       float health;
//       int level;
//       patty::Remote<char> name;
//       patty::Remote<Player> target;
//   };
//
// Word is the target's pointer width: Remote<T> for 64-bit, Remote32<T> for 32-bit.
template <typename T, typename Word = std::uint64_t>
struct Remote {
    static_assert(std::is_unsigned_v<Word>, "Remote's Word must be an unsigned integer");

    Word raw = 0;

    constexpr Remote() = default;
    constexpr explicit Remote(Address address) : raw(static_cast<Word>(address)) {}

    constexpr Address address() const { return static_cast<Address>(raw); }
    constexpr explicit operator bool() const { return raw != 0; }

    // Arithmetic in elements, like T*: `players + 2` is two Players further.
    constexpr Remote operator+(std::ptrdiff_t n) const {
        return Remote(address() + static_cast<Address>(n) * sizeof(T));
    }
    constexpr Remote operator-(std::ptrdiff_t n) const { return *this + -n; }

    // The same address seen as another type.
    template <typename U>
    constexpr Remote<U, Word> as() const { return Remote<U, Word>(address()); }

    // The address of a member: player[&Player::health] is a Remote<float>.
    // (U is T; spelling it as a parameter keeps Remote<char> etc. valid.)
    template <typename M, typename U = T>
        requires std::is_same_v<U, T> && std::is_class_v<U>
    Remote<M, Word> operator[](M U::* member) const;

    constexpr auto operator<=>(const Remote&) const = default;
};

template <typename T>
using Remote32 = Remote<T, std::uint32_t>;

template <typename T>
inline constexpr bool is_remote_v = false;
template <typename T, typename Word>
inline constexpr bool is_remote_v<Remote<T, Word>> = true;

// Byte offset of a data member: offset_of(&Player::target) == 0x10.
template <typename T, typename M>
std::size_t offset_of(M T::* member) {
    static_assert(std::is_standard_layout_v<T>, "offset_of needs a standard-layout type");
    static const T object{};
    return static_cast<std::size_t>(reinterpret_cast<const std::byte*>(&(object.*member)) -
                                    reinterpret_cast<const std::byte*>(&object));
}

template <typename T, typename Word>
template <typename M, typename U>
    requires std::is_same_v<U, T> && std::is_class_v<U>
Remote<M, Word> Remote<T, Word>::operator[](M U::* member) const {
    return Remote<M, Word>(address() + offset_of(member));
}

} // namespace patty

#ifdef __cpp_lib_format
// std::format("{:#x}", remote) formats the address like an integer.
template <typename T, typename Word>
struct std::formatter<patty::Remote<T, Word>> : std::formatter<patty::Address> {
    auto format(const patty::Remote<T, Word>& remote, std::format_context& context) const {
        return std::formatter<patty::Address>::format(remote.address(), context);
    }
};
#endif
