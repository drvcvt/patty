#pragma once

#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace patty {

// One step applied to a match to get from "where the bytes are" to "what you
// actually want", e.g. the global a `mov rax, [rip+disp]` refers to.
struct ResolveStep {
    enum class Kind {
        Add,    // address += value
        Rip,    // address = address + 4 + *(int32_t*)address   (rel32 operand)
        Deref,  // address = *(pointer*)address
    };
    Kind kind = Kind::Add;
    int64_t value = 0;

    bool operator==(const ResolveStep&) const = default;
};

// A byte pattern with optional wildcards, plus resolve steps.
// Factories throw patty::Error on malformed input or patterns without a
// single fixed byte. Builder methods return *this, so they chain:
//
//   auto global = Pattern::aob("48 8B 05 ?? ?? ?? ?? 48 85 C0").rip(3).named("Global");
class Pattern {
public:
    // "48 8B 05 ?? ?? ?? ??": hex bytes separated by spaces, "?" or "??" for any byte.
    // IDA and Cheat Engine style signatures both parse.
    static Pattern aob(std::string_view text);

    // Raw bytes with a mask: 'x' = must match, '?' or '.' = any byte.
    // An empty mask means every byte must match.
    static Pattern raw(std::span<const uint8_t> bytes, std::string_view mask = {});

    // The exact bytes of a string, without a terminator.
    static Pattern text(std::string_view text);

    // An MSVC x64 std::string object holding `text` (32 bytes: buffer or heap
    // pointer, size, capacity). Finds the string objects, not the characters.
    static Pattern msvc_string(std::string_view text);

    // A little-endian integer of `size` bytes (1..8).
    static Pattern integer(uint64_t value, size_t size = 8);

    // The exact in-memory bytes of any trivially copyable value.
    template <typename T>
    static Pattern value(const T& v) {
        static_assert(std::is_trivially_copyable_v<T>, "Pattern::value needs a trivially copyable T");
        uint8_t bytes[sizeof(T)];
        std::memcpy(bytes, &v, sizeof(T));
        return raw(bytes);
    }

    Pattern& named(std::string_view name);
    Pattern& add(int64_t offset);
    // Treats the 4 bytes at the current address as a rel32 operand.
    Pattern& rip();
    // Shorthand for add(operand_offset).rip().
    Pattern& rip(int64_t operand_offset);
    Pattern& deref();

    const std::string& name() const { return m_name; }
    size_t size() const { return m_values.size(); }
    std::span<const uint8_t> values() const { return m_values; }
    // 0xFF for bytes that must match, 0x00 for wildcards.
    std::span<const uint8_t> mask() const { return m_mask; }
    std::span<const ResolveStep> steps() const { return m_steps; }

    bool matches(const uint8_t* data) const {
        for (size_t i = 0; i < m_values.size(); ++i)
            if ((data[i] & m_mask[i]) != m_values[i])
                return false;
        return true;
    }

    // "48 8B 05 ?? ?? ?? ??"
    std::string to_string() const;

private:
    Pattern() = default;
    void finish();

    std::string m_name;
    std::vector<uint8_t> m_values;
    std::vector<uint8_t> m_mask;
    std::vector<ResolveStep> m_steps;
};

} // namespace patty
