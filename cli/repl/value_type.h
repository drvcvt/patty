#pragma once

// Value types the shell understands: i8..u64, float, double, ptr, str.

#include <nlohmann/json.hpp>

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace patty::cli {

enum class Compare { Equal, NotEqual, Less, Greater, LessEqual, GreaterEqual, Changed, Unchanged, Increased, Decreased };

class ValueType {
public:
    enum class Kind { Signed, Unsigned, Float, Double, Pointer, String };

    // Throws patty::Error naming the valid types.
    static ValueType parse(std::string_view name);
    // i32 for integers, float when the text has a decimal point.
    static ValueType guess(std::string_view value);

    const std::string& name() const { return m_name; }
    Kind kind() const { return m_kind; }
    // Bytes one value occupies; pointers depend on the target, strings have no fixed size.
    size_t size(size_t pointer_size) const;

    // "87.5" -> the float's bytes. Throws patty::Error on text that is not a value of this type.
    std::vector<uint8_t> encode(std::string_view text, size_t pointer_size) const;
    std::string format(std::span<const uint8_t> bytes) const;
    nlohmann::json to_json(std::span<const uint8_t> bytes) const;

    // `reference` is ignored for Changed/Unchanged/Increased/Decreased against itself;
    // for those it holds the previous value.
    bool compare(std::span<const uint8_t> current, Compare op, std::span<const uint8_t> reference) const;

private:
    std::string m_name;
    Kind m_kind = Kind::Signed;
    size_t m_size = 4;
};

// "==", "!=", "<", ">", "<=", ">=", "changed", "unchanged", "increased", "decreased".
Compare parse_compare(std::string_view text);
// True for the ops that compare against an earlier value rather than a given one.
bool needs_previous(Compare op);

} // namespace patty::cli
