#include "value_type.h"
#include "../common.h"
#include "../output.h"

#include <patty/error.h>

#include <charconv>
#include <cstring>
#include <sstream>

namespace patty::cli {

namespace {

struct Known {
    const char* name;
    ValueType::Kind kind;
    size_t size;
};

constexpr Known kTypes[] = {
    {"i8", ValueType::Kind::Signed, 1},    {"i16", ValueType::Kind::Signed, 2},
    {"i32", ValueType::Kind::Signed, 4},   {"i64", ValueType::Kind::Signed, 8},
    {"u8", ValueType::Kind::Unsigned, 1},  {"u16", ValueType::Kind::Unsigned, 2},
    {"u32", ValueType::Kind::Unsigned, 4}, {"u64", ValueType::Kind::Unsigned, 8},
    {"float", ValueType::Kind::Float, 4},  {"double", ValueType::Kind::Double, 8},
    {"ptr", ValueType::Kind::Pointer, 0},  {"str", ValueType::Kind::String, 0},
};

uint64_t raw_bits(std::span<const uint8_t> bytes) {
    uint64_t value = 0;
    std::memcpy(&value, bytes.data(), std::min(bytes.size(), sizeof(value)));
    return value;
}

int64_t as_signed(std::span<const uint8_t> bytes) {
    const uint64_t raw = raw_bits(bytes);
    const int shift = static_cast<int>(64 - bytes.size() * 8);
    return shift >= 64 ? 0 : static_cast<int64_t>(raw << shift) >> shift;
}

double as_double(std::span<const uint8_t> bytes, ValueType::Kind kind) {
    if (kind == ValueType::Kind::Float) {
        float f;
        std::memcpy(&f, bytes.data(), sizeof(f));
        return f;
    }
    double d;
    std::memcpy(&d, bytes.data(), sizeof(d));
    return d;
}

template <typename T>
int order(T a, T b) {
    return a < b ? -1 : (b < a ? 1 : 0);
}

} // namespace

ValueType ValueType::parse(std::string_view name) {
    for (const auto& known : kTypes) {
        if (name == known.name) {
            ValueType type;
            type.m_name = known.name;
            type.m_kind = known.kind;
            type.m_size = known.size;
            return type;
        }
    }
    throw Error("unknown type " + std::string(name) + " (i8 i16 i32 i64 u8 u16 u32 u64 float double ptr str)");
}

ValueType ValueType::guess(std::string_view value) {
    return parse(value.find('.') != std::string_view::npos ? "float" : "i32");
}

size_t ValueType::size(size_t pointer_size) const {
    return m_kind == Kind::Pointer ? pointer_size : m_size;
}

std::vector<uint8_t> ValueType::encode(std::string_view text, size_t pointer_size) const {
    std::vector<uint8_t> bytes;
    if (m_kind == Kind::String) {
        bytes.assign(text.begin(), text.end());
        return bytes;
    }
    if (m_kind == Kind::Float || m_kind == Kind::Double) {
        double number = 0;
        const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), number);
        if (error != std::errc() || end != text.data() + text.size())
            throw Error("not a number: " + std::string(text));
        bytes.resize(m_size);
        if (m_kind == Kind::Float) {
            const auto f = static_cast<float>(number);
            std::memcpy(bytes.data(), &f, sizeof(f));
        } else {
            std::memcpy(bytes.data(), &number, sizeof(number));
        }
        return bytes;
    }
    const auto number = parse_number(text);
    if (!number)
        throw Error("not a number: " + std::string(text));
    bytes.resize(size(pointer_size));
    std::memcpy(bytes.data(), &*number, bytes.size());
    return bytes;
}

std::string ValueType::format(std::span<const uint8_t> bytes) const {
    switch (m_kind) {
    case Kind::Signed:   return std::to_string(as_signed(bytes));
    case Kind::Unsigned: return std::to_string(raw_bits(bytes));
    case Kind::Pointer:  return hex(raw_bits(bytes), bytes.size());
    case Kind::String:   return std::string(bytes.begin(), bytes.end());
    case Kind::Float:
    case Kind::Double:   break;
    }
    std::ostringstream out;
    out << as_double(bytes, m_kind);
    return out.str();
}

nlohmann::json ValueType::to_json(std::span<const uint8_t> bytes) const {
    switch (m_kind) {
    case Kind::Signed:   return as_signed(bytes);
    case Kind::Unsigned: return raw_bits(bytes);
    case Kind::Float:
    case Kind::Double:   return as_double(bytes, m_kind);
    case Kind::Pointer:
    case Kind::String:   break;
    }
    return format(bytes);
}

bool ValueType::compare(std::span<const uint8_t> current, Compare op, std::span<const uint8_t> reference) const {
    int sign = 0;
    switch (m_kind) {
    case Kind::Signed:   sign = order(as_signed(current), as_signed(reference)); break;
    case Kind::Unsigned:
    case Kind::Pointer:  sign = order(raw_bits(current), raw_bits(reference)); break;
    case Kind::Float:
    case Kind::Double:   sign = order(as_double(current, m_kind), as_double(reference, m_kind)); break;
    case Kind::String:
        sign = order(std::string_view(reinterpret_cast<const char*>(current.data()), current.size()),
                     std::string_view(reinterpret_cast<const char*>(reference.data()), reference.size()));
        break;
    }
    switch (op) {
    case Compare::Equal:
    case Compare::Unchanged:    return sign == 0;
    case Compare::NotEqual:
    case Compare::Changed:      return sign != 0;
    case Compare::Less:
    case Compare::Decreased:    return sign < 0;
    case Compare::Greater:
    case Compare::Increased:    return sign > 0;
    case Compare::LessEqual:    return sign <= 0;
    case Compare::GreaterEqual: return sign >= 0;
    }
    return false;
}

Compare parse_compare(std::string_view text) {
    static const std::pair<std::string_view, Compare> ops[] = {
        {"==", Compare::Equal},        {"!=", Compare::NotEqual},      {"<", Compare::Less},
        {">", Compare::Greater},       {"<=", Compare::LessEqual},     {">=", Compare::GreaterEqual},
        {"changed", Compare::Changed}, {"unchanged", Compare::Unchanged},
        {"increased", Compare::Increased}, {"decreased", Compare::Decreased},
    };
    for (const auto& [name, op] : ops)
        if (text == name)
            return op;
    throw Error("unknown comparison " + std::string(text) +
                " (== != < > <= >= changed unchanged increased decreased)");
}

bool needs_previous(Compare op) {
    return op == Compare::Changed || op == Compare::Unchanged || op == Compare::Increased ||
           op == Compare::Decreased;
}

} // namespace patty::cli
