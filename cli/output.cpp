#include "output.h"

#include <cstdio>
#include <iomanip>
#include <ostream>
#include <sstream>

namespace patty::cli {

void Output::record(std::string_view table_line, const std::vector<std::string>& fields, const json& object) {
    switch (m_mode) {
    case Mode::Table:
        m_out << table_line << '\n';
        break;
    case Mode::Lines:
        for (size_t i = 0; i < fields.size(); ++i)
            m_out << (i ? "\t" : "") << fields[i];
        m_out << '\n';
        break;
    case Mode::Json:
        m_out << object.dump() << '\n';
        break;
    }
}

std::string hex(uint64_t value, size_t pointer_size) {
    char buffer[24];
    std::snprintf(buffer, sizeof(buffer), "0x%0*llX", static_cast<int>(pointer_size * 2),
                  static_cast<unsigned long long>(value));
    return buffer;
}

std::string hex_short(uint64_t value) {
    char buffer[24];
    std::snprintf(buffer, sizeof(buffer), "0x%llX", static_cast<unsigned long long>(value));
    return buffer;
}

std::string human_size(size_t bytes) {
    constexpr const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    double value = static_cast<double>(bytes);
    size_t unit = 0;
    while (value >= 1024 && unit + 1 < std::size(units)) {
        value /= 1024;
        ++unit;
    }
    std::ostringstream out;
    out << std::setprecision(value < 10 && unit ? 2 : 3) << value << ' ' << units[unit];
    return out.str();
}

std::string permissions(const Region& region) {
    return {region.readable ? 'r' : '-', region.writable ? 'w' : '-', region.executable ? 'x' : '-'};
}

void print_hexdump(std::ostream& out, Address address, std::span<const uint8_t> bytes, size_t pointer_size) {
    for (size_t line = 0; line < bytes.size(); line += 16) {
        out << hex(address + line, pointer_size) << "  ";
        std::string ascii;
        for (size_t i = 0; i < 16; ++i) {
            if (line + i < bytes.size()) {
                const uint8_t b = bytes[line + i];
                char cell[4];
                std::snprintf(cell, sizeof(cell), "%02X ", b);
                out << cell;
                ascii.push_back(b >= 0x20 && b < 0x7F ? static_cast<char>(b) : '.');
            } else {
                out << "   ";
            }
            if (i == 7)
                out << ' ';
        }
        out << ' ' << ascii << '\n';
    }
}

} // namespace patty::cli
