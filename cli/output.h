#pragma once

// How results reach the user: a table on a terminal, tab-separated lines in a
// pipe, JSON Lines on request.

#include <patty/patty.h>
#include <nlohmann/json.hpp>

#include <cstdint>
#include <iosfwd>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace patty::cli {

using json = nlohmann::json;

enum class Mode {
    Table,  // for people: aligned, with $N labels and summaries
    Lines,  // for pipes: one tab-separated line per result, address first
    Json,   // one JSON object per line
};

class Output {
public:
    Output(std::ostream& out, std::ostream& err, Mode mode) : m_out(out), m_err(err), m_mode(mode) {}

    Mode mode() const { return m_mode; }
    bool table() const { return m_mode == Mode::Table; }

    // One result. Each mode uses its own form; the other two are ignored.
    void record(std::string_view table_line, const std::vector<std::string>& fields, const json& object);

    // Summaries and progress ("3 matches", "opened ..."). On stdout in table
    // mode, on stderr otherwise so pipes only carry results.
    std::ostream& info() { return table() ? m_out : m_err; }
    // Text meant for a person whatever the mode (help, hex dumps).
    std::ostream& text() { return m_out; }
    std::ostream& err() { return m_err; }

private:
    std::ostream& m_out;
    std::ostream& m_err;
    Mode m_mode;
};

// Zero-padded to the target's pointer width: 0x0000000140001000.
std::string hex(uint64_t value, size_t pointer_size = 8);
// Unpadded: 0x1A.
std::string hex_short(uint64_t value);
std::string human_size(size_t bytes);
// "r-x"
std::string permissions(const Region& region);
// 16 bytes per line with an ASCII column.
void print_hexdump(std::ostream& out, Address address, std::span<const uint8_t> bytes, size_t pointer_size);

} // namespace patty::cli
