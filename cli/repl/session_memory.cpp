#include "session.h"
#include "../output.h"

#include <cctype>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <ostream>
#include <sstream>

namespace patty::cli {

namespace {

// gdb's x/NFU: count, format letter, unit letter, in any order after the count.
struct Format {
    size_t count = 1;
    char format = 'x';
    size_t unit = 4;
};

Format parse_format(const std::string& suffix, size_t pointer_size) {
    Format f;
    size_t i = 0;
    if (i < suffix.size() && std::isdigit(static_cast<unsigned char>(suffix[i]))) {
        f.count = 0;
        while (i < suffix.size() && std::isdigit(static_cast<unsigned char>(suffix[i])))
            f.count = f.count * 10 + static_cast<size_t>(suffix[i++] - '0');
    }
    bool unit_given = false;
    for (; i < suffix.size(); ++i) {
        switch (const char c = suffix[i]) {
        case 'b': f.unit = 1; unit_given = true; break;
        case 'h': f.unit = 2; unit_given = true; break;
        case 'w': f.unit = 4; unit_given = true; break;
        case 'g': f.unit = 8; unit_given = true; break;
        case 'x': case 'd': case 'u': case 'f': case 'a': case 's': case 'c':
            f.format = c;
            break;
        default:
            throw Error(std::string("unknown x format letter '") + c + "' (formats xdufasc, units bhwg)");
        }
    }
    if (f.format == 'a')
        f.unit = pointer_size;
    else if (f.format == 'c')
        f.unit = 1;
    else if (f.format == 'f' && unit_given && f.unit != 4 && f.unit != 8)
        throw Error("floats are w (4) or g (8) bytes");
    if (f.count == 0 || f.count > 4096)
        throw Error("count must be 1..4096");
    return f;
}

std::string format_unit(const uint8_t* data, const Format& f) {
    uint64_t raw = 0;
    std::memcpy(&raw, data, f.unit);
    std::ostringstream out;
    switch (f.format) {
    case 'x':
        out << "0x" << std::hex << std::uppercase << std::setw(static_cast<int>(f.unit * 2)) << std::setfill('0') << raw;
        break;
    case 'u':
        out << raw;
        break;
    case 'd': {
        const int shift = static_cast<int>(64 - f.unit * 8);
        out << (static_cast<int64_t>(raw << shift) >> shift);
        break;
    }
    case 'f':
        if (f.unit == 8) {
            double d;
            std::memcpy(&d, data, 8);
            out << d;
        } else {
            float v;
            std::memcpy(&v, data, 4);
            out << v;
        }
        break;
    case 'c': {
        const auto c = static_cast<unsigned char>(raw);
        out << static_cast<int>(c);
        if (c >= 0x20 && c < 0x7F)
            out << " '" << static_cast<char>(c) << "'";
        break;
    }
    }
    return out.str();
}

} // namespace

void Session::cmd_examine(Args& args) {
    auto& t = target();
    const auto address = static_cast<uintptr_t>(eval(args.rest()));
    const size_t width = t.pointer_size();

    if (args.suffix.empty()) {
        const auto bytes = t.read_bytes(address, 64);
        if (bytes.empty())
            throw Error("cannot read 64 bytes at " + hex(address, width));
        print_hexdump(m_out, address, bytes, width);
        return;
    }

    const auto f = parse_format(args.suffix, width);
    if (f.format == 's') {
        uintptr_t at = address;
        for (size_t i = 0; i < f.count; ++i) {
            const auto text = t.read_string(at, 512);
            if (!text)
                throw Error("cannot read at " + hex(at, width));
            m_out << hex(at, width) << "  \"" << *text << "\"\n";
            at += text->size() + 1;
        }
        return;
    }

    const auto bytes = t.read_bytes(address, f.count * f.unit);
    if (bytes.empty())
        throw Error("cannot read " + std::to_string(f.count * f.unit) + " bytes at " + hex(address, width));

    if (f.format == 'a') {
        for (size_t i = 0; i < f.count; ++i) {
            uint64_t value = 0;
            std::memcpy(&value, bytes.data() + i * f.unit, f.unit);
            m_out << hex(address + i * f.unit, width) << "  " << hex(value, width);
            if (const auto place = where(static_cast<uintptr_t>(value)); place != "unmapped")
                m_out << "  " << place;
            m_out << '\n';
        }
        return;
    }

    const size_t per_line = f.format == 'c' ? 8 : std::max<size_t>(1, 16 / f.unit);
    for (size_t i = 0; i < f.count; ++i) {
        if (i % per_line == 0)
            m_out << (i ? "\n" : "") << hex(address + i * f.unit, width) << ' ';
        m_out << ' ' << format_unit(bytes.data() + i * f.unit, f);
    }
    m_out << '\n';
}

void Session::cmd_print(Args& args) {
    const auto value = static_cast<uintptr_t>(eval(args.rest()));
    const size_t width = m_target ? m_target->pointer_size() : 8;
    m_out << remember(value) << " = " << hex(value, width);
    if (m_target)
        m_out << "  " << where(value);
    m_out << '\n';
}

void Session::cmd_probe(Args& args) {
    size_t size = 0x100;
    if (!args.done() && args.tokens[args.next].text == "-s") {
        args.take();
        const auto parsed = parse_number(args.take().text);
        if (!parsed || *parsed == 0)
            throw Error("-s needs a size");
        size = static_cast<size_t>(*parsed);
    }
    const auto address = static_cast<uintptr_t>(eval(args.rest()));
    print_probe(m_out, Scanner(target()).probe(address, size), target().pointer_size());
}

void Session::cmd_dump(Args& args) {
    const std::string path = args.take().text;
    const auto size = parse_number(args.take().text);
    if (!size || *size == 0)
        throw Error("usage: dump <file> <size> <expr>");
    const auto address = static_cast<uintptr_t>(eval(args.rest()));
    const auto bytes = target().read_bytes(address, static_cast<size_t>(*size));
    if (bytes.empty())
        throw Error("cannot read " + std::to_string(*size) + " bytes at " + hex(address, target().pointer_size()));
    std::ofstream out(path, std::ios::binary);
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!out.flush())
        throw Error("cannot write " + path);
    m_out << "wrote " << human_size(bytes.size()) << " to " << path << '\n';
}

} // namespace patty::cli
