#include "session.h"
#include "value_type.h"
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

int Session::cmd_read(Args& args) {
    size_t count = 1;
    if (!args.done() && args.tokens[args.next].text == "-n") {
        args.take();
        const auto parsed = parse_number(args.take().text);
        if (!parsed || *parsed == 0 || *parsed > 4096)
            throw Error("-n needs a count from 1 to 4096");
        count = static_cast<size_t>(*parsed);
    }
    const auto type = ValueType::parse(args.take().text);
    auto& t = target();
    const size_t width = t.pointer_size();
    const size_t size = type.size(width);
    const auto starts = addresses(args);
    const bool many = starts.size() * count > 1;

    m_hits.clear();
    for (const Address start : starts) {
        for (size_t i = 0; i < count; ++i) {
            const Address at = start + i * size;
            std::vector<uint8_t> bytes;
            if (type.kind() == ValueType::Kind::String) {
                if (const auto text = t.read_string(at, 512))
                    bytes.assign(text->begin(), text->end());
                else if (!many)
                    throw Error("cannot read at " + hex(at, width));
                else
                    continue;
            } else {
                bytes = t.read_bytes(at, size);
                if (bytes.empty()) {
                    if (!many)
                        throw Error("cannot read " + std::to_string(size) + " bytes at " + hex(at, width));
                    m_out.err() << "cannot read " << hex(at, width) << '\n';
                    continue;
                }
            }
            const auto shown = type.format(bytes);
            const auto table_value = type.kind() == ValueType::Kind::String ? "\"" + shown + "\"" : shown;
            m_out.record(hex(at, width) + "  " + table_value, {hex(at, width), shown},
                         {{"address", hex(at, width)}, {"type", type.name()}, {"value", type.to_json(bytes)}});
            m_hits.push_back({at, std::move(bytes)});
        }
    }
    return m_hits.empty() ? 2 : 0;
}

int Session::cmd_examine(Args& args) {
    auto& t = target();
    const auto address = static_cast<Address>(eval(args.rest()));
    auto& out = m_out.text();
    const size_t width = t.pointer_size();

    if (args.suffix.empty()) {
        const auto bytes = t.read_bytes(address, 64);
        if (bytes.empty())
            throw Error("cannot read 64 bytes at " + hex(address, width));
        print_hexdump(out, address, bytes, width);
        return 0;
    }

    const auto f = parse_format(args.suffix, width);
    if (f.format == 's') {
        Address at = address;
        for (size_t i = 0; i < f.count; ++i) {
            const auto text = t.read_string(at, 512);
            if (!text)
                throw Error("cannot read at " + hex(at, width));
            out << hex(at, width) << "  \"" << *text << "\"\n";
            at += text->size() + 1;
        }
        return 0;
    }

    const auto bytes = t.read_bytes(address, f.count * f.unit);
    if (bytes.empty())
        throw Error("cannot read " + std::to_string(f.count * f.unit) + " bytes at " + hex(address, width));

    if (f.format == 'a') {
        for (size_t i = 0; i < f.count; ++i) {
            uint64_t value = 0;
            std::memcpy(&value, bytes.data() + i * f.unit, f.unit);
            out << hex(address + i * f.unit, width) << "  " << hex(value, width);
            if (const auto place = where(static_cast<Address>(value)); place != "unmapped")
                out << "  " << place;
            out << '\n';
        }
        return 0;
    }

    const size_t per_line = f.format == 'c' ? 8 : std::max<size_t>(1, 16 / f.unit);
    for (size_t i = 0; i < f.count; ++i) {
        if (i % per_line == 0)
            out << (i ? "\n" : "") << hex(address + i * f.unit, width) << ' ';
        out << ' ' << format_unit(bytes.data() + i * f.unit, f);
    }
    out << '\n';
    return 0;
}

int Session::cmd_print(Args& args) {
    const size_t width = m_target ? m_target->pointer_size() : 8;
    const auto values = addresses(args);
    const auto modules = m_target ? m_target->modules() : std::vector<Module>{};
    const auto regions = m_target ? m_target->regions() : std::vector<Region>{};
    for (const Address value : values) {
        const auto place = m_target ? where(value, modules, regions) : std::string{};
        m_out.record(remember(value) + " = " + hex(value, width) + (place.empty() ? "" : "  " + place),
                     {hex(value, width), place}, {{"value", hex(value, width)}, {"where", place}});
    }
    return 0;
}

int Session::cmd_probe(Args& args) {
    size_t size = 0x100;
    if (!args.done() && args.tokens[args.next].text == "-s") {
        args.take();
        const auto parsed = parse_number(args.take().text);
        if (!parsed || *parsed == 0)
            throw Error("-s needs a size");
        size = static_cast<size_t>(*parsed);
    }
    const size_t width = target().pointer_size();
    Scanner scanner(target());
    size_t fields = 0;
    for (const Address address : addresses(args)) {
        const auto probe = scanner.probe(address, size);
        if (probe.fields.empty()) {
            m_out.err() << "nothing readable at " << hex(address, width) << '\n';
            continue;
        }
        m_out.info() << "Probed " << human_size(probe.size) << " at " << hex(address, width)
                     << (m_out.table() ? "\n\n" : "\n");
        for (const auto& field : probe.fields) {
            const Address at = address + field.offset;
            std::ostringstream line;
            line << "  +" << std::left << std::setw(6) << hex_short(field.offset).substr(2)
                 << std::setw(static_cast<int>(width * 2 + 4)) << hex(field.raw, width) << std::setw(12)
                 << to_string(field.kind) << field.detail;
            std::string text = line.str();
            text.erase(text.find_last_not_of(' ') + 1);
            m_out.record(text, {hex(at, width), hex_short(field.offset), std::string(to_string(field.kind)),
                                hex(field.raw, width), field.detail},
                         {{"address", hex(at, width)}, {"offset", field.offset}, {"kind", to_string(field.kind)},
                          {"raw", hex(field.raw, width)}, {"detail", field.detail}});
            ++fields;
        }
    }
    return fields ? 0 : 2;
}

int Session::cmd_dump(Args& args) {
    const std::string path = args.take().text;
    const auto size = parse_number(args.take().text);
    if (!size || *size == 0)
        throw Error("usage: dump <file> <size> <expr>");
    const auto address = static_cast<Address>(eval(args.rest()));
    const auto bytes = target().read_bytes(address, static_cast<size_t>(*size));
    if (bytes.empty())
        throw Error("cannot read " + std::to_string(*size) + " bytes at " + hex(address, target().pointer_size()));
    std::ofstream out(path, std::ios::binary);
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!out.flush())
        throw Error("cannot write " + path);
    m_out.info() << "wrote " << human_size(bytes.size()) << " to " << path << '\n';
    return 0;
}

} // namespace patty::cli
