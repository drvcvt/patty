#include "output.h"

#include <cstdio>
#include <iomanip>
#include <ostream>
#include <sstream>

namespace patty::cli {

namespace {

std::string trim_right(std::string text) {
    text.erase(text.find_last_not_of(' ') + 1);
    return text;
}

} // namespace

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

json to_json(const Match& match, size_t pointer_size) {
    json item{{"address", hex(match.address, pointer_size)}, {"region", match.region.name}};
    if (match.resolved)
        item["resolved"] = hex(*match.resolved, pointer_size);
    if (match.resolve_failed)
        item["resolve_failed"] = true;
    return item;
}

json to_json(const ScanResult& result, size_t pointer_size) {
    json matches = json::array();
    for (const auto& match : result)
        matches.push_back(to_json(match, pointer_size));
    return {{"pattern", result.pattern}, {"count", result.size()}, {"matches", std::move(matches)},
            {"elapsed_ms", result.elapsed_ms}, {"bytes_scanned", result.bytes_scanned}};
}

json to_json(const Probe& probe, size_t pointer_size) {
    json fields = json::array();
    for (const auto& field : probe.fields)
        fields.push_back({{"offset", field.offset},
                          {"raw_value", hex(field.raw, pointer_size)},
                          {"classification", to_string(field.kind)},
                          {"detail", field.detail}});
    return {{"address", hex(probe.address, pointer_size)}, {"probed_size", probe.size},
            {"fields", std::move(fields)}};
}

json to_json(const CheckReport& report, size_t pointer_size) {
    json patterns = json::array();
    for (const auto& check : report.patterns) {
        json item{{"name", check.name}, {"status", to_string(check.status)}, {"count", check.matches.size()}};
        if (check.status == CheckStatus::Ok)
            item["value"] = hex(check.value, pointer_size);
        if (check.rva)
            item["rva"] = hex(*check.rva, 4);
        json matches = json::array();
        for (const auto& match : check.matches)
            matches.push_back(to_json(match, pointer_size));
        item["matches"] = std::move(matches);
        patterns.push_back(std::move(item));
    }
    json payload{{"summary", {{"ok", report.count(CheckStatus::Ok)},
                              {"ambiguous", report.count(CheckStatus::Ambiguous)},
                              {"missing", report.count(CheckStatus::Missing)},
                              {"unresolved", report.count(CheckStatus::Unresolved)}}},
                 {"patterns", std::move(patterns)},
                 {"elapsed_ms", report.elapsed_ms},
                 {"bytes_scanned", report.bytes_scanned}};
    if (report.module) {
        payload["module"] = report.module->name;
        payload["module_base"] = hex(report.module->base, pointer_size);
    }
    return payload;
}

json regions_json(const std::vector<Region>& regions, size_t pointer_size) {
    json out = json::array();
    for (const auto& region : regions)
        out.push_back({{"base", hex(region.base, pointer_size)}, {"size", region.size},
                       {"size_human", human_size(region.size)}, {"protection", permissions(region)},
                       {"name", region.name}});
    return out;
}

json modules_json(const std::vector<Module>& modules, size_t pointer_size) {
    json out = json::array();
    for (const auto& module : modules)
        out.push_back({{"name", module.name}, {"base", hex(module.base, pointer_size)}, {"size", module.size}});
    return out;
}

void print_matches(std::ostream& out, const ScanResult& result, size_t pointer_size, const MatchLabel& label) {
    for (const auto& match : result) {
        out << "  ";
        if (label)
            out << std::left << std::setw(6) << label(match);
        out << hex(match.address, pointer_size);
        if (match.resolved)
            out << " -> " << hex(*match.resolved, pointer_size);
        else if (match.resolve_failed)
            out << " -> (unresolved)";
        if (!match.region.name.empty())
            out << "  " << match.region.name;
        out << '\n';
    }
}

void print_results(std::ostream& out, std::span<const ScanResult> results, size_t pointer_size,
                   const MatchLabel& label) {
    if (results.empty())
        return;
    out << "Scanned " << human_size(results.front().bytes_scanned) << " in " << std::fixed
        << std::setprecision(1) << results.front().elapsed_ms << " ms"
        << (results.front().cancelled ? " (cancelled)" : "") << "\n";
    for (const auto& result : results) {
        out << '\n';
        if (results.size() > 1 || !result.pattern.empty())
            out << '[' << result.pattern << "] ";
        out << result.size() << (result.size() == 1 ? " match\n" : " matches\n");
        print_matches(out, result, pointer_size, label);
    }
}

void print_regions(std::ostream& out, const std::vector<Region>& regions, size_t pointer_size) {
    const int width = static_cast<int>(pointer_size * 2 + 4);
    out << std::left << std::setw(width) << "Base" << std::setw(10) << "Size" << std::setw(6) << "Prot"
        << "Name\n";
    for (const auto& region : regions)
        out << std::left << std::setw(width) << hex(region.base, pointer_size) << std::setw(10)
            << human_size(region.size) << std::setw(6) << permissions(region) << region.name << '\n';
    out << regions.size() << (regions.size() == 1 ? " region\n" : " regions\n");
}

void print_modules(std::ostream& out, const std::vector<Module>& modules, size_t pointer_size) {
    const int width = static_cast<int>(pointer_size * 2 + 4);
    out << std::left << std::setw(width) << "Base" << std::setw(10) << "Size" << "Name\n";
    for (const auto& module : modules)
        out << std::left << std::setw(width) << hex(module.base, pointer_size) << std::setw(10)
            << human_size(module.size) << module.name << '\n';
}

void print_probe(std::ostream& out, const Probe& probe, size_t pointer_size) {
    if (probe.fields.empty()) {
        out << "Nothing readable at " << hex(probe.address, pointer_size) << '\n';
        return;
    }
    out << "Probed " << human_size(probe.size) << " at " << hex(probe.address, pointer_size) << "\n\n";
    const int width = static_cast<int>(pointer_size * 2 + 4);
    for (const auto& field : probe.fields) {
        std::ostringstream line;
        line << "  +" << std::left << std::setw(6) << hex_short(field.offset).substr(2) << std::setw(width)
             << hex(field.raw, pointer_size) << std::setw(12) << to_string(field.kind) << field.detail;
        out << trim_right(line.str()) << '\n';
    }
}

void print_check(std::ostream& out, const CheckReport& report, size_t pointer_size) {
    out << "Checked " << report.patterns.size() << " pattern(s) over " << human_size(report.bytes_scanned)
        << " in " << std::fixed << std::setprecision(1) << report.elapsed_ms << " ms: "
        << report.count(CheckStatus::Ok) << " ok, " << report.count(CheckStatus::Ambiguous) << " ambiguous, "
        << report.count(CheckStatus::Missing) << " missing";
    if (const auto unresolved = report.count(CheckStatus::Unresolved))
        out << ", " << unresolved << " unresolved";
    out << (report.cancelled ? " (cancelled)" : "") << "\n\n";

    size_t name_width = 4;
    for (const auto& check : report.patterns)
        name_width = std::max(name_width, check.name.size());
    for (const auto& check : report.patterns) {
        out << "  " << std::left << std::setw(12) << to_string(check.status);
        if (check.status == CheckStatus::Missing) {
            out << check.name << '\n';
            continue;
        }
        out << std::setw(static_cast<int>(name_width + 2)) << check.name;
        if (check.status == CheckStatus::Ok) {
            out << hex(check.value, pointer_size);
            if (check.rva)
                out << "  rva " << hex(*check.rva, 4);
        } else {
            out << check.matches.size() << " matches";
        }
        out << '\n';
    }
}

void print_hexdump(std::ostream& out, uintptr_t address, std::span<const uint8_t> bytes, size_t pointer_size) {
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
