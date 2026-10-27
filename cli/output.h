#pragma once

// Formatting shared by the one-shot CLI commands and the REPL.

#include <patty/patty.h>
#include <nlohmann/json.hpp>

#include <functional>
#include <iosfwd>
#include <span>
#include <string>

namespace patty::cli {

using json = nlohmann::json;

inline constexpr int kSchemaVersion = 2;

// Zero-padded to the target's pointer width: 0x0000000140001000.
std::string hex(uint64_t value, size_t pointer_size = 8);
// Unpadded: 0x1A.
std::string hex_short(uint64_t value);
std::string human_size(size_t bytes);
// "r-x"
std::string permissions(const Region& region);

json to_json(const Match& match, size_t pointer_size);
json to_json(const ScanResult& result, size_t pointer_size);
json to_json(const Probe& probe, size_t pointer_size);
json to_json(const CheckReport& report, size_t pointer_size);
json regions_json(const std::vector<Region>& regions, size_t pointer_size);
json modules_json(const std::vector<Module>& modules, size_t pointer_size);

// `label` lets the REPL put "$3" in front of each match.
using MatchLabel = std::function<std::string(const Match&)>;
// `note` replaces the region name at the end of each line (the shell shows module+offset).
void print_matches(std::ostream& out, const ScanResult& result, size_t pointer_size,
                   const MatchLabel& label = {}, const MatchLabel& note = {});
void print_results(std::ostream& out, std::span<const ScanResult> results, size_t pointer_size,
                   const MatchLabel& label = {}, const MatchLabel& note = {});
void print_regions(std::ostream& out, const std::vector<Region>& regions, size_t pointer_size);
void print_modules(std::ostream& out, const std::vector<Module>& modules, size_t pointer_size);
void print_probe(std::ostream& out, const Probe& probe, size_t pointer_size);
void print_check(std::ostream& out, const CheckReport& report, size_t pointer_size);
// 16 bytes per line with an ASCII column.
void print_hexdump(std::ostream& out, uintptr_t address, std::span<const uint8_t> bytes,
                   size_t pointer_size);

} // namespace patty::cli
