#pragma once

#include <patty/patty.h>

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace patty::cli {

struct TargetArgs {
    uint32_t pid = 0;
    std::string name;
    std::string file;
    bool raw = false;  // load --file without parsing PE/ELF headers

    bool empty() const { return pid == 0 && name.empty() && file.empty(); }
};

struct ScanArgs {
    bool code_only = false;
    bool data_only = false;
    bool parallel = false;
    std::string module;
    std::string region;  // only regions with this name (sections of a file)
    size_t max = 0;
    size_t threads = 0;
    size_t chunk_size = 0;
    std::string output = "table";
};

struct PatternArgs {
    std::string aob, ida, text, msvc_string, profile, resolve;
    int64_t offset = 0;
};

// Throws patty::Error unless exactly one of pid/name/file is set.
std::unique_ptr<Target> open_target(const TargetArgs& args);

// Validates and clamps; throws patty::Error on contradictions.
ScanOptions scan_options(const ScanArgs& args);

// A profile's module names a process module. Files are scanned whole, with RVAs
// relative to the image base. An explicit options.module always wins.
void apply_profile_module(ScanOptions& options, const Profile& profile, Target& target);

// "0x1F", "31", "-8"; nullopt on anything else.
std::optional<uint64_t> parse_number(std::string_view text);

// Appends resolve steps from "rip,deref,add:8".
void apply_resolve_spec(Pattern& pattern, std::string_view spec);

int cmd_scan(const TargetArgs& target, const ScanArgs& scan, const PatternArgs& pattern);
int cmd_scan_value(const TargetArgs& target, const ScanArgs& scan, const std::string& value, size_t size);
int cmd_scan_pointers(const TargetArgs& target, const ScanArgs& scan,
                      const std::vector<std::string>& addresses, const char* command);
int cmd_probe(const TargetArgs& target, const std::string& address, size_t size, const std::string& output);
int cmd_list(const TargetArgs& target, bool modules, const std::string& output);
int cmd_dump(const TargetArgs& target, const std::string& address, size_t size, const std::string& path);
int cmd_check(const TargetArgs& target, const ScanArgs& scan, const std::string& profile);

// Interactive session; `target` may be empty.
int run_repl(const TargetArgs& target);

} // namespace patty::cli
