#pragma once

// Small pieces the shell and main() share.

#include <patty/patty.h>

#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace patty::cli {

struct TargetArgs {
    uint32_t pid = 0;
    std::string name;
    std::string file;
    bool raw = false;  // load a file flat, without parsing PE/ELF headers

    bool empty() const { return pid == 0 && name.empty() && file.empty(); }
};

// "4242" is a pid, an existing file is a file, anything else a process name.
TargetArgs guess_target(std::string_view text, bool raw = false);

// Throws patty::Error.
std::unique_ptr<Target> open_target(const TargetArgs& args);

// "0x1F", "31", "-8"; nullopt on anything else.
std::optional<uint64_t> parse_number(std::string_view text);

// Appends resolve steps from "rip,deref,add:8".
void apply_resolve_spec(Pattern& pattern, std::string_view spec);

// A profile's module names a process module. Files are scanned whole, with RVAs
// relative to the image base. An explicit options.module always wins.
void apply_profile_module(ScanOptions& options, const Profile& profile, Target& target);

} // namespace patty::cli
