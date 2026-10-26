#pragma once

#include "../scan/pattern.h"

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace patty {

// A named set of signatures for one target, usually kept as JSON next to your
// offsets so you can re-check them after every game update:
//
//   {
//     "name": "Game", "version": "1.4.2", "module": "Game.exe",
//     "patterns": [
//       { "name": "World", "aob": "48 8B 05 ?? ?? ?? ?? 48 85 C0",
//         "result_offset": 3, "resolve": ["rip"] }
//     ]
//   }
//
// Pattern keys: one of "aob" (or "ida"), "string", "sso_string"; optional
// "result_offset" and "resolve" (strings "rip", "deref", or {"type": "add", "extra": n}).
struct Profile {
    std::string name;
    std::string version;
    std::string description;
    std::optional<std::string> module;
    std::vector<Pattern> patterns;

    // Throws patty::Error naming the file and what is wrong with it.
    static Profile load(const std::filesystem::path& path);
    static Profile parse(std::string_view json);
};

} // namespace patty
