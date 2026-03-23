#pragma once

#include "profile.h"
#include <string>
#include <optional>
#include <stdexcept>

namespace patty {

class ProfileLoader {
public:
    // Load a target profile from a JSON file
    static std::optional<TargetProfile> fromFile(const std::string& path);

    // Load a target profile from a JSON string
    static std::optional<TargetProfile> fromJSON(const std::string& json);
};

} // namespace patty
