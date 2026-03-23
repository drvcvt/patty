#pragma once

#include "../core/pattern.h"
#include "../resolve/validator.h"
#include <string>
#include <vector>
#include <optional>
#include <unordered_map>

namespace patty {

struct TargetProfile {
    std::string name;
    std::string version;
    std::string description;
    std::vector<Pattern> patterns;

    std::optional<std::string> module_name;
    std::unordered_map<std::string, resolve::Validator> validators;

    TargetProfile& add(Pattern pattern) {
        patterns.push_back(std::move(pattern));
        return *this;
    }

    TargetProfile& add(Pattern pattern, resolve::Validator validator) {
        std::string pname = pattern.name;
        patterns.push_back(std::move(pattern));
        validators[pname] = std::move(validator);
        return *this;
    }

    TargetProfile& forModule(const std::string& mod) {
        module_name = mod;
        return *this;
    }
};

} // namespace patty
