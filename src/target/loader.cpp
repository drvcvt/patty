#include "patty/target/loader.h"

#include <nlohmann/json.hpp>
#include <fstream>

using json = nlohmann::json;

namespace patty {

static ResolveType parseResolveType(const std::string& s) {
    if (s == "rip_relative" || s == "rip") return ResolveType::RIPRelative;
    if (s == "dereference" || s == "deref") return ResolveType::Dereference;
    if (s == "add") return ResolveType::Add;
    return ResolveType::None;
}

static TargetProfile parseProfile(const json& j) {
    TargetProfile profile;

    profile.name = j.value("name", "");
    profile.version = j.value("version", "");
    profile.description = j.value("description", "");

    if (j.contains("module")) {
        profile.module_name = j["module"].get<std::string>();
    }

    if (j.contains("patterns") && j["patterns"].is_array()) {
        for (const auto& pj : j["patterns"]) {
            Pattern pattern;

            // Parse the pattern bytes
            if (pj.contains("aob")) {
                pattern = Pattern::fromAOB(pj["aob"].get<std::string>());
            } else if (pj.contains("ida")) {
                pattern = Pattern::fromIDA(pj["ida"].get<std::string>());
            } else if (pj.contains("string")) {
                pattern = Pattern::fromString(pj["string"].get<std::string>());
            } else if (pj.contains("sso_string")) {
                pattern = Pattern::fromSSOString(pj["sso_string"].get<std::string>());
            } else {
                continue; // Skip patterns without bytes
            }

            pattern.name = pj.value("name", "");
            pattern.description = pj.value("description", "");
            pattern.result_offset = pj.value("result_offset", 0);

            // Parse resolve chain
            if (pj.contains("resolve") && pj["resolve"].is_array()) {
                for (const auto& rj : pj["resolve"]) {
                    if (rj.is_string()) {
                        pattern.resolve_chain.push_back({parseResolveType(rj.get<std::string>()), 0});
                    } else if (rj.is_object()) {
                        ResolveStep step;
                        step.type = parseResolveType(rj.value("type", "none"));
                        step.extra = rj.value("extra", 0);
                        pattern.resolve_chain.push_back(step);
                    }
                }
            }

            profile.patterns.push_back(std::move(pattern));
        }
    }

    return profile;
}

std::optional<TargetProfile> ProfileLoader::fromFile(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return std::nullopt;

    try {
        json j = json::parse(file);
        return parseProfile(j);
    } catch (const json::exception&) {
        return std::nullopt;
    }
}

std::optional<TargetProfile> ProfileLoader::fromJSON(const std::string& jsonStr) {
    try {
        json j = json::parse(jsonStr);
        return parseProfile(j);
    } catch (const json::exception&) {
        return std::nullopt;
    }
}

} // namespace patty
