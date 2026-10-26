#include "patty/profile/profile.h"
#include "patty/error.h"

#include <nlohmann/json.hpp>

#include <fstream>
#include <sstream>

using json = nlohmann::json;

namespace patty {

namespace {

void apply_resolve_step(Pattern& pattern, const json& step) {
    const std::string type = step.is_string() ? step.get<std::string>() : step.value("type", "");
    if (type == "rip" || type == "rip_relative")
        pattern.rip();
    else if (type == "deref" || type == "dereference")
        pattern.deref();
    else if (type == "add")
        pattern.add(step.is_object() ? step.value("extra", int64_t{0}) : 0);
    else
        throw Error("unknown resolve step \"" + type + "\" (expected rip, deref or add)");
}

Pattern parse_pattern(const json& j) {
    std::optional<Pattern> pattern;
    if (j.contains("aob"))
        pattern = Pattern::aob(j.at("aob").get<std::string>());
    else if (j.contains("ida"))
        pattern = Pattern::aob(j.at("ida").get<std::string>());
    else if (j.contains("string"))
        pattern = Pattern::text(j.at("string").get<std::string>());
    else if (j.contains("sso_string"))
        pattern = Pattern::msvc_string(j.at("sso_string").get<std::string>());
    else
        throw Error("pattern needs one of \"aob\", \"ida\", \"string\", \"sso_string\"");

    pattern->named(j.value("name", ""));
    if (const auto offset = j.value("result_offset", int64_t{0}); offset != 0)
        pattern->add(offset);
    if (j.contains("resolve"))
        for (const auto& step : j.at("resolve"))
            apply_resolve_step(*pattern, step);
    return std::move(*pattern);
}

} // namespace

Profile Profile::parse(std::string_view text) {
    json j;
    try {
        j = json::parse(text);
    } catch (const json::parse_error& e) {
        throw Error(std::string("invalid JSON: ") + e.what());
    }
    if (!j.is_object())
        throw Error("profile must be a JSON object");

    Profile profile;
    try {
        profile.name = j.value("name", "");
        profile.version = j.value("version", "");
        profile.description = j.value("description", "");
        if (j.contains("module"))
            profile.module = j.at("module").get<std::string>();

        const auto& patterns = j.value("patterns", json::array());
        for (size_t i = 0; i < patterns.size(); ++i) {
            try {
                profile.patterns.push_back(parse_pattern(patterns[i]));
            } catch (const Error& e) {
                const std::string label = patterns[i].is_object() ? patterns[i].value("name", "") : "";
                throw Error("pattern #" + std::to_string(i + 1) +
                            (label.empty() ? "" : " (" + label + ")") + ": " + e.what());
            }
        }
    } catch (const json::exception& e) {
        throw Error(std::string("unexpected JSON value: ") + e.what());
    }
    return profile;
}

Profile Profile::load(const std::filesystem::path& path) {
    std::ifstream file(path);
    if (!file)
        throw Error("cannot open profile " + path.string());
    std::stringstream text;
    text << file.rdbuf();
    try {
        return parse(text.str());
    } catch (const Error& e) {
        throw Error(path.string() + ": " + e.what());
    }
}

} // namespace patty
