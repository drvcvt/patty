#include "patty/profile/check.h"
#include "patty/profile/profile.h"
#include "patty/scan/scanner.h"

#include <algorithm>

namespace patty {

std::string_view to_string(CheckStatus status) {
    switch (status) {
    case CheckStatus::Ok:         return "ok";
    case CheckStatus::Ambiguous:  return "ambiguous";
    case CheckStatus::Missing:    return "missing";
    case CheckStatus::Unresolved: return "unresolved";
    }
    return "unknown";
}

size_t CheckReport::count(CheckStatus status) const {
    return static_cast<size_t>(std::count_if(patterns.begin(), patterns.end(),
        [status](const PatternCheck& p) { return p.status == status; }));
}

namespace {

PatternCheck classify(ScanResult result, const std::optional<Module>& module) {
    PatternCheck check;
    check.name = std::move(result.pattern);
    check.matches = std::move(result.matches);

    std::vector<uintptr_t> values;
    for (const auto& match : check.matches)
        if (!match.resolve_failed)
            values.push_back(match.value());
    std::sort(values.begin(), values.end());
    values.erase(std::unique(values.begin(), values.end()), values.end());

    if (check.matches.empty())
        check.status = CheckStatus::Missing;
    else if (values.empty())
        check.status = CheckStatus::Unresolved;
    else if (values.size() > 1)
        check.status = CheckStatus::Ambiguous;
    else {
        check.status = CheckStatus::Ok;
        check.value = values.front();
        if (module && check.value >= module->base)
            check.rva = check.value - module->base;
    }
    return check;
}

} // namespace

CheckReport Scanner::check(const Profile& profile, const ScanOptions& options) const {
    ScanOptions bounded = options;
    // Enough matches to tell "unique" from "ambiguous" without unbounded output.
    if (bounded.max == 0)
        bounded.max = 100;

    CheckReport report;
    if (!options.module.empty())
        report.module = m_target->module(options.module);

    for (auto& result : find(profile.patterns, bounded)) {
        report.bytes_scanned = result.bytes_scanned;
        report.elapsed_ms = result.elapsed_ms;
        report.cancelled = result.cancelled;
        report.patterns.push_back(classify(std::move(result), report.module));
    }
    return report;
}

} // namespace patty
