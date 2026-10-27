#include "common.h"

#include <charconv>
#include <filesystem>

namespace patty::cli {

void apply_profile_module(ScanOptions& options, const Profile& profile, Target& target) {
    if (!options.module.empty())
        return;
    if (auto* image = dynamic_cast<Image*>(&target))
        options.module = image->name();
    else if (profile.module)
        options.module = *profile.module;
}

TargetArgs guess_target(std::string_view text, bool raw) {
    TargetArgs args;
    args.raw = raw;
    std::error_code ec;
    if (const auto pid = parse_number(text); pid && *pid > 0 && *pid < 0x100000000)
        args.pid = static_cast<uint32_t>(*pid);
    else if (std::filesystem::is_regular_file(std::string(text), ec))
        args.file = text;
    else
        args.name = text;
    return args;
}

std::unique_ptr<Target> open_target(const TargetArgs& args) {
    const int selectors = (args.pid != 0) + !args.name.empty() + !args.file.empty();
    if (selectors != 1)
        throw Error("no target given");
    if (args.pid)
        return std::make_unique<Process>(Process::open(args.pid));
    if (!args.name.empty())
        return std::make_unique<Process>(Process::open(args.name));
    if (args.raw)
        return std::make_unique<Image>(Image::open_raw(args.file));
    return std::make_unique<Image>(Image::open(args.file));
}

std::optional<uint64_t> parse_number(std::string_view text) {
    bool negative = false;
    if (!text.empty() && (text.front() == '-' || text.front() == '+')) {
        negative = text.front() == '-';
        text.remove_prefix(1);
    }
    int base = 10;
    if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        base = 16;
        text.remove_prefix(2);
    }
    uint64_t value = 0;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value, base);
    if (text.empty() || error != std::errc() || end != text.data() + text.size())
        return std::nullopt;
    return negative ? uint64_t{0} - value : value;
}

void apply_resolve_spec(Pattern& pattern, std::string_view spec) {
    while (!spec.empty()) {
        const auto comma = spec.find(',');
        auto step = spec.substr(0, comma);
        spec = comma == std::string_view::npos ? std::string_view{} : spec.substr(comma + 1);
        while (!step.empty() && step.front() == ' ') step.remove_prefix(1);
        while (!step.empty() && step.back() == ' ') step.remove_suffix(1);

        if (step == "rip" || step == "rip_relative") {
            pattern.rip();
        } else if (step == "deref" || step == "dereference") {
            pattern.deref();
        } else if (step.starts_with("add:")) {
            const auto amount = parse_number(step.substr(4));
            if (!amount)
                throw Error("bad resolve step: " + std::string(step));
            pattern.add(static_cast<int64_t>(*amount));
        } else if (!step.empty()) {
            throw Error("unknown resolve step \"" + std::string(step) + "\" (rip, deref, add:N)");
        }
    }
}

} // namespace patty::cli
