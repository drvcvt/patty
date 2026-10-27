#include "commands.h"
#include "output.h"

#include <algorithm>
#include <charconv>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>

namespace patty::cli {

namespace {

constexpr size_t kMaxThreads = 64;
constexpr size_t kMaxChunkSize = size_t{64} << 20;
constexpr size_t kMaxResults = 100000;

bool wants_json(const std::string& output) {
    if (output == "json")
        return true;
    if (output == "table")
        return false;
    throw Error("unknown output format \"" + output + "\" (table or json)");
}

json envelope(const char* command) {
    return {{"schema_version", kSchemaVersion}, {"command", command}};
}

uintptr_t require_address(const std::string& text) {
    const auto value = parse_number(text);
    if (!value)
        throw Error("not an address: " + text);
    return static_cast<uintptr_t>(*value);
}

int report(const std::vector<ScanResult>& results, Target& target, const ScanArgs& scan, const char* command) {
    if (wants_json(scan.output)) {
        auto payload = envelope(command);
        json items = json::array();
        for (const auto& result : results)
            items.push_back(to_json(result, target.pointer_size()));
        payload["results"] = std::move(items);
        payload["elapsed_ms"] = results.empty() ? 0.0 : results.front().elapsed_ms;
        payload["bytes_scanned"] = results.empty() ? 0 : results.front().bytes_scanned;
        std::cout << payload.dump(2) << '\n';
    } else {
        print_results(std::cout, results, target.pointer_size());
    }
    const bool any = std::any_of(results.begin(), results.end(), [](const ScanResult& r) { return !r.empty(); });
    return any ? 0 : 2;
}

} // namespace

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
        throw Error("pick exactly one target: --pid, --name or --file");
    if (args.pid)
        return std::make_unique<Process>(Process::open(args.pid));
    if (!args.name.empty())
        return std::make_unique<Process>(Process::open(args.name));
    if (args.raw)
        return std::make_unique<Image>(Image::open_raw(args.file));
    return std::make_unique<Image>(Image::open(args.file));
}

ScanOptions scan_options(const ScanArgs& args) {
    if (args.code_only && args.data_only)
        throw Error("--code-only and --data-only exclude each other");
    ScanOptions options;
    options.code_only = args.code_only;
    options.data_only = args.data_only;
    options.module = args.module;
    // Parallel is the default; --threads 1 is the way to stay on one thread.
    options.parallel = args.threads != 1;
    options.max = std::min(args.max, kMaxResults);
    options.threads = std::min(args.threads, kMaxThreads);
    if (args.chunk_size)
        options.chunk_size = std::min(args.chunk_size, kMaxChunkSize);
    if (!args.region.empty())
        options.filter = [name = args.region](const Region& r) { return r.name == name; };
    return options;
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

int cmd_scan(const TargetArgs& target_args, const ScanArgs& scan, const PatternArgs& args) {
    const int inputs = !args.aob.empty() + !args.ida.empty() + !args.text.empty() +
                       !args.msvc_string.empty() + !args.profile.empty();
    if (inputs != 1)
        throw Error("pick exactly one of --pattern, --ida, --string, --sso-string, --profile");
    wants_json(scan.output);

    auto target = open_target(target_args);
    auto options = scan_options(scan);
    std::vector<Pattern> patterns;

    if (!args.profile.empty()) {
        if (args.offset || !args.resolve.empty())
            throw Error("--offset and --resolve apply to single patterns, not profiles");
        auto profile = Profile::load(args.profile);
        apply_profile_module(options, profile, *target);
        patterns = std::move(profile.patterns);
    } else {
        auto pattern = !args.aob.empty() ? Pattern::aob(args.aob)
                     : !args.ida.empty() ? Pattern::aob(args.ida)
                     : !args.text.empty() ? Pattern::text(args.text)
                     : Pattern::msvc_string(args.msvc_string);
        pattern.named("cli_pattern");
        if (args.offset)
            pattern.add(args.offset);
        apply_resolve_spec(pattern, args.resolve);
        patterns.push_back(std::move(pattern));
    }

    return report(Scanner(*target).find(patterns, options), *target, scan, "scan");
}

int cmd_scan_value(const TargetArgs& target_args, const ScanArgs& scan, const std::string& value, size_t size) {
    const auto number = parse_number(value);
    if (!number)
        throw Error("not a number: " + value);
    auto pattern = Pattern::integer(*number, size).named("value_" + hex_short(*number));
    auto options = scan_options(scan);
    wants_json(scan.output);
    auto target = open_target(target_args);
    return report({Scanner(*target).find(pattern, options)}, *target, scan, "scan-value");
}

int cmd_scan_pointers(const TargetArgs& target_args, const ScanArgs& scan,
                      const std::vector<std::string>& addresses, const char* command) {
    std::vector<uintptr_t> values;
    for (const auto& text : addresses)
        values.push_back(require_address(text));
    auto options = scan_options(scan);
    wants_json(scan.output);
    auto target = open_target(target_args);
    return report(Scanner(*target).find_pointers(values, options), *target, scan, command);
}

int cmd_probe(const TargetArgs& target_args, const std::string& address, size_t size, const std::string& output) {
    const auto at = require_address(address);
    const bool json_out = wants_json(output);
    auto target = open_target(target_args);
    const auto probe = Scanner(*target).probe(at, size);
    if (json_out) {
        auto payload = envelope("probe");
        payload.update(to_json(probe, target->pointer_size()));
        std::cout << payload.dump(2) << '\n';
    } else {
        print_probe(std::cout, probe, target->pointer_size());
    }
    return 0;
}

int cmd_list(const TargetArgs& target_args, bool modules, const std::string& output) {
    const bool json_out = wants_json(output);
    auto target = open_target(target_args);
    const size_t width = target->pointer_size();
    if (json_out) {
        auto payload = envelope("list");
        if (modules)
            payload["modules"] = modules_json(target->modules(), width);
        else
            payload["regions"] = regions_json(target->regions(), width);
        std::cout << payload.dump(2) << '\n';
    } else if (modules) {
        print_modules(std::cout, target->modules(), width);
    } else {
        print_regions(std::cout, target->regions(), width);
    }
    return 0;
}

int cmd_dump(const TargetArgs& target_args, const std::string& address, size_t size, const std::string& path) {
    const auto at = require_address(address);
    if (size == 0)
        throw Error("--size must be greater than 0");
    auto target = open_target(target_args);
    const auto bytes = target->read_bytes(at, size);
    if (bytes.empty())
        throw Error("cannot read " + std::to_string(size) + " bytes at " + hex(at, target->pointer_size()));

    std::ofstream out(path, std::ios::binary);
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!out.flush())
        throw Error("cannot write " + path);
    std::cout << "Wrote " << human_size(bytes.size()) << " to " << path << '\n';
    return 0;
}

int cmd_check(const TargetArgs& target_args, const ScanArgs& scan, const std::string& profile_path) {
    const bool json_out = wants_json(scan.output);
    const auto profile = Profile::load(profile_path);
    auto target = open_target(target_args);
    auto options = scan_options(scan);
    apply_profile_module(options, profile, *target);

    const auto check = Scanner(*target).check(profile, options);
    if (json_out) {
        auto payload = envelope("check");
        payload["profile"] = profile.name;
        payload.update(to_json(check, target->pointer_size()));
        std::cout << payload.dump(2) << '\n';
    } else {
        print_check(std::cout, check, target->pointer_size());
    }
    return check.all_ok() ? 0 : 2;
}

int cmd_ps(const std::string& filter) {
    const auto wanted = [&](const ProcessInfo& p) {
        auto lower = [](std::string text) {
            for (auto& c : text)
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            return text;
        };
        return filter.empty() || lower(p.name).find(lower(filter)) != std::string::npos;
    };
    for (const auto& process : Process::list())
        if (wanted(process))
            std::cout << std::setw(8) << process.pid << "  " << process.name << '\n';
    return 0;
}

} // namespace patty::cli
