#include <patty/patty.h>
#include <CLI/CLI.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

using json = nlohmann::json;
using namespace patty;

namespace {

constexpr size_t kMaxCliThreadCount = 64;
constexpr size_t kMaxCliChunkSize = 64ull * 1024ull * 1024ull;
constexpr size_t kMaxCliMaxResults = 100000;
constexpr int kJsonSchemaVersion = 1;

struct TargetOptions {
    uint32_t pid = 0;
    std::string process_name;
    std::string file_path;
};

struct ScanOptions {
    bool code_only = false;
    bool data_only = false;
    bool parallel = false;
    std::string module_filter;
    std::string output_fmt = "table";
    size_t max_results = 0;
    size_t chunk_size = 0;
    size_t thread_count = 0;
};

std::string hexAddr(uintptr_t addr, bool is64 = true) {
    std::ostringstream ss;
    if (is64)
        ss << "0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(16) << addr;
    else
        ss << "0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(8) << addr;
    return ss.str();
}

std::string hexValue(uint64_t value, size_t width_bytes = sizeof(uint64_t)) {
    std::ostringstream ss;
    ss << "0x" << std::hex << std::uppercase << std::setfill('0')
       << std::setw(static_cast<int>(width_bytes * 2)) << value;
    return ss.str();
}

std::string humanSize(size_t bytes) {
    if (bytes >= 1024ull * 1024ull * 1024ull)
        return std::to_string(bytes / (1024ull * 1024ull * 1024ull)) + " GB";
    if (bytes >= 1024ull * 1024ull)
        return std::to_string(bytes / (1024ull * 1024ull)) + " MB";
    if (bytes >= 1024ull)
        return std::to_string(bytes / 1024ull) + " KB";
    return std::to_string(bytes) + " B";
}

std::string protStr(uint32_t prot) {
    std::string s;
    if (prot & 0xF0) s += "X"; else s += "-";
    if (prot & 0x02 || prot & 0x04 || prot & 0x20 || prot & 0x40) s += "R"; else s += "-";
    if (prot & 0x04 || prot & 0x08 || prot & 0x40 || prot & 0x80) s += "W"; else s += "-";
    return s;
}

std::string trim(std::string_view value) {
    size_t start = 0;
    while (start < value.size() && std::isspace(static_cast<unsigned char>(value[start])))
        ++start;
    size_t end = value.size();
    while (end > start && std::isspace(static_cast<unsigned char>(value[end - 1])))
        --end;
    return std::string(value.substr(start, end - start));
}

std::optional<uint64_t> parseUnsigned(std::string_view text) {
    const auto token = trim(text);
    if (token.empty())
        return std::nullopt;
    try {
        size_t consumed = 0;
        auto value = std::stoull(token, &consumed, 0);
        if (consumed != token.size())
            return std::nullopt;
        return value;
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<int64_t> parseSigned(std::string_view text) {
    const auto token = trim(text);
    if (token.empty())
        return std::nullopt;
    try {
        size_t consumed = 0;
        auto value = std::stoll(token, &consumed, 0);
        if (consumed != token.size())
            return std::nullopt;
        return value;
    } catch (...) {
        return std::nullopt;
    }
}

std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

void addTargetOptions(CLI::App* app, TargetOptions& target) {
    app->add_option("--pid", target.pid, "Process ID");
    app->add_option("--name", target.process_name, "Process name");
    app->add_option("--file", target.file_path, "File path");
}

void addScanOptions(CLI::App* app, ScanOptions& options, bool allow_module = true) {
    app->add_flag("--code-only", options.code_only, "Scan executable regions only");
    app->add_flag("--data-only", options.data_only, "Scan writable data regions only");
    app->add_flag("--parallel", options.parallel, "Scan regions in parallel");
    app->add_option("--threads", options.thread_count, "Worker thread count (0 = auto)");
    app->add_option("--chunk-size", options.chunk_size, "Chunk size in bytes (default 2MB)");
    app->add_option("--output,-o", options.output_fmt, "Output format: table, json");
    app->add_option("--max", options.max_results, "Max results per pattern");
    if (allow_module)
        app->add_option("--module", options.module_filter, "Filter by module name");
}

bool validateTargetOptions(const TargetOptions& target) {
    const size_t selectors =
        (target.pid > 0 ? 1u : 0u) +
        (!target.process_name.empty() ? 1u : 0u) +
        (!target.file_path.empty() ? 1u : 0u);
    if (selectors != 1) {
        std::cerr << "Specify exactly one of --pid, --name, or --file\n";
        return false;
    }
    return true;
}

std::shared_ptr<IMemoryProvider> createProvider(const TargetOptions& target) {
    if (!validateTargetOptions(target))
        return nullptr;
#ifdef _WIN32
    if (target.pid > 0) {
        auto p = ProcessProvider::open(target.pid);
        if (!p) {
            std::cerr << "Failed to open process " << target.pid << "\n";
            return nullptr;
        }
        return std::make_shared<ProcessProvider>(std::move(*p));
    }

    if (!target.process_name.empty()) {
        auto p = ProcessProvider::openByName(target.process_name);
        if (!p) {
            std::cerr << "Process not found: " << target.process_name << "\n";
            return nullptr;
        }
        return std::make_shared<ProcessProvider>(std::move(*p));
    }
#endif

    if (!target.file_path.empty()) {
        auto f = FileProvider::open(target.file_path);
        if (!f) {
            std::cerr << "Failed to open file: " << target.file_path << "\n";
            return nullptr;
        }
        return std::make_shared<FileProvider>(std::move(*f));
    }

    std::cerr << "No target specified. Use --pid, --name, or --file\n";
    return nullptr;
}

ScanConfig buildScanConfig(const ScanOptions& options) {
    ScanConfig config;
    if (options.code_only)
        config.filter = RegionFilter::codeOnly();
    else if (options.data_only)
        config.filter = RegionFilter::dataOnly();

    if (!options.module_filter.empty())
        config.filter.module_name = options.module_filter;
    if (options.max_results > 0)
        config.max_results = options.max_results;
    if (options.chunk_size > 0)
        config.chunk_size = options.chunk_size;
    config.parallel = options.parallel;
    config.thread_count = options.thread_count;
    return config;
}

bool normalizeScanOptions(ScanOptions& options) {
    if (options.code_only && options.data_only) {
        std::cerr << "Choose either --code-only or --data-only, not both\n";
        return false;
    }
    const auto normalized_output = lower(options.output_fmt);
    if (normalized_output == "ndjson") {
        std::cerr << "ndjson output is not supported yet\n";
        return false;
    }
    if (normalized_output != "table" && normalized_output != "json") {
        std::cerr << "Unsupported output format: " << options.output_fmt << "\n";
        return false;
    }
    if (options.thread_count > kMaxCliThreadCount) {
        std::cerr << "Clamping --threads to " << kMaxCliThreadCount << "\n";
        options.thread_count = kMaxCliThreadCount;
    }
    if (options.chunk_size > kMaxCliChunkSize) {
        std::cerr << "Clamping --chunk-size to " << kMaxCliChunkSize << " bytes\n";
        options.chunk_size = kMaxCliChunkSize;
    }
    if (options.max_results > kMaxCliMaxResults) {
        std::cerr << "Clamping --max to " << kMaxCliMaxResults << "\n";
        options.max_results = kMaxCliMaxResults;
    }
    return true;
}

bool applyResolveSpec(Pattern& pattern, const std::string& resolve_spec) {
    if (resolve_spec.empty())
        return true;

    std::stringstream stream(resolve_spec);
    std::string token;
    while (std::getline(stream, token, ',')) {
        auto step = lower(trim(token));
        if (step.empty())
            continue;
        if (step == "rip" || step == "rip_relative") {
            pattern.withResolve(ResolveType::RIPRelative);
        } else if (step == "deref" || step == "dereference") {
            pattern.withResolve(ResolveType::Dereference);
        } else if (step.rfind("add:", 0) == 0) {
            auto extra = parseSigned(step.substr(4));
            if (!extra) {
                std::cerr << "Invalid add resolve step: " << token << "\n";
                return false;
            }
            pattern.withResolve(ResolveType::Add, *extra);
        } else {
            std::cerr << "Unsupported resolve step: " << token << "\n";
            return false;
        }
    }

    return true;
}

json matchToJson(const Match& match, bool is64) {
    json item;
    item["address"] = hexAddr(match.address, is64);
    if (match.hasResolved())
        item["resolved"] = hexAddr(match.resolved, is64);
    item["region"] = match.region.name;
    return item;
}

json scanResultToJson(const ScanResult& result, bool is64) {
    json item;
    item["pattern"] = result.pattern_name;
    item["count"] = result.matches.size();
    item["matches"] = json::array();
    for (const auto& match : result.matches)
        item["matches"].push_back(matchToJson(match, is64));
    item["elapsed_ms"] = result.elapsed_ms;
    item["bytes_scanned"] = result.bytes_scanned;
    item["regions_scanned"] = result.regions_scanned;
    return item;
}

json multiScanResultToJson(const MultiScanResult& result, bool is64, std::string_view command_name) {
    json payload;
    payload["schema_version"] = kJsonSchemaVersion;
    payload["command"] = command_name;
    payload["results"] = json::array();
    for (const auto& entry : result.results)
        payload["results"].push_back(scanResultToJson(entry, is64));
    payload["elapsed_ms"] = result.total_elapsed_ms;
    payload["bytes_scanned"] = result.total_bytes_scanned;
    return payload;
}

bool hasMatches(const MultiScanResult& result) {
    for (const auto& entry : result.results) {
        if (!entry.matches.empty())
            return true;
    }
    return false;
}

MultiScanResult wrapSingleResult(ScanResult result) {
    MultiScanResult wrapped;
    wrapped.total_elapsed_ms = result.elapsed_ms;
    wrapped.total_bytes_scanned = result.bytes_scanned;
    wrapped.results.push_back(std::move(result));
    return wrapped;
}

void printMultiScanResult(const MultiScanResult& result, bool is64, const std::string& output_fmt, std::string_view command_name) {
    if (lower(output_fmt) == "json") {
        std::cout << multiScanResultToJson(result, is64, command_name).dump(2) << "\n";
        return;
    }

    std::cout << "Scanned " << humanSize(result.total_bytes_scanned)
              << " in " << std::fixed << std::setprecision(1)
              << result.total_elapsed_ms << " ms\n\n";

    for (const auto& entry : result.results) {
        std::cout << "[" << entry.pattern_name << "] " << entry.matches.size() << " match(es)\n";
        for (const auto& match : entry.matches) {
            std::cout << "  " << hexAddr(match.address, is64);
            if (match.hasResolved())
                std::cout << " -> " << hexAddr(match.resolved, is64);
            if (!match.region.name.empty())
                std::cout << " (" << match.region.name << ")";
            std::cout << "\n";
        }
        std::cout << "\n";
    }
}

void printProbeResult(const ProbeResult& probe, bool is64, const std::string& output_fmt) {
    if (lower(output_fmt) == "json") {
        json payload;
        payload["schema_version"] = kJsonSchemaVersion;
        payload["command"] = "probe";
        payload["address"] = hexAddr(probe.address, is64);
        payload["probed_size"] = probe.probed_size;
        payload["fields"] = json::array();
        const size_t word_size = is64 ? 8 : 4;
        for (const auto& field : probe.fields) {
            json item;
            item["offset"] = field.offset;
            item["raw_value"] = hexValue(field.raw_value, word_size);
            item["classification"] = field.classification;
            item["detail"] = field.detail;
            payload["fields"].push_back(item);
        }
        std::cout << payload.dump(2) << "\n";
        return;
    }

    const size_t word_size = is64 ? 8 : 4;
    std::cout << "Probed " << hexAddr(probe.address, is64)
              << " (" << humanSize(probe.probed_size) << ")\n\n";
    std::cout << std::left
              << std::setw(10) << "Offset"
              << std::setw(22) << "Raw"
              << std::setw(16) << "Class"
              << "Detail" << "\n";
    std::cout << std::string(80, '-') << "\n";

    for (const auto& field : probe.fields) {
        std::ostringstream offset_ss;
        offset_ss << "+0x" << std::hex << std::uppercase << field.offset;
        std::cout << std::left
                  << std::setw(10) << offset_ss.str()
                  << std::setw(22) << hexValue(field.raw_value, word_size)
                  << std::setw(16) << field.classification
                  << field.detail << "\n";
    }
}

int cmdScan(const TargetOptions& target, ScanOptions options,
            const std::string& pattern_str, const std::string& ida_pattern,
            const std::string& ascii_string, const std::string& sso_string,
            const std::string& profile_path, int32_t result_offset,
            const std::string& resolve_spec) {
    if (!normalizeScanOptions(options))
        return 1;

    auto provider = createProvider(target);
    if (!provider)
        return 1;

    std::vector<Pattern> patterns;
    size_t input_count = 0;
    input_count += !pattern_str.empty();
    input_count += !ida_pattern.empty();
    input_count += !ascii_string.empty();
    input_count += !sso_string.empty();
    input_count += !profile_path.empty();

    if (input_count != 1) {
        std::cerr << "Choose exactly one of --pattern, --ida, --string, --sso-string, or --profile\n";
        return 1;
    }

    try {
        if (!pattern_str.empty()) {
            auto pattern = Pattern::fromAOB(pattern_str, "cli_pattern");
            pattern.withOffset(result_offset);
            if (!applyResolveSpec(pattern, resolve_spec))
                return 1;
            patterns.push_back(std::move(pattern));
        } else if (!ida_pattern.empty()) {
            auto pattern = Pattern::fromIDA(ida_pattern, "cli_pattern");
            pattern.withOffset(result_offset);
            if (!applyResolveSpec(pattern, resolve_spec))
                return 1;
            patterns.push_back(std::move(pattern));
        } else if (!ascii_string.empty()) {
            auto pattern = Pattern::fromString(ascii_string, "cli_string");
            pattern.withOffset(result_offset);
            if (!applyResolveSpec(pattern, resolve_spec))
                return 1;
            patterns.push_back(std::move(pattern));
        } else if (!sso_string.empty()) {
            auto pattern = Pattern::fromSSOString(sso_string, "cli_sso_string");
            pattern.withOffset(result_offset);
            if (!applyResolveSpec(pattern, resolve_spec))
                return 1;
            patterns.push_back(std::move(pattern));
        } else {
            auto profile = ProfileLoader::fromFile(profile_path);
            if (!profile) {
                std::cerr << "Failed to load profile: " << profile_path << "\n";
                return 1;
            }
            if (result_offset != 0 || !resolve_spec.empty()) {
                std::cerr << "--offset/--resolve are only supported for direct CLI patterns, not profiles\n";
                return 1;
            }
            for (auto& pattern : profile->patterns)
                patterns.push_back(std::move(pattern));
        }
    } catch (const std::exception& ex) {
        std::cerr << ex.what() << "\n";
        return 1;
    }

    Scanner scanner(provider);
    auto result = scanner.scan(std::span<const Pattern>(patterns), buildScanConfig(options));
    printMultiScanResult(result, provider->is64Bit(), options.output_fmt, "scan");
    return hasMatches(result) ? 0 : 2;
}

int cmdScanValue(const TargetOptions& target, ScanOptions options,
                 const std::string& value_text, size_t value_size) {
    if (!normalizeScanOptions(options))
        return 1;
    if (value_size == 0 || value_size > sizeof(uint64_t)) {
        std::cerr << "--size must be between 1 and 8 bytes\n";
        return 1;
    }

    auto value = parseUnsigned(value_text);
    if (!value) {
        std::cerr << "Invalid value: " << value_text << "\n";
        return 1;
    }

    auto provider = createProvider(target);
    if (!provider)
        return 1;

    Scanner scanner(provider);
    auto result = wrapSingleResult(scanner.scanForValue(*value, value_size, buildScanConfig(options)));
    printMultiScanResult(result, provider->is64Bit(), options.output_fmt, "scan-value");
    return hasMatches(result) ? 0 : 2;
}

int cmdScanPointer(const TargetOptions& target, ScanOptions options,
                   const std::string& address_text) {
    if (!normalizeScanOptions(options))
        return 1;

    auto address = parseUnsigned(address_text);
    if (!address) {
        std::cerr << "Invalid address: " << address_text << "\n";
        return 1;
    }

    auto provider = createProvider(target);
    if (!provider)
        return 1;

    Scanner scanner(provider);
    auto result = wrapSingleResult(scanner.scanForPointer(static_cast<uintptr_t>(*address), buildScanConfig(options)));
    printMultiScanResult(result, provider->is64Bit(), options.output_fmt, "scan-pointer");
    return hasMatches(result) ? 0 : 2;
}

int cmdScanPointers(const TargetOptions& target, ScanOptions options,
                    const std::vector<std::string>& address_texts) {
    if (!normalizeScanOptions(options))
        return 1;
    if (address_texts.empty()) {
        std::cerr << "Specify at least one --address\n";
        return 1;
    }

    std::vector<uintptr_t> addresses;
    addresses.reserve(address_texts.size());
    for (const auto& text : address_texts) {
        auto parsed = parseUnsigned(text);
        if (!parsed) {
            std::cerr << "Invalid address: " << text << "\n";
            return 1;
        }
        addresses.push_back(static_cast<uintptr_t>(*parsed));
    }

    auto provider = createProvider(target);
    if (!provider)
        return 1;

    Scanner scanner(provider);
    auto result = scanner.scanForPointers(std::span<const uintptr_t>(addresses), buildScanConfig(options));
    printMultiScanResult(result, provider->is64Bit(), options.output_fmt, "scan-pointers");
    return hasMatches(result) ? 0 : 2;
}

int cmdProbe(const TargetOptions& target, const std::string& address_text,
             size_t probe_size, const std::string& output_fmt) {
    if (lower(output_fmt) != "table" && lower(output_fmt) != "json") {
        std::cerr << "Unsupported output format: " << output_fmt << "\n";
        return 1;
    }

    auto address = parseUnsigned(address_text);
    if (!address) {
        std::cerr << "Invalid address: " << address_text << "\n";
        return 1;
    }

    auto provider = createProvider(target);
    if (!provider)
        return 1;

    Scanner scanner(provider);
    auto probe = scanner.probeObject(static_cast<uintptr_t>(*address), probe_size);
    printProbeResult(probe, provider->is64Bit(), output_fmt);
    return 0;
}

int cmdList(const TargetOptions& target, const std::string& output_fmt) {
    auto provider = createProvider(target);
    if (!provider)
        return 1;

    auto regions = provider->regions();
    if (lower(output_fmt) == "json") {
        json payload;
        payload["schema_version"] = kJsonSchemaVersion;
        payload["command"] = "list";
        payload["regions"] = json::array();
        for (const auto& region : regions) {
            payload["regions"].push_back({
                {"base", hexAddr(region.base, provider->is64Bit())},
                {"size", region.size},
                {"size_human", humanSize(region.size)},
                {"protection", protStr(region.protection)},
                {"name", region.name},
            });
        }
        std::cout << payload.dump(2) << "\n";
        return 0;
    }

    std::cout << std::left
              << std::setw(20) << "Base"
              << std::setw(12) << "Size"
              << std::setw(6) << "Prot"
              << "Name" << "\n";
    std::cout << std::string(60, '-') << "\n";

    for (const auto& region : regions) {
        std::cout << std::left
                  << std::setw(20) << hexAddr(region.base, provider->is64Bit())
                  << std::setw(12) << humanSize(region.size)
                  << std::setw(6) << protStr(region.protection)
                  << region.name << "\n";
    }

    std::cout << "\n" << regions.size() << " regions\n";
    return 0;
}

int cmdDump(const TargetOptions& target, const std::string& region_base_str,
            size_t dump_size, const std::string& output_path) {
#ifdef _WIN32
    auto provider = createProvider(target);
    if (!provider)
        return 1;

    auto base = parseUnsigned(region_base_str);
    if (!base || dump_size == 0) {
        std::cerr << "Specify --region <hex_base> and --size <bytes>\n";
        return 1;
    }

    auto data = provider->readBytes(static_cast<uintptr_t>(*base), dump_size);
    if (data.empty()) {
        std::cerr << "Failed to read memory at " << hexAddr(static_cast<uintptr_t>(*base), provider->is64Bit()) << "\n";
        return 1;
    }

    const std::string path = output_path.empty() ? "dump.bin" : output_path;
    std::ofstream out(path, std::ios::binary);
    if (!out.is_open()) {
        std::cerr << "Failed to open output file: " << path << "\n";
        return 1;
    }
    out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    out.flush();
    if (!out.good()) {
        std::cerr << "Failed to write dump to " << path << "\n";
        return 1;
    }
    std::cout << "Dumped " << humanSize(data.size()) << " to " << path << "\n";
    return 0;
#else
    (void)target;
    (void)region_base_str;
    (void)dump_size;
    (void)output_path;
    std::cerr << "Dump not supported on this platform\n";
    return 1;
#endif
}

} // namespace

int main(int argc, char** argv) {
    CLI::App app{"patty - Universal Memory Pattern Scanner"};
    app.require_subcommand(1);

    // --- scan ---
    TargetOptions scan_target;
    ScanOptions scan_options;
    std::string pattern_str, ida_pattern, ascii_string, sso_string, profile_path, resolve_spec;
    int32_t result_offset = 0;
    auto* scan = app.add_subcommand("scan", "Scan for patterns");
    addTargetOptions(scan, scan_target);
    addScanOptions(scan, scan_options);
    scan->add_option("--pattern,-p", pattern_str, "AOB pattern (e.g. \"48 8B 05 ?? ?? ?? ??\")");
    scan->add_option("--ida", ida_pattern, "IDA-style byte pattern");
    scan->add_option("--string", ascii_string, "Exact ASCII string pattern");
    scan->add_option("--sso-string", sso_string, "MSVC std::string SSO pattern");
    scan->add_option("--profile", profile_path, "Target profile JSON");
    scan->add_option("--resolve", resolve_spec, "Resolve chain spec: rip,deref,add:<n>");
    scan->add_option("--offset", result_offset, "Result offset applied before resolve steps");

    // --- scan-value ---
    TargetOptions value_target;
    ScanOptions value_options;
    std::string value_text;
    size_t value_size = 8;
    auto* scan_value = app.add_subcommand("scan-value", "Scan for a numeric value");
    addTargetOptions(scan_value, value_target);
    addScanOptions(scan_value, value_options);
    scan_value->add_option("--value", value_text, "Value to scan for (hex or decimal)")->required();
    scan_value->add_option("--size", value_size, "Value width in bytes (1-8)");

    // --- scan-pointer ---
    TargetOptions pointer_target;
    ScanOptions pointer_options;
    std::string pointer_address;
    auto* scan_pointer = app.add_subcommand("scan-pointer", "Scan for a pointer-sized address");
    addTargetOptions(scan_pointer, pointer_target);
    addScanOptions(scan_pointer, pointer_options);
    scan_pointer->add_option("--address", pointer_address, "Pointer target address (hex or decimal)")->required();

    // --- scan-pointers ---
    TargetOptions pointers_target;
    ScanOptions pointers_options;
    std::vector<std::string> pointer_addresses;
    auto* scan_pointers = app.add_subcommand("scan-pointers", "Scan for multiple pointer-sized addresses in one pass");
    addTargetOptions(scan_pointers, pointers_target);
    addScanOptions(scan_pointers, pointers_options);
    scan_pointers->add_option("--address", pointer_addresses, "Pointer target address (repeat for multiple values)")->required();

    // --- probe ---
    TargetOptions probe_target;
    std::string probe_address;
    size_t probe_size = 0x400;
    std::string probe_output = "table";
    auto* probe = app.add_subcommand("probe", "Probe an object's memory layout");
    addTargetOptions(probe, probe_target);
    probe->add_option("--address", probe_address, "Object base address (hex or decimal)")->required();
    probe->add_option("--size", probe_size, "Bytes to inspect (default 0x400)");
    probe->add_option("--output,-o", probe_output, "Output format: table, json");

    // --- list ---
    TargetOptions list_target;
    std::string list_output = "table";
    auto* list = app.add_subcommand("list", "List memory regions");
    addTargetOptions(list, list_target);
    list->add_option("--output,-o", list_output, "Output format: table, json");

    // --- dump ---
    TargetOptions dump_target;
    std::string region_base_str, dump_output;
    size_t dump_size = 0;
    auto* dump = app.add_subcommand("dump", "Dump memory region");
    addTargetOptions(dump, dump_target);
    dump->add_option("--region", region_base_str, "Region base address (hex or decimal)");
    dump->add_option("--size", dump_size, "Size in bytes");
    dump->add_option("--output,-o", dump_output, "Output file path");

    CLI11_PARSE(app, argc, argv);

    if (scan->parsed())
        return cmdScan(scan_target, scan_options, pattern_str, ida_pattern, ascii_string,
                       sso_string, profile_path, result_offset, resolve_spec);
    if (scan_value->parsed())
        return cmdScanValue(value_target, value_options, value_text, value_size);
    if (scan_pointer->parsed())
        return cmdScanPointer(pointer_target, pointer_options, pointer_address);
    if (scan_pointers->parsed())
        return cmdScanPointers(pointers_target, pointers_options, pointer_addresses);
    if (probe->parsed())
        return cmdProbe(probe_target, probe_address, probe_size, probe_output);
    if (list->parsed())
        return cmdList(list_target, list_output);
    if (dump->parsed())
        return cmdDump(dump_target, region_base_str, dump_size, dump_output);

    return 0;
}
