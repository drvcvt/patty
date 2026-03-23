#include <patty/patty.h>
#include <CLI/CLI.hpp>
#include <nlohmann/json.hpp>

#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <memory>

using json = nlohmann::json;
using namespace patty;

// Format address as hex string
static std::string hexAddr(uintptr_t addr, bool is64 = true) {
    std::ostringstream ss;
    if (is64)
        ss << "0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(16) << addr;
    else
        ss << "0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(8) << addr;
    return ss.str();
}

// Format size as human readable
static std::string humanSize(size_t bytes) {
    if (bytes >= 1024 * 1024 * 1024)
        return std::to_string(bytes / (1024 * 1024 * 1024)) + " GB";
    if (bytes >= 1024 * 1024)
        return std::to_string(bytes / (1024 * 1024)) + " MB";
    if (bytes >= 1024)
        return std::to_string(bytes / 1024) + " KB";
    return std::to_string(bytes) + " B";
}

// Print protection flags
static std::string protStr(uint32_t prot) {
    std::string s;
    if (prot & 0xF0) s += "X"; else s += "-";
    if (prot & 0x02 || prot & 0x04 || prot & 0x20 || prot & 0x40) s += "R"; else s += "-";
    if (prot & 0x04 || prot & 0x08 || prot & 0x40 || prot & 0x80) s += "W"; else s += "-";
    return s;
}

// Create a memory provider based on CLI args
static std::shared_ptr<IMemoryProvider> createProvider(
    uint32_t pid, const std::string& name, const std::string& file_path)
{
#ifdef _WIN32
    if (pid > 0) {
        auto p = ProcessProvider::open(pid);
        if (!p) {
            std::cerr << "Failed to open process " << pid << "\n";
            return nullptr;
        }
        return std::make_shared<ProcessProvider>(std::move(*p));
    }

    if (!name.empty()) {
        auto p = ProcessProvider::openByName(name);
        if (!p) {
            std::cerr << "Process not found: " << name << "\n";
            return nullptr;
        }
        return std::make_shared<ProcessProvider>(std::move(*p));
    }
#endif

    if (!file_path.empty()) {
        auto f = FileProvider::open(file_path);
        if (!f) {
            std::cerr << "Failed to open file: " << file_path << "\n";
            return nullptr;
        }
        return std::make_shared<FileProvider>(std::move(*f));
    }

    std::cerr << "No target specified. Use --pid, --name, or --file\n";
    return nullptr;
}

// ---- Commands ----

static int cmdScan(uint32_t pid, const std::string& proc_name, const std::string& file_path,
                    const std::string& pattern_str, const std::string& profile_path,
                    bool code_only, bool data_only, const std::string& module_filter,
                    const std::string& output_fmt, size_t max_results,
                    const std::string& resolve_str) {
    auto provider = createProvider(pid, proc_name, file_path);
    if (!provider) return 1;

    Scanner scanner(provider);

    // Build patterns list
    std::vector<Pattern> patterns;

    if (!pattern_str.empty()) {
        auto p = Pattern::fromAOB(pattern_str, "cli_pattern");

        // Apply resolve from CLI
        if (resolve_str == "rip" || resolve_str == "rip_relative") {
            p.withResolve(ResolveType::RIPRelative);
        } else if (resolve_str == "deref" || resolve_str == "dereference") {
            p.withResolve(ResolveType::Dereference);
        }

        patterns.push_back(std::move(p));
    }

    if (!profile_path.empty()) {
        auto profile = ProfileLoader::fromFile(profile_path);
        if (!profile) {
            std::cerr << "Failed to load profile: " << profile_path << "\n";
            return 1;
        }
        for (auto& p : profile->patterns)
            patterns.push_back(std::move(p));
    }

    if (patterns.empty()) {
        std::cerr << "No patterns specified. Use --pattern or --profile\n";
        return 1;
    }

    // Build config
    ScanConfig config;
    if (code_only) config.filter = RegionFilter::codeOnly();
    else if (data_only) config.filter = RegionFilter::dataOnly();
    if (!module_filter.empty()) config.filter.module_name = module_filter;
    if (max_results > 0) config.max_results = max_results;

    // Scan
    auto result = scanner.scan(std::span<const Pattern>(patterns), config);

    // Output
    if (output_fmt == "json") {
        json jout = json::array();
        for (const auto& sr : result.results) {
            json jsr;
            jsr["pattern"] = sr.pattern_name;
            jsr["count"] = sr.matches.size();
            jsr["matches"] = json::array();
            for (const auto& m : sr.matches) {
                json jm;
                jm["address"] = hexAddr(m.address, provider->is64Bit());
                if (m.hasResolved())
                    jm["resolved"] = hexAddr(m.resolved, provider->is64Bit());
                jm["region"] = m.region.name;
                jsr["matches"].push_back(jm);
            }
            jout.push_back(jsr);
        }

        json wrapper;
        wrapper["results"] = jout;
        wrapper["elapsed_ms"] = result.total_elapsed_ms;
        wrapper["bytes_scanned"] = result.total_bytes_scanned;
        std::cout << wrapper.dump(2) << "\n";
    } else {
        // Table output
        std::cout << "Scanned " << humanSize(result.total_bytes_scanned)
                  << " in " << std::fixed << std::setprecision(1)
                  << result.total_elapsed_ms << " ms\n\n";

        for (const auto& sr : result.results) {
            std::cout << "[" << sr.pattern_name << "] " << sr.matches.size() << " match(es)\n";
            for (const auto& m : sr.matches) {
                std::cout << "  " << hexAddr(m.address, provider->is64Bit());
                if (m.hasResolved())
                    std::cout << " -> " << hexAddr(m.resolved, provider->is64Bit());
                if (!m.region.name.empty())
                    std::cout << " (" << m.region.name << ")";
                std::cout << "\n";
            }
            std::cout << "\n";
        }
    }

    return 0;
}

static int cmdList(uint32_t pid, const std::string& proc_name, const std::string& file_path,
                    const std::string& output_fmt) {
    auto provider = createProvider(pid, proc_name, file_path);
    if (!provider) return 1;

    auto regions = provider->regions();

    if (output_fmt == "json") {
        json jout = json::array();
        for (const auto& r : regions) {
            json jr;
            jr["base"] = hexAddr(r.base, provider->is64Bit());
            jr["size"] = r.size;
            jr["size_human"] = humanSize(r.size);
            jr["protection"] = protStr(r.protection);
            jr["name"] = r.name;
            jout.push_back(jr);
        }
        std::cout << jout.dump(2) << "\n";
    } else {
        std::cout << std::left
                  << std::setw(20) << "Base"
                  << std::setw(12) << "Size"
                  << std::setw(6) << "Prot"
                  << "Name" << "\n";
        std::cout << std::string(60, '-') << "\n";

        for (const auto& r : regions) {
            std::cout << std::left
                      << std::setw(20) << hexAddr(r.base, provider->is64Bit())
                      << std::setw(12) << humanSize(r.size)
                      << std::setw(6) << protStr(r.protection)
                      << r.name << "\n";
        }

        std::cout << "\n" << regions.size() << " regions\n";
    }

    return 0;
}

static int cmdDump(uint32_t pid, const std::string& proc_name,
                    const std::string& region_base_str, size_t dump_size,
                    const std::string& output_path) {
#ifdef _WIN32
    std::shared_ptr<IMemoryProvider> provider;

    if (pid > 0) {
        auto p = ProcessProvider::open(pid);
        if (!p) { std::cerr << "Failed to open process\n"; return 1; }
        provider = std::make_shared<ProcessProvider>(std::move(*p));
    } else if (!proc_name.empty()) {
        auto p = ProcessProvider::openByName(proc_name);
        if (!p) { std::cerr << "Process not found\n"; return 1; }
        provider = std::make_shared<ProcessProvider>(std::move(*p));
    } else {
        std::cerr << "Dump requires --pid or --name\n";
        return 1;
    }

    uintptr_t base = 0;
    if (!region_base_str.empty()) {
        base = std::stoull(region_base_str, nullptr, 16);
    }

    if (base == 0 || dump_size == 0) {
        std::cerr << "Specify --region <hex_base> and --size <bytes>\n";
        return 1;
    }

    auto data = provider->readBytes(base, dump_size);
    if (data.empty()) {
        std::cerr << "Failed to read memory at " << hexAddr(base) << "\n";
        return 1;
    }

    std::string path = output_path.empty() ? "dump.bin" : output_path;
    std::ofstream out(path, std::ios::binary);
    out.write(reinterpret_cast<const char*>(data.data()), data.size());
    std::cout << "Dumped " << humanSize(data.size()) << " to " << path << "\n";
    return 0;
#else
    std::cerr << "Dump not supported on this platform\n";
    return 1;
#endif
}

int main(int argc, char** argv) {
    CLI::App app{"patty - Universal Memory Pattern Scanner"};
    app.require_subcommand(1);

    // Shared options
    uint32_t pid = 0;
    std::string proc_name, file_path, output_fmt = "table";

    // --- scan ---
    auto* scan = app.add_subcommand("scan", "Scan for patterns");
    std::string pattern_str, profile_path, module_filter, resolve_str;
    bool code_only = false, data_only = false;
    size_t max_results = 0;

    scan->add_option("--pid", pid, "Process ID");
    scan->add_option("--name", proc_name, "Process name");
    scan->add_option("--file", file_path, "File path");
    scan->add_option("--pattern,-p", pattern_str, "AOB pattern (e.g. \"48 8B 05 ?? ?? ?? ??\")");
    scan->add_option("--profile", profile_path, "Target profile JSON");
    scan->add_flag("--code-only", code_only, "Scan executable regions only");
    scan->add_flag("--data-only", data_only, "Scan data regions only");
    scan->add_option("--module", module_filter, "Filter by module name");
    scan->add_option("--output,-o", output_fmt, "Output format: table, json");
    scan->add_option("--max", max_results, "Max results per pattern");
    scan->add_option("--resolve", resolve_str, "Resolve type: rip, deref");

    // --- list ---
    auto* list = app.add_subcommand("list", "List memory regions");
    list->add_option("--pid", pid, "Process ID");
    list->add_option("--name", proc_name, "Process name");
    list->add_option("--file", file_path, "File path");
    list->add_option("--output,-o", output_fmt, "Output format: table, json");

    // --- dump ---
    auto* dump = app.add_subcommand("dump", "Dump memory region");
    std::string region_base_str, dump_output;
    size_t dump_size = 0;
    dump->add_option("--pid", pid, "Process ID");
    dump->add_option("--name", proc_name, "Process name");
    dump->add_option("--region", region_base_str, "Region base address (hex)");
    dump->add_option("--size", dump_size, "Size in bytes");
    dump->add_option("--output,-o", dump_output, "Output file path");

    CLI11_PARSE(app, argc, argv);

    if (scan->parsed()) {
        return cmdScan(pid, proc_name, file_path, pattern_str, profile_path,
                       code_only, data_only, module_filter, output_fmt, max_results, resolve_str);
    }
    if (list->parsed()) {
        return cmdList(pid, proc_name, file_path, output_fmt);
    }
    if (dump->parsed()) {
        return cmdDump(pid, proc_name, region_base_str, dump_size, dump_output);
    }

    return 0;
}
