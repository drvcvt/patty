#include "commands.h"

#include <CLI/CLI.hpp>

#include <iostream>

using namespace patty;
using namespace patty::cli;

namespace {

void add_target(CLI::App* app, TargetArgs& target) {
    app->add_option("--pid", target.pid, "Process id");
    app->add_option("--name", target.name, "Process name, e.g. Game.exe");
    app->add_option("--file", target.file, "Binary or dump on disk");
    app->add_flag("--raw", target.raw, "Load --file flat, without parsing PE/ELF headers");
}

void add_scan(CLI::App* app, ScanArgs& scan) {
    app->add_flag("--code-only", scan.code_only, "Executable regions only");
    app->add_flag("--data-only", scan.data_only, "Writable, non-executable regions only");
    app->add_option("--module", scan.module, "Only inside this module");
    app->add_option("--region", scan.region, "Only regions with this name (e.g. .text of a file)");
    app->add_option("--max", scan.max, "Matches per pattern (0 = all)");
    app->add_flag("--parallel", scan.parallel, "Accepted for compatibility, scans are parallel by default");
    app->add_option("--threads", scan.threads, "Worker threads (0 = all cores, 1 = single thread)");
    app->add_option("--chunk-size", scan.chunk_size, "Bytes read per step (default 256 KiB)");
    app->add_option("--output,-o", scan.output, "table or json");
}

} // namespace

int main(int argc, char** argv) {
    CLI::App app{"patty: read-only memory pattern scanner for processes and binaries.\n"
                 "Run without a command for the interactive shell."};
    app.require_subcommand(0, 1);
    app.set_version_flag("--version", std::string(version_string));

    TargetArgs repl_target;
    auto* repl = app.add_subcommand("repl", "Interactive shell (also the default without a command)");
    add_target(repl, repl_target);

    TargetArgs scan_target;
    ScanArgs scan_args;
    PatternArgs pattern;
    auto* scan = app.add_subcommand("scan", "Search for a pattern, string or a whole profile");
    add_target(scan, scan_target);
    add_scan(scan, scan_args);
    scan->add_option("--pattern,-p", pattern.aob, "Byte pattern, e.g. \"48 8B 05 ?? ?? ?? ??\"");
    scan->add_option("--ida", pattern.ida, "IDA-style pattern (same syntax)");
    scan->add_option("--string", pattern.text, "Exact ASCII string");
    scan->add_option("--sso-string", pattern.msvc_string, "MSVC std::string object holding this text");
    scan->add_option("--profile", pattern.profile, "Profile JSON with many patterns");
    scan->add_option("--offset", pattern.offset, "Add to each match before resolving");
    scan->add_option("--resolve", pattern.resolve, "Resolve steps: rip,deref,add:<n>");

    TargetArgs value_target;
    ScanArgs value_args;
    std::string value;
    size_t value_size = 8;
    auto* scan_value = app.add_subcommand("scan-value", "Search for a little-endian integer");
    add_target(scan_value, value_target);
    add_scan(scan_value, value_args);
    scan_value->add_option("--value", value, "Value, decimal or 0x hex")->required();
    scan_value->add_option("--size", value_size, "Width in bytes, 1..8");

    TargetArgs pointer_target;
    ScanArgs pointer_args;
    std::string pointer;
    auto* scan_pointer = app.add_subcommand("scan-pointer", "Find pointers to an address");
    add_target(scan_pointer, pointer_target);
    add_scan(scan_pointer, pointer_args);
    scan_pointer->add_option("--address", pointer, "Address the pointers point to")->required();

    TargetArgs pointers_target;
    ScanArgs pointers_args;
    std::vector<std::string> pointers;
    auto* scan_pointers = app.add_subcommand("scan-pointers", "Find pointers to several addresses in one pass");
    add_target(scan_pointers, pointers_target);
    add_scan(scan_pointers, pointers_args);
    scan_pointers->add_option("--address", pointers, "Repeat for each address")->required();

    TargetArgs check_target;
    ScanArgs check_args;
    std::string check_profile;
    auto* check = app.add_subcommand("check", "Check that every profile signature still matches uniquely");
    add_target(check, check_target);
    add_scan(check, check_args);
    check->add_option("--profile", check_profile, "Profile JSON")->required();

    TargetArgs probe_target;
    std::string probe_address, probe_output = "table";
    size_t probe_size = 0x400;
    auto* probe = app.add_subcommand("probe", "Guess what each field of an object is");
    add_target(probe, probe_target);
    probe->add_option("--address", probe_address, "Object address")->required();
    probe->add_option("--size", probe_size, "Bytes to look at (default 0x400)");
    probe->add_option("--output,-o", probe_output, "table or json");

    TargetArgs list_target;
    std::string list_output = "table";
    bool list_modules = false;
    auto* list = app.add_subcommand("list", "List regions or modules");
    add_target(list, list_target);
    list->add_flag("--modules", list_modules, "Modules instead of regions");
    list->add_option("--output,-o", list_output, "table or json");

    TargetArgs dump_target;
    std::string dump_address, dump_path = "dump.bin";
    size_t dump_size = 0;
    auto* dump = app.add_subcommand("dump", "Write memory to a file");
    add_target(dump, dump_target);
    dump->add_option("--region,--address", dump_address, "Start address")->required();
    dump->add_option("--size", dump_size, "Bytes")->required();
    dump->add_option("--output,-o", dump_path, "File to write (default dump.bin)");

    CLI11_PARSE(app, argc, argv);

    try {
        if (scan->parsed())
            return cmd_scan(scan_target, scan_args, pattern);
        if (scan_value->parsed())
            return cmd_scan_value(value_target, value_args, value, value_size);
        if (scan_pointer->parsed())
            return cmd_scan_pointers(pointer_target, pointer_args, {pointer}, "scan-pointer");
        if (scan_pointers->parsed())
            return cmd_scan_pointers(pointers_target, pointers_args, pointers, "scan-pointers");
        if (check->parsed())
            return cmd_check(check_target, check_args, check_profile);
        if (probe->parsed())
            return cmd_probe(probe_target, probe_address, probe_size, probe_output);
        if (list->parsed())
            return cmd_list(list_target, list_modules, list_output);
        if (dump->parsed())
            return cmd_dump(dump_target, dump_address, dump_size, dump_path);
        return run_repl(repl_target);
    } catch (const Error& e) {
        std::cerr << "patty: " << e.what() << '\n';
        return 1;
    }
}
