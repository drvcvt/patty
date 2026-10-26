#include "session.h"
#include "expr.h"
#include "../output.h"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <ostream>

namespace patty::cli {

namespace {

std::string lower(std::string_view text) {
    std::string out(text);
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

bool contains_ci(std::string_view haystack, std::string_view needle) {
    return lower(haystack).find(lower(needle)) != std::string::npos;
}

std::vector<Session::Token> tokenize(std::string_view text) {
    std::vector<Session::Token> tokens;
    size_t i = 0;
    while (i < text.size()) {
        if (std::isspace(static_cast<unsigned char>(text[i]))) {
            ++i;
            continue;
        }
        Session::Token token;
        token.offset = i;
        if (text[i] == '"') {
            const auto end = text.find('"', i + 1);
            if (end == std::string_view::npos)
                throw Error("missing closing \"");
            token.text = std::string(text.substr(i + 1, end - i - 1));
            token.quoted = true;
            i = end + 1;
        } else {
            while (i < text.size() && !std::isspace(static_cast<unsigned char>(text[i])))
                token.text.push_back(text[i++]);
        }
        tokens.push_back(std::move(token));
    }
    return tokens;
}

bool is_flag(const Session::Token& token) {
    return !token.quoted && token.text.size() >= 2 && token.text[0] == '-' &&
           std::isalpha(static_cast<unsigned char>(token.text[1]));
}

size_t require_number(const std::string& text) {
    const auto value = parse_number(text);
    if (!value)
        throw Error("not a number: " + text);
    return static_cast<size_t>(*value);
}

} // namespace

// --- argument handling ---------------------------------------------------

const Session::Token& Session::Args::take() {
    if (done())
        throw Error("missing argument");
    return tokens[next++];
}

std::string_view Session::Args::rest() const {
    if (done())
        return {};
    return raw.substr(tokens[next].offset);
}

// --- dispatch ------------------------------------------------------------

const std::vector<Session::Command>& Session::commands() {
    static const std::vector<Command> table = {
        {"proc", nullptr, "proc <pid|name>", "open a running process",
         "Opens a process read-only. Names match case-insensitively; Wine/Proton\n"
         "games are found by their .exe name.\n\n  proc 4242\n  proc Game.exe",
         &Session::cmd_proc},
        {"file", nullptr, "file [-raw] <path>", "open a binary or dump",
         "PE and ELF files are mapped like a loader would (sections at their virtual\n"
         "addresses). -raw loads the bytes flat at address 0.\n\n  file ~/dumps/Game.exe",
         &Session::cmd_file},
        {"close", nullptr, "close", "drop the current target", "", &Session::cmd_close},
        {"info", "i", "info", "describe the current target", "", &Session::cmd_info},
        {"maps", nullptr, "maps [text]", "list readable regions",
         "Lists regions, optionally only those whose name contains <text>.\n\n  maps\n  maps heap",
         &Session::cmd_maps},
        {"modules", "mods", "modules [text]", "list loaded modules", "", &Session::cmd_modules},
        {"find", "f", "find [flags] <aob | \"text\">", "search for a byte pattern or string",
         "Flags:\n"
         "  -c          executable regions only     -d   writable data only\n"
         "  -m <mod>    only inside a module         -n N stop after N matches\n"
         "  -o <n>      add n to each match          -r   resolve steps: rip,deref,add:8\n"
         "  -s          \"text\" is an MSVC std::string object, not raw characters\n\n"
         "Every match becomes a $N value.\n\n"
         "  find 48 8B 05 ?? ?? ?? ?? 48 85 C0\n"
         "  find -c -m Game.exe -o 3 -r rip 48 8B 05 ?? ?? ?? ??\n"
         "  find \"PlayerController\"",
         &Session::cmd_find},
        {"findval", "fv", "findval [flags] <value> [type]", "search for a number",
         "Types: i8 i16 i32 i64 u8 u16 u32 u64 float double. Default is i32, or\n"
         "float when the value has a decimal point. Same flags as find.\n\n"
         "  findval 1337\n  findval 87.5\n  findval -d 0x7FF6A0010000 u64",
         &Session::cmd_findval},
        {"refs", nullptr, "refs [flags] <expr>", "find pointers to an address",
         "  refs $1\n  refs -d Game.exe+0x2A4F10", &Session::cmd_refs},
        {"x", nullptr, "x[/NFU] <expr>", "examine memory",
         "Without /: hex dump of 64 bytes. Otherwise N units in format F of size U:\n"
         "  F: x hex  d signed  u unsigned  f float  a address  s string  c char\n"
         "  U: b 1    h 2       w 4         g 8\n\n"
         "  x $1\n  x/8xg [Game.exe+0x2A4F10]\n  x/4f $2+0x30\n  x/s $3",
         &Session::cmd_examine},
        {"print", "p", "print <expr>", "evaluate an address expression",
         "Expressions: numbers (0x for hex), module names (quote ones with '-'),\n"
         "$ and $N values, [expr] to read a pointer, + - * / and parentheses.\n\n"
         "  p Game.exe+0x2A4F10\n  p [[$1]+0x18]\n  p 'ld-linux-x86-64.so.2'",
         &Session::cmd_print},
        {"probe", nullptr, "probe [-s size] <expr>", "guess what each field of an object is",
         "  probe [$1]\n  probe -s 0x80 $2", &Session::cmd_probe},
        {"dump", nullptr, "dump <file> <size> <expr>", "write memory to a file",
         "  dump player.bin 0x400 [$1]", &Session::cmd_dump},
        {"load", nullptr, "load <profile.json>", "load a signature profile", "", &Session::cmd_load},
        {"check", nullptr, "check [-m module]", "check the loaded profile against the target",
         "Each signature comes back ok (unique, with its RVA), ambiguous, missing or\n"
         "unresolved. ok values become $N.",
         &Session::cmd_check},
        {"set", nullptr, "set [max N | parallel on|off]", "show or change scan settings", "", &Session::cmd_set},
        {"help", "h", "help [command]", "list commands or explain one", "", &Session::cmd_help},
        {"quit", "q", "quit", "leave (Ctrl-D twice works too)", "", nullptr},
    };
    return table;
}

std::vector<std::string> Session::command_names() {
    std::vector<std::string> names;
    for (const auto& command : commands())
        names.emplace_back(command.name);
    return names;
}

bool Session::execute(std::string_view line) {
    while (!line.empty() && std::isspace(static_cast<unsigned char>(line.front())))
        line.remove_prefix(1);
    if (line.empty() || line.front() == '#')
        return true;

    const auto word_end = line.find_first_of(" \t");
    std::string word(line.substr(0, word_end));
    Args args;
    args.raw = word_end == std::string_view::npos ? std::string_view{} : line.substr(word_end + 1);
    if (const auto slash = word.find('/'); slash != std::string::npos) {
        args.suffix = word.substr(slash + 1);
        word.resize(slash);
    }

    const auto& table = commands();
    const auto command = std::find_if(table.begin(), table.end(), [&](const Command& c) {
        return word == c.name || (c.alias && word == c.alias);
    });
    if (command == table.end()) {
        m_out << "unknown command \"" << word << "\", try help\n";
        return true;
    }
    if (!command->run)
        return false;

    try {
        args.tokens = tokenize(args.raw);
        m_cancel = false;
        (this->*command->run)(args);
    } catch (const Error& e) {
        m_out << "error: " << e.what() << '\n';
    } catch (const std::exception& e) {
        m_out << "error: " << e.what() << '\n';
    }
    return true;
}

// --- helpers -------------------------------------------------------------

Target& Session::target() {
    if (!m_target)
        throw Error("no target yet, open one with proc or file");
    return *m_target;
}

uint64_t Session::eval(std::string_view expression) {
    if (expression.empty())
        throw Error("missing address expression");
    return evaluate(expression, {m_target.get(), m_values});
}

std::string Session::remember(uintptr_t value) {
    m_values.push_back(value);
    return "$" + std::to_string(m_values.size());
}

std::string Session::where(uintptr_t address) {
    if (!m_target)
        return {};
    std::string text;
    if (const auto module = m_target->module_at(address))
        text = module->name + "+" + hex_short(address - module->base);
    if (const auto region = m_target->region_at(address)) {
        text += (text.empty() ? "" : " ") + permissions(*region);
        if (!region->name.empty() && (!m_target->module_at(address) || region->name != m_target->module_at(address)->name))
            text += " " + region->name;
    } else {
        text += text.empty() ? "unmapped" : " unmapped";
    }
    return text;
}

ScanOptions Session::scan_flags(Args& args, const FlagHandler& extra) {
    ScanOptions options;
    options.max = m_max;
    options.parallel = m_parallel;
    options.cancel = &m_cancel;
    while (!args.done() && is_flag(args.tokens[args.next])) {
        const std::string flag = args.take().text;
        if (flag == "-c")
            options.code_only = true;
        else if (flag == "-d")
            options.data_only = true;
        else if (flag == "-m")
            options.module = args.take().text;
        else if (flag == "-n")
            options.max = require_number(args.take().text);
        else if (!extra || !extra(flag, args))
            throw Error("unknown flag " + flag);
    }
    if (options.code_only && options.data_only)
        throw Error("-c and -d exclude each other");
    return options;
}

void Session::show(const std::vector<ScanResult>& results, const ScanOptions& options) {
    const size_t width = target().pointer_size();
    print_results(m_out, results, width, [this](const Match& m) { return remember(m.value()); });
    for (const auto& result : results)
        if (options.max && result.size() >= options.max)
            m_out << "  (stopped at " << options.max << ", use -n or \"set max\" for more)\n";
}

std::string Session::prompt() const {
    if (!m_target)
        return "patty";
    if (const auto* process = dynamic_cast<const Process*>(m_target.get()))
        return "patty " + process->name() + ":" + std::to_string(process->pid());
    return "patty " + static_cast<const Image*>(m_target.get())->name();
}

std::vector<std::string> Session::module_names() {
    std::vector<std::string> names;
    if (m_target)
        for (const auto& module : m_target->modules())
            names.push_back(module.name);
    return names;
}

void Session::open(const TargetArgs& args) {
    m_target = open_target(args);
    m_out << "opened " << m_target->describe() << '\n';
}

// --- target commands -----------------------------------------------------

void Session::cmd_proc(Args& args) {
    const std::string which = args.take().text;
    TargetArgs target;
    if (const auto pid = parse_number(which))
        target.pid = static_cast<uint32_t>(*pid);
    else
        target.name = which;
    open(target);
}

void Session::cmd_file(Args& args) {
    TargetArgs target;
    if (!args.done() && args.tokens[args.next].text == "-raw") {
        target.raw = true;
        args.take();
    }
    target.file = std::string(args.rest());
    if (!args.done() && args.tokens[args.next].quoted)
        target.file = args.tokens[args.next].text;
    if (target.file.empty())
        throw Error("usage: file [-raw] <path>");
    open(target);
}

void Session::cmd_close(Args&) {
    m_target.reset();
    m_out << "closed\n";
}

void Session::cmd_info(Args&) {
    auto& t = target();
    const auto regions = t.regions();
    size_t bytes = 0;
    for (const auto& region : regions)
        bytes += region.size;
    m_out << t.describe() << '\n'
          << "  " << t.pointer_size() * 8 << "-bit, " << regions.size()
          << (regions.size() == 1 ? " region, " : " regions, ")
          << human_size(bytes) << " readable, " << t.modules().size()
          << (t.modules().size() == 1 ? " module\n" : " modules\n");
    if (m_profile)
        m_out << "  profile " << (m_profile->name.empty() ? "(unnamed)" : m_profile->name) << ", "
              << m_profile->patterns.size() << " patterns\n";
    if (!m_values.empty())
        m_out << "  values $1..$" << m_values.size() << '\n';
}

void Session::cmd_maps(Args& args) {
    auto regions = target().regions();
    if (const auto filter = args.rest(); !filter.empty())
        std::erase_if(regions, [&](const Region& r) { return !contains_ci(r.name, filter); });
    print_regions(m_out, regions, target().pointer_size());
}

void Session::cmd_modules(Args& args) {
    auto modules = target().modules();
    if (const auto filter = args.rest(); !filter.empty())
        std::erase_if(modules, [&](const Module& m) { return !contains_ci(m.name, filter); });
    print_modules(m_out, modules, target().pointer_size());
}

// --- scanning ------------------------------------------------------------

void Session::cmd_find(Args& args) {
    int64_t offset = 0;
    std::string resolve;
    bool msvc = false;
    auto options = scan_flags(args, [&](const std::string& flag, Args& a) {
        if (flag == "-o")
            offset = static_cast<int64_t>(require_number(a.take().text));
        else if (flag == "-r")
            resolve = a.take().text;
        else if (flag == "-s")
            msvc = true;
        else
            return false;
        return true;
    });
    if (args.done())
        throw Error("usage: find [flags] <aob | \"text\">");

    const auto& first = args.tokens[args.next];
    auto pattern = first.quoted ? (msvc ? Pattern::msvc_string(first.text) : Pattern::text(first.text))
                                : Pattern::aob(args.rest());
    if (offset)
        pattern.add(offset);
    apply_resolve_spec(pattern, resolve);
    show({Scanner(target()).find(pattern, options)}, options);
}

void Session::cmd_findval(Args& args) {
    auto options = scan_flags(args);
    const std::string value = args.take().text;
    const bool decimal_point = value.find('.') != std::string::npos;
    const std::string type = args.done() ? (decimal_point ? "float" : "i32") : lower(args.take().text);

    std::optional<Pattern> pattern;
    if (type == "float" || type == "double") {
        size_t used = 0;
        const double number = std::stod(value, &used);
        if (used != value.size())
            throw Error("not a number: " + value);
        pattern = type == "float" ? Pattern::value(static_cast<float>(number)) : Pattern::value(number);
    } else {
        static const std::pair<const char*, size_t> sizes[] = {
            {"i8", 1}, {"u8", 1}, {"i16", 2}, {"u16", 2}, {"i32", 4}, {"u32", 4}, {"i64", 8}, {"u64", 8}};
        const auto size = std::find_if(std::begin(sizes), std::end(sizes),
                                       [&](const auto& entry) { return type == entry.first; });
        if (size == std::end(sizes))
            throw Error("unknown type " + type + " (i8 i16 i32 i64 u8 u16 u32 u64 float double)");
        const auto number = parse_number(value);
        if (!number)
            throw Error("not a number: " + value);
        pattern = Pattern::integer(*number, size->second);
    }
    pattern->named(value + " " + type);
    show({Scanner(target()).find(*pattern, options)}, options);
}

void Session::cmd_refs(Args& args) {
    auto options = scan_flags(args);
    const auto address = static_cast<uintptr_t>(eval(args.rest()));
    show({Scanner(target()).find_pointer(address, options)}, options);
}

// --- profiles ------------------------------------------------------------

void Session::cmd_load(Args& args) {
    const auto path = args.done() ? std::string{} : (args.tokens[args.next].quoted ? args.tokens[args.next].text
                                                                                  : std::string(args.rest()));
    if (path.empty())
        throw Error("usage: load <profile.json>");
    m_profile = Profile::load(path);
    m_out << "loaded " << m_profile->patterns.size() << " patterns"
          << (m_profile->name.empty() ? "" : " from " + m_profile->name)
          << (m_profile->module ? " for " + *m_profile->module : "") << '\n';
}

void Session::cmd_check(Args& args) {
    if (!m_profile)
        throw Error("no profile, load one first");
    auto options = scan_flags(args);
    options.max = 100;
    apply_profile_module(options, *m_profile, target());
    const auto report = Scanner(target()).check(*m_profile, options);
    print_check(m_out, report, target().pointer_size());

    std::string labels;
    for (const auto& check : report.patterns)
        if (check.status == CheckStatus::Ok)
            labels += "  " + remember(check.value) + " " + check.name + "\n";
    if (!labels.empty())
        m_out << '\n' << labels;
}

void Session::cmd_set(Args& args) {
    if (!args.done()) {
        const std::string key = args.take().text;
        const std::string value = args.take().text;
        if (key == "max")
            m_max = require_number(value);
        else if (key == "parallel")
            m_parallel = value == "on" || value == "1" || value == "true";
        else
            throw Error("unknown setting " + key + " (max, parallel)");
    }
    m_out << "max " << m_max << (m_max ? "" : " (unlimited)") << ", parallel " << (m_parallel ? "on" : "off") << '\n';
}

void Session::cmd_help(Args& args) {
    const auto& table = commands();
    if (!args.done()) {
        const std::string name = args.take().text;
        const auto command = std::find_if(table.begin(), table.end(), [&](const Command& c) {
            return name == c.name || (c.alias && name == c.alias);
        });
        if (command == table.end())
            throw Error("no command " + name);
        m_out << command->usage << "\n  " << command->summary << '\n';
        if (*command->details)
            m_out << '\n' << command->details << '\n';
        return;
    }
    for (const auto& command : table)
        m_out << "  " << std::left << std::setw(34) << command.usage << command.summary << '\n';
    m_out << "\nhelp <command> shows details and examples.\n";
}

} // namespace patty::cli
