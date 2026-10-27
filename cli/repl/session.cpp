#include "session.h"
#include "expr.h"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <iostream>
#include <sstream>

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

bool is_name(std::string_view text) {
    return !text.empty() && (std::isalpha(static_cast<unsigned char>(text[0])) || text[0] == '_') &&
           std::all_of(text.begin(), text.end(), [](unsigned char c) { return std::isalnum(c) || c == '_'; });
}

} // namespace

// --- arguments -----------------------------------------------------------

const Session::Token& Session::Args::take() {
    if (done())
        throw Error("missing argument");
    return tokens[next++];
}

std::string_view Session::Args::rest() const {
    if (done())
        return {};
    if (next + 1 == tokens.size() && tokens[next].quoted)
        return tokens[next].text;
    return raw.substr(tokens[next].offset);
}

// --- commands ------------------------------------------------------------

const std::vector<Session::Command>& Session::commands() {
    static const std::vector<Command> table = {
        {"open", "o", "target", "open <pid|name|file>", "open a process, a binary or a dump",
         "A number is a pid, an existing file is a file, anything else a process name.\n"
         "-raw loads a file flat at address 0 instead of mapping its PE/ELF sections.\n\n"
         "  open toygame\n  open 4242\n  open ~/dumps/Game.exe",
         &Session::cmd_open},
        {"ps", nullptr, "target", "ps [text]", "list processes", "  ps\n  ps game", &Session::cmd_ps},
        {"info", "i", "target", "info", "what's open", "", &Session::cmd_info},
        {"maps", nullptr, "target", "maps [text]", "readable regions", "  maps\n  maps heap", &Session::cmd_maps},
        {"modules", "mods", "target", "modules [text]", "loaded modules", "", &Session::cmd_modules},
        {"close", nullptr, "target", "close", "drop the target", "", &Session::cmd_close},

        {"find", "f", "search", "find [flags] <sig | text>", "search for a signature or a string",
         "Hex bytes with ?? wildcards are a signature, anything else is searched as\n"
         "text. Quote text that has spaces.\n\n"
         "  -c        code only            -d   writable data only\n"
         "  -m <mod>  inside one module    -n N stop after N hits\n"
         "  -r 3      follow the rip-relative operand at byte 3\n"
         "  -o <n>    add n to each hit    -r rip,deref,add:8  any resolve steps\n"
         "  -s        text is an MSVC std::string object\n\n"
         "  find -c -m Game.exe -r 3 48 8B 05 ?? ?? ?? ??\n"
         "  find PlayerController",
         &Session::cmd_find},
        {"findval", "fv", "search", "findval [flags] <value> [type]", "search for a number",
         "Types: i8 i16 i32 i64 u8 u16 u32 u64 float double. Default i32, or float when\n"
         "the value has a decimal point. Same flags as find.\n\n"
         "  findval 1337\n  findval 87.5\n  findval -d 0x7FF6A0010000 u64",
         &Session::cmd_findval},
        {"refs", nullptr, "search", "refs [flags] <expr|->", "find pointers to an address",
         "  refs $1\n  refs -d Game.exe+0x2A4F10", &Session::cmd_refs},
        {"filter", nullptr, "search", "filter <type> <op> [value] [-]", "keep the hits whose value matches now",
         "Works on the hits of the last find/findval/refs/read/filter, or on the\n"
         "addresses piped in with -. Ops: == != < > <= >=, and changed, unchanged,\n"
         "increased, decreased (against the value at the last look).\n\n"
         "  findval 100\n  filter i32 == 90\n  filter i32 decreased",
         &Session::cmd_filter},

        {"read", "r", "memory", "read [-n count] <type> <expr|->", "read typed values",
         "Types: i8 .. u64, float, double, ptr, str.\n\n"
         "  read float $2\n  read str [[$5]+8]\n  read -n 4 i32 [$1]",
         &Session::cmd_read},
        {"x", nullptr, "memory", "x[/NFU] <expr>", "examine memory, gdb style",
         "Without /: hex dump of 64 bytes. Otherwise N units in format F of size U:\n"
         "  F: x hex  d signed  u unsigned  f float  a address  s string  c char\n"
         "  U: b 1    h 2       w 4         g 8\n\n"
         "  x $1\n  x/8xg [Game.exe+0x2A4F10]\n  x/s $3",
         &Session::cmd_examine},
        {"print", "p", "memory", "p <expr|->", "evaluate an address, show where it points",
         "Numbers (0x for hex), module names (quote names with '-'), $ $N $name,\n"
         "[expr] reads a pointer, + - * / and parentheses.\n\n"
         "  p Game.exe+0x2A4F10\n  p [[$1]+0x18]",
         &Session::cmd_print},
        {"probe", nullptr, "memory", "probe [-s size] <expr|->", "guess what each field of an object is",
         "  probe [$1]\n  probe -s 0x80 $2", &Session::cmd_probe},
        {"dump", nullptr, "memory", "dump <file> <size> <expr>", "write memory to a file",
         "  dump player.bin 0x400 [$1]", &Session::cmd_dump},

        {"check", nullptr, "profiles", "check [-m module] [profile.json]", "check a signature profile",
         "Each signature comes back ok (unique, with its RVA), ambiguous, missing or\n"
         "unresolved. The profile is remembered, later checks can leave it out.",
         &Session::cmd_check},

        {"vals", nullptr, "shell", "vals", "list $names and recent $N", "", &Session::cmd_vals},
        {"set", nullptr, "shell", "set [max N | parallel on|off]", "scan settings", "", &Session::cmd_set},
        {"help", "h", "shell", "help [command]", "this, or details on one command", "", &Session::cmd_help},
        {"quit", "q", "shell", "quit", "leave (Ctrl-D twice works too)", "", nullptr},
    };
    return table;
}

bool Session::is_command(std::string_view word) {
    const auto& table = commands();
    return std::any_of(table.begin(), table.end(), [&](const Command& c) {
        return word == c.name || (c.alias && word == c.alias) || word.starts_with("x/");
    });
}

std::vector<std::string> Session::command_names() {
    std::vector<std::string> names;
    for (const auto& command : commands())
        names.emplace_back(command.name);
    return names;
}

int Session::execute(std::string_view line) {
    while (!line.empty() && std::isspace(static_cast<unsigned char>(line.front())))
        line.remove_prefix(1);
    while (!line.empty() && std::isspace(static_cast<unsigned char>(line.back())))
        line.remove_suffix(1);
    if (line.empty() || line.front() == '#')
        return 0;

    // $name = expression
    if (line.front() == '$') {
        const auto equals = line.find('=');
        if (equals != std::string_view::npos && line.substr(equals, 2) != "==") {
            auto name = line.substr(1, equals - 1);
            while (!name.empty() && std::isspace(static_cast<unsigned char>(name.back())))
                name.remove_suffix(1);
            try {
                return assign(name, line.substr(equals + 1));
            } catch (const std::exception& e) {
                m_out.err() << "error: " << e.what() << '\n';
                return 1;
            }
        }
    }

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
        const auto close = suggest(word);
        m_out.err() << "unknown command \"" << word << "\""
                    << (close.empty() ? ", try help" : ", did you mean " + close + "?") << '\n';
        return 1;
    }
    if (!command->run) {
        m_quit = true;
        return 0;
    }

    try {
        args.tokens = tokenize(args.raw);
        m_cancel = false;
        return (this->*command->run)(args);
    } catch (const std::exception& e) {
        m_out.err() << "error: " << e.what() << '\n';
        return 1;
    }
}

// --- helpers -------------------------------------------------------------

Target& Session::target() {
    if (!m_target)
        throw Error("nothing open yet: open <pid|name|file>");
    return *m_target;
}

uint64_t Session::eval(std::string_view expression) {
    if (expression.empty())
        throw Error("missing address expression");
    return evaluate(expression, {m_target.get(), m_values, &m_names});
}

const std::vector<Session::InputLine>& Session::input() {
    if (!m_stdin_data)
        throw Error("\"-\" reads addresses from a pipe: patty <target> <command> ... -");
    if (!m_input) {
        m_input.emplace();
        std::string line;
        while (std::getline(std::cin, line)) {
            std::istringstream fields(line);
            std::string first, second;
            fields >> first >> second;
            if (const auto address = parse_number(first))
                m_input->push_back({static_cast<Address>(*address), second});
        }
    }
    return *m_input;
}

std::vector<Address> Session::addresses(const Args& args) {
    if (args.rest() == "-") {
        std::vector<Address> result;
        for (const auto& line : input())
            result.push_back(line.address);
        return result;
    }
    return {static_cast<Address>(eval(args.rest()))};
}

std::string Session::remember(Address value) {
    m_values.push_back(value);
    return "$" + std::to_string(m_values.size());
}

std::string Session::where(Address address) {
    if (!m_target)
        return {};
    return where(address, m_target->modules(), m_target->regions());
}

std::string Session::where(Address address, const std::vector<Module>& modules,
                           const std::vector<Region>& regions) {
    std::string text;
    const Module* module = nullptr;
    for (const auto& m : modules)
        if (m.contains(address))
            module = &m;
    if (module)
        text = module->name + "+" + hex_short(address - module->base);
    const Region* region = nullptr;
    for (const auto& r : regions)
        if (r.contains(address))
            region = &r;
    if (region) {
        text += (text.empty() ? "" : " ") + permissions(*region);
        if (!region->name.empty() && (!module || region->name != module->name))
            text += " " + region->name;
    } else {
        text += text.empty() ? "unmapped" : " unmapped";
    }
    return text;
}

std::string Session::suggest(std::string_view word) {
    // Plain edit distance; the command list is short.
    auto distance = [](std::string_view a, std::string_view b) {
        std::vector<size_t> row(b.size() + 1);
        for (size_t j = 0; j <= b.size(); ++j)
            row[j] = j;
        for (size_t i = 1; i <= a.size(); ++i) {
            size_t diagonal = row[0];
            row[0] = i;
            for (size_t j = 1; j <= b.size(); ++j) {
                const size_t above = row[j];
                row[j] = std::min({row[j] + 1, row[j - 1] + 1, diagonal + (a[i - 1] != b[j - 1])});
                diagonal = above;
            }
        }
        return row[b.size()];
    };
    std::string best;
    size_t best_distance = 3;
    for (const auto& command : commands()) {
        for (const char* name : {command.name, command.alias}) {
            if (!name)
                continue;
            const size_t d = distance(word, name);
            if (d < best_distance) {
                best_distance = d;
                best = command.name;
            }
        }
    }
    return best;
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

std::string Session::prompt() const {
    if (!m_target)
        return "patty";
    if (const auto* process = dynamic_cast<const Process*>(m_target.get()))
        return "patty " + process->name() + ":" + std::to_string(process->pid());
    return "patty " + static_cast<const Image*>(m_target.get())->name();
}

std::vector<std::string> Session::completion_words() {
    std::vector<std::string> words;
    if (m_target)
        for (const auto& module : m_target->modules())
            words.push_back(module.name);
    for (const auto& [name, value] : m_names)
        words.push_back("$" + name);
    return words;
}

void Session::open(const TargetArgs& args, bool announce) {
    m_target = open_target(args);
    m_hits.clear();
    if (announce)
        m_out.info() << "opened " << m_target->describe() << '\n';
}

int Session::assign(std::string_view name, std::string_view expression) {
    if (!is_name(name))
        throw Error("bad name \"$" + std::string(name) + "\" (letters, digits, _)");
    const auto value = static_cast<Address>(eval(expression));
    m_names[std::string(name)] = value;
    const size_t width = m_target ? m_target->pointer_size() : 8;
    const auto place = where(value);
    m_out.record("$" + std::string(name) + " = " + hex(value, width) + (place.empty() ? "" : "  " + place),
                 {hex(value, width), place}, {{"name", name}, {"value", hex(value, width)}, {"where", place}});
    return 0;
}

// --- target commands -----------------------------------------------------

int Session::cmd_open(Args& args) {
    bool raw = false;
    if (!args.done() && args.tokens[args.next].text == "-raw") {
        raw = true;
        args.take();
    }
    if (args.done())
        throw Error("usage: open [-raw] <pid|name|file>");
    open(guess_target(args.rest(), raw));
    return 0;
}

int Session::cmd_ps(Args& args) {
    const auto filter = std::string(args.rest());
    size_t shown = 0;
    for (const auto& process : Process::list()) {
        if (!filter.empty() && !contains_ci(process.name, filter))
            continue;
        std::ostringstream line;
        line << std::setw(8) << process.pid << "  " << process.name;
        m_out.record(line.str(), {std::to_string(process.pid), process.name},
                     {{"pid", process.pid}, {"name", process.name}});
        ++shown;
    }
    if (shown == 0)
        m_out.info() << "no process matches \"" << filter << "\"\n";
    return shown ? 0 : 2;
}

int Session::cmd_close(Args&) {
    m_target.reset();
    m_hits.clear();
    m_out.info() << "closed\n";
    return 0;
}

int Session::cmd_info(Args&) {
    auto& t = target();
    const auto regions = t.regions();
    const auto modules = t.modules();
    size_t bytes = 0;
    for (const auto& region : regions)
        bytes += region.size;
    auto& out = m_out.text();
    out << t.describe() << '\n'
        << "  " << t.pointer_size() * 8 << "-bit, " << regions.size() << (regions.size() == 1 ? " region, " : " regions, ")
        << human_size(bytes) << " readable, " << modules.size() << (modules.size() == 1 ? " module\n" : " modules\n");
    if (m_profile)
        out << "  profile " << (m_profile->name.empty() ? "(unnamed)" : m_profile->name) << ", "
            << m_profile->patterns.size() << " patterns\n";
    if (!m_hits.empty())
        out << "  " << m_hits.size() << " hits to filter\n";
    return 0;
}

int Session::cmd_maps(Args& args) {
    const size_t width = target().pointer_size();
    const auto filter = args.rest();
    size_t shown = 0;
    for (const auto& r : target().regions()) {
        if (!filter.empty() && !contains_ci(r.name, filter))
            continue;
        std::ostringstream line;
        line << std::left << hex(r.base, width) << "  " << std::setw(9) << human_size(r.size) << ' '
             << permissions(r) << "  " << r.name;
        m_out.record(line.str(), {hex(r.base, width), std::to_string(r.size), permissions(r), r.name},
                     {{"base", hex(r.base, width)}, {"size", r.size}, {"perms", permissions(r)}, {"name", r.name}});
        ++shown;
    }
    return shown ? 0 : 2;
}

int Session::cmd_modules(Args& args) {
    const size_t width = target().pointer_size();
    const auto filter = args.rest();
    size_t shown = 0;
    for (const auto& m : target().modules()) {
        if (!filter.empty() && !contains_ci(m.name, filter))
            continue;
        std::ostringstream line;
        line << std::left << hex(m.base, width) << "  " << std::setw(9) << human_size(m.size) << ' ' << m.name;
        m_out.record(line.str(), {hex(m.base, width), std::to_string(m.size), m.name},
                     {{"base", hex(m.base, width)}, {"size", m.size}, {"name", m.name}});
        ++shown;
    }
    return shown ? 0 : 2;
}

int Session::cmd_vals(Args&) {
    auto& out = m_out.text();
    const size_t width = m_target ? m_target->pointer_size() : 8;
    for (const auto& [name, value] : m_names)
        out << "  $" << std::left << std::setw(12) << name << hex(value, width) << "  " << where(value) << '\n';
    const size_t first = m_values.size() > 10 ? m_values.size() - 10 : 0;
    for (size_t i = first; i < m_values.size(); ++i)
        out << "  $" << std::left << std::setw(12) << (i + 1) << hex(m_values[i], width) << '\n';
    if (m_names.empty() && m_values.empty())
        out << "no values yet; every hit becomes $N, and $name = <expr> names one\n";
    return 0;
}

int Session::cmd_set(Args& args) {
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
    m_out.text() << "max " << m_max << (m_max ? "" : " (unlimited)") << ", parallel " << (m_parallel ? "on" : "off") << '\n';
    return 0;
}

int Session::cmd_help(Args& args) {
    const auto& table = commands();
    auto& out = m_out.text();
    if (!args.done()) {
        const std::string name = args.take().text;
        const auto command = std::find_if(table.begin(), table.end(), [&](const Command& c) {
            return name == c.name || (c.alias && name == c.alias);
        });
        if (command == table.end())
            throw Error("no command " + name);
        out << command->usage << "\n  " << command->summary << '\n';
        if (*command->details)
            out << '\n' << command->details << '\n';
        return 0;
    }
    std::string group;
    for (const auto& command : table) {
        if (group != command.group) {
            group = command.group;
            out << (group == "target" ? "" : "\n") << group << '\n';
        }
        out << "  " << std::left << std::setw(36) << command.usage << command.summary << '\n';
    }
    out << "\n  $name = <expr>                      give a value a name\n"
        << "\nhelp <command> has examples. In scripts, patty <target> <command> runs one.\n";
    return 0;
}

} // namespace patty::cli
