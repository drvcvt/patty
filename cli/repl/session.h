#pragma once

#include "../commands.h"

#include <patty/patty.h>

#include <atomic>
#include <functional>
#include <iosfwd>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace patty::cli {

// State and commands of one interactive session. Input handling (line
// editing, history, Ctrl-C) lives in repl.cpp; this class only executes lines.
class Session {
public:
    explicit Session(std::ostream& out) : m_out(out) {}

    // Runs one line. Errors are printed, not thrown. Returns false on "quit".
    bool execute(std::string_view line);

    // Throws patty::Error.
    void open(const TargetArgs& args);

    std::string prompt() const;
    bool has_target() const { return m_target != nullptr; }
    std::atomic_bool& cancel_flag() { return m_cancel; }

    // For tab completion.
    static std::vector<std::string> command_names();
    std::vector<std::string> module_names();

    struct Token {
        std::string text;
        bool quoted = false;
        size_t offset = 0;  // where the token starts in the argument string
    };
    struct Args {
        std::string_view raw;      // everything after the command word
        std::string suffix;        // "16xb" for "x/16xb"
        std::vector<Token> tokens;
        size_t next = 0;           // first token not consumed by flags

        bool done() const { return next >= tokens.size(); }
        const Token& take();
        // The unconsumed rest of the line, verbatim (expressions may contain spaces).
        std::string_view rest() const;
    };

private:
    using Handler = void (Session::*)(Args&);
    struct Command {
        const char* name;
        const char* alias;
        const char* usage;
        const char* summary;
        const char* details;
        Handler run;
    };
    static const std::vector<Command>& commands();

    // session.cpp
    void cmd_help(Args& args);
    void cmd_open(Args& args);
    void cmd_ps(Args& args);
    void cmd_proc(Args& args);
    void cmd_file(Args& args);
    void cmd_close(Args& args);
    void cmd_info(Args& args);
    void cmd_maps(Args& args);
    void cmd_modules(Args& args);
    void cmd_find(Args& args);
    void cmd_findval(Args& args);
    void cmd_refs(Args& args);
    void cmd_load(Args& args);
    void cmd_check(Args& args);
    void cmd_set(Args& args);

    // session_memory.cpp
    void cmd_examine(Args& args);
    void cmd_print(Args& args);
    void cmd_probe(Args& args);
    void cmd_dump(Args& args);

    Target& target();
    uint64_t eval(std::string_view expression);
    // Stores a value as the next $N and returns "$N".
    std::string remember(uintptr_t value);
    // "Game.exe+0x1A2B r-x .text" or "[heap] rw-"
    std::string where(uintptr_t address);
    // Same, with the lists passed in, so many lookups share one /proc read.
    static std::string where(uintptr_t address, const std::vector<Module>& modules,
                             const std::vector<Region>& regions);
    // Closest command name for typos, empty if nothing is close.
    static std::string suggest(std::string_view word);
    // Consumes -c -d -m <module> -n <max> -p; other flags go to `extra`,
    // which returns false for flags it does not know either.
    using FlagHandler = std::function<bool(const std::string& flag, Args& args)>;
    ScanOptions scan_flags(Args& args, const FlagHandler& extra = {});
    void show(const std::vector<ScanResult>& results, const ScanOptions& options);

    std::ostream& m_out;
    std::unique_ptr<Target> m_target;
    std::vector<uintptr_t> m_values;
    std::optional<Profile> m_profile;
    size_t m_max = 50;
    bool m_parallel = true;
    std::atomic_bool m_cancel{false};
};

} // namespace patty::cli
