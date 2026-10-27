#pragma once

#include "../common.h"
#include "../output.h"

#include <patty/patty.h>

#include <atomic>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace patty::cli {

// State and commands of a shell session. The same commands run interactively,
// from a piped script and as `patty <target> <command>`. Input handling (line
// editing, history, Ctrl-C) lives in repl.cpp.
class Session {
public:
    // With `stdin_data`, an argument "-" means "the addresses on stdin".
    explicit Session(Output& out, bool stdin_data = false) : m_out(out), m_stdin_data(stdin_data) {}

    // Runs one line. Returns 0 when it worked and found something, 2 when it
    // found nothing (or a check was not clean), 1 on errors. Errors are printed.
    int execute(std::string_view line);
    bool quit_requested() const { return m_quit; }

    // Throws patty::Error.
    void open(const TargetArgs& args, bool announce = true);

    std::string prompt() const;
    bool has_target() const { return m_target != nullptr; }
    std::atomic_bool& cancel_flag() { return m_cancel; }

    static bool is_command(std::string_view word);
    static std::vector<std::string> command_names();
    // Module names and $names, for tab completion of expressions.
    std::vector<std::string> completion_words();

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
        // The unconsumed rest of the line, verbatim, or the text of a single
        // quoted token (expressions may contain spaces either way).
        std::string_view rest() const;
    };

private:
    using Handler = int (Session::*)(Args&);
    struct Command {
        const char* name;
        const char* alias;
        const char* group;
        const char* usage;
        const char* summary;
        const char* details;
        Handler run;
    };
    static const std::vector<Command>& commands();

    // session.cpp: targets and the shell itself
    int cmd_open(Args& args);
    int cmd_ps(Args& args);
    int cmd_close(Args& args);
    int cmd_info(Args& args);
    int cmd_maps(Args& args);
    int cmd_modules(Args& args);
    int cmd_vals(Args& args);
    int cmd_set(Args& args);
    int cmd_help(Args& args);
    int assign(std::string_view name, std::string_view expression);

    // session_scan.cpp: searching and profiles
    int cmd_find(Args& args);
    int cmd_findval(Args& args);
    int cmd_refs(Args& args);
    int cmd_filter(Args& args);
    int cmd_check(Args& args);

    // session_memory.cpp: looking at memory
    int cmd_read(Args& args);
    int cmd_examine(Args& args);
    int cmd_print(Args& args);
    int cmd_probe(Args& args);
    int cmd_dump(Args& args);

    Target& target();
    uint64_t eval(std::string_view expression);
    // "-" -> every address on stdin, anything else -> one expression.
    std::vector<Address> addresses(const Args& args);
    struct InputLine {
        Address address = 0;
        std::string value;  // second column, if any
    };
    const std::vector<InputLine>& input();
    // Stores a value as the next $N and returns "$N".
    std::string remember(Address value);
    // "Game.exe+0x1A2B r-x" or "rw- [heap]"
    std::string where(Address address);
    static std::string where(Address address, const std::vector<Module>& modules,
                             const std::vector<Region>& regions);
    static std::string suggest(std::string_view word);

    // Consumes -c -d -m <module> -n <max>; other flags go to `extra`, which
    // returns false for flags it does not know either.
    using FlagHandler = std::function<bool(const std::string& flag, Args& args)>;
    ScanOptions scan_flags(Args& args, const FlagHandler& extra = {});
    // Prints hits and makes them the set `filter` works on. `last` is what
    // they held when found (the searched value), if known.
    int show(const std::vector<ScanResult>& results, const ScanOptions& options,
             const std::vector<uint8_t>& last = {});

    struct Hit {
        Address address = 0;
        std::vector<uint8_t> last;  // value at the last look, for changed/unchanged
    };

    Output& m_out;
    bool m_stdin_data;
    std::optional<std::vector<InputLine>> m_input;
    std::unique_ptr<Target> m_target;
    std::vector<Address> m_values;            // $1, $2, ...
    std::map<std::string, Address> m_names;   // $player, ...
    std::vector<Hit> m_hits;
    std::optional<Profile> m_profile;
    size_t m_max = 50;
    bool m_parallel = true;
    bool m_quit = false;
    std::atomic_bool m_cancel{false};
};

} // namespace patty::cli
