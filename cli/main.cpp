#include "common.h"
#include "repl/repl.h"
#include "repl/session.h"

#include <cstdlib>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

using namespace patty;
using namespace patty::cli;

namespace {

constexpr const char* kUsage = R"(patty, a read-only memory scanner

  patty                        the shell, nothing open yet
  patty <target>               the shell with a process name, pid or file open
  patty <target> <command>     run one shell command and exit
  patty ps [text]              list processes

Options, anywhere on the line:
  --json      one JSON object per result line
  --table     the human format even in a pipe
  --lines     tab-separated lines even on a terminal
  --raw       load a file flat instead of mapping its PE/ELF sections
  --version   --help

PATTY_TARGET=<target> lets you leave the target out. In a pipe the output is
tab-separated with the address first, and "-" as an argument reads addresses
from stdin, so patty can feed patty:

  patty game findval 100 | patty game read i32 -

`patty help` lists the shell commands.
)";

// Arguments become one shell line again; ones with spaces get their quotes back.
std::string join(const std::vector<std::string>& words, size_t first) {
    std::string line;
    for (size_t i = first; i < words.size(); ++i) {
        if (!line.empty())
            line += ' ';
        const bool spaced = words[i].find_first_of(" \t") != std::string::npos;
        line += spaced ? '"' + words[i] + '"' : words[i];
    }
    return line;
}

} // namespace

int main(int argc, char** argv) {
    std::optional<Mode> mode;
    bool raw = false;
    std::vector<std::string> words;
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg = argv[i];
        if (arg == "--json") {
            mode = Mode::Json;
        } else if (arg == "--table") {
            mode = Mode::Table;
        } else if (arg == "--lines") {
            mode = Mode::Lines;
        } else if (arg == "--raw") {
            raw = true;
        } else if (arg == "--version") {
            std::cout << "patty " << version_string << '\n';
            return 0;
        } else if (arg == "--help" || (arg == "-h" && words.empty())) {
            std::cout << kUsage;
            return 0;
        } else if (arg.starts_with("--")) {
            std::cerr << "patty: unknown option " << arg << " (see patty --help)\n";
            return 1;
        } else {
            words.emplace_back(arg);
        }
    }

    const Mode output = mode.value_or(stdout_is_terminal() ? Mode::Table : Mode::Lines);
    TargetArgs target;
    size_t first = 0;
    if (!words.empty() && !Session::is_command(words[0])) {
        target = guess_target(words[0], raw);
        first = 1;
    } else if (const char* fallback = std::getenv("PATTY_TARGET"); fallback && *fallback) {
        target = guess_target(fallback, raw);
    }

    try {
        if (first >= words.size())
            return run_shell(target, output);
        return run_once(target, join(words, first), output);
    } catch (const Error& e) {
        std::cerr << "patty: " << e.what() << '\n';
        return 1;
    }
}
