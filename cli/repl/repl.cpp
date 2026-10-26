// Interactive loop: line editing, history, completion and Ctrl-C.
// Commands themselves live in Session.

#include "session.h"
#include "../commands.h"

#include <isocline.h>

#include <atomic>
#include <cctype>
#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>

#ifdef _WIN32
#include <io.h>
#define PATTY_ISATTY _isatty
#define PATTY_FILENO _fileno
#else
#include <unistd.h>
#define PATTY_ISATTY isatty
#define PATTY_FILENO fileno
#endif

namespace patty::cli {

namespace {

std::atomic_bool* g_cancel = nullptr;

extern "C" void on_interrupt(int) {
    if (g_cancel)
        g_cancel->store(true);
}

std::filesystem::path history_path() {
    namespace fs = std::filesystem;
#ifdef _WIN32
    const char* base = std::getenv("APPDATA");
    fs::path dir = base ? fs::path(base) / "patty" : fs::path(".patty");
#else
    fs::path dir;
    if (const char* state = std::getenv("XDG_STATE_HOME"); state && *state)
        dir = fs::path(state) / "patty";
    else if (const char* home = std::getenv("HOME"))
        dir = fs::path(home) / ".local" / "state" / "patty";
    else
        return {};
#endif
    std::error_code ec;
    fs::create_directories(dir, ec);
    return ec ? fs::path{} : dir / "history";
}

// Completion needs the session and the whole line, isocline hands us neither
// to the per-word callback.
struct Completion {
    Session* session = nullptr;
    std::vector<std::string> words;
};
Completion g_completion;

bool is_word_char(const char* s, long length) {
    if (length != 1)
        return false;
    const char c = *s;
    return std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '_' || c == '-';
}

void complete_words(ic_completion_env_t* env, const char* word) {
    const std::string_view prefix(word);
    for (const auto& candidate : g_completion.words)
        if (std::string_view(candidate).starts_with(prefix))
            ic_add_completion(env, candidate.c_str());
}

void complete(ic_completion_env_t* env, const char* input) {
    const std::string_view line(input);
    const auto first_space = line.find(' ');
    if (first_space == std::string_view::npos) {
        g_completion.words = Session::command_names();
        ic_complete_word(env, input, &complete_words, &is_word_char);
        return;
    }
    const auto command = line.substr(0, first_space);
    if (command == "file" || command == "load" || command == "dump") {
        ic_complete_filename(env, input, 0, nullptr, nullptr);
        return;
    }
    g_completion.words = g_completion.session->module_names();
    ic_complete_word(env, input, &complete_words, &is_word_char);
}

int interactive(Session& session) {
    ic_set_history(history_path().string().c_str(), 1000);
    ic_set_prompt_marker("> ", "> ");
    ic_enable_hint(true);
    ic_enable_brace_insertion(false);
    g_completion.session = &session;
    ic_set_default_completer(&complete, nullptr);

    std::cout << "patty " << version_string << ". help lists commands, Ctrl-C stops a scan.\n";
    bool interrupted_once = false;
    while (true) {
        char* raw = ic_readline(session.prompt().c_str());
        if (!raw) {
            // isocline returns NULL for both Ctrl-C and Ctrl-D. A single one is
            // too easy to hit while trying to stop a scan that just finished.
            if (interrupted_once)
                break;
            interrupted_once = true;
            std::cout << "(press Ctrl-D again or type quit to leave)\n";
            continue;
        }
        interrupted_once = false;
        const std::string line(raw);
        ic_free(raw);
        if (!session.execute(line))
            break;
    }
    return 0;
}

// Piped input: no editing, no prompt, just run lines. Used by scripts and tests.
int batch(Session& session) {
    std::string line;
    while (std::getline(std::cin, line))
        if (!session.execute(line))
            break;
    return 0;
}

} // namespace

int run_repl(const TargetArgs& target) {
    Session session(std::cout);
    const bool tty = PATTY_ISATTY(PATTY_FILENO(stdin));
    if (tty) {
        // Ctrl-C cancels the running scan instead of killing the session.
        // Piped sessions keep the default so a stuck script can still be killed.
        g_cancel = &session.cancel_flag();
        std::signal(SIGINT, on_interrupt);
    }

    if (!target.empty()) {
        try {
            session.open(target);
        } catch (const Error& e) {
            std::cout << "error: " << e.what() << '\n';
        }
    }
    return tty ? interactive(session) : batch(session);
}

} // namespace patty::cli
