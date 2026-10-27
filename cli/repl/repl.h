#pragma once

#include "../common.h"
#include "../output.h"

#include <string>

namespace patty::cli {

bool stdin_is_terminal();
bool stdout_is_terminal();

// The shell: interactive on a terminal, a script when stdin is piped.
// Returns 0, or 1 if any command of a script failed.
int run_shell(const TargetArgs& target, Mode mode);

// One command, as in `patty <target> <command>`. "-" arguments read stdin.
// Returns the command's exit status.
int run_once(const TargetArgs& target, const std::string& command, Mode mode);

} // namespace patty::cli
