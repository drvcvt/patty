#pragma once

#include <patty/patty.h>

#include <cstdint>
#include <span>
#include <string_view>

namespace patty::cli {

// Address expressions, gdb flavoured:
//
//   0x7ff6a0010000   1234         numbers (decimal unless 0x)
//   Game.exe         'ld-linux.so.2'   module base, quotes for names with '-'
//   $   $3                        last value / value number 3
//   [expr]                        read a pointer at expr
//   + - * /  ( )  unary -
//
// Throws patty::Error with the column of the problem.
struct ExprContext {
    Target* target = nullptr;              // needed for module names and [deref]
    std::span<const uintptr_t> values;     // $1 is values[0]
};

uint64_t evaluate(std::string_view text, const ExprContext& context);

} // namespace patty::cli
