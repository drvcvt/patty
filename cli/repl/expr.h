#pragma once

#include <patty/patty.h>

#include <cstdint>
#include <map>
#include <string>
#include <span>
#include <string_view>

namespace patty::cli {

// Address expressions, gdb flavoured:
//
//   0x7ff6a0010000   1234         numbers (decimal unless 0x)
//   Game.exe         'ld-linux.so.2'   module base, quotes for names with '-'
//   $   $3   $player              last value / value number 3 / a named value
//   [expr]                        read a pointer at expr
//   + - * /  ( )  unary -
//
// Throws patty::Error with the column of the problem.
struct ExprContext {
    Target* target = nullptr;                               // for module names and [deref]
    std::span<const Address> values;                        // $1 is values[0]
    const std::map<std::string, Address>* names = nullptr;  // $player
};

uint64_t evaluate(std::string_view text, const ExprContext& context);

} // namespace patty::cli
