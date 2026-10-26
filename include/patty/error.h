#pragma once

#include <stdexcept>

namespace patty {

// Thrown when a target cannot be opened, a pattern or profile cannot be parsed,
// or a scan names a module the target does not have. Reads on an open target
// never throw; they report failure through their return value.
class Error : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

} // namespace patty
