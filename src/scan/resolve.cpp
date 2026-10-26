#include "patty/scan/resolve.h"

namespace patty {

std::optional<uintptr_t> rip_relative(Target& target, uintptr_t operand, int64_t operand_size) {
    const auto disp = target.read<int32_t>(operand);
    if (!disp)
        return std::nullopt;
    return operand + static_cast<uintptr_t>(operand_size) + static_cast<uintptr_t>(int64_t{*disp});
}

std::optional<uintptr_t> resolve(Target& target, uintptr_t address,
                                 std::span<const ResolveStep> steps) {
    uintptr_t current = address;
    for (const auto& step : steps) {
        switch (step.kind) {
        case ResolveStep::Kind::Add:
            current += static_cast<uintptr_t>(step.value);
            break;
        case ResolveStep::Kind::Rip: {
            const auto next = rip_relative(target, current);
            if (!next)
                return std::nullopt;
            current = *next;
            break;
        }
        case ResolveStep::Kind::Deref: {
            const auto next = target.read_pointer(current);
            if (!next || *next == 0)
                return std::nullopt;
            current = *next;
            break;
        }
        }
    }
    return current;
}

std::optional<uintptr_t> pointer_chain(Target& target, uintptr_t base,
                                       std::span<const int64_t> offsets) {
    uintptr_t current = base;
    for (size_t i = 0; i < offsets.size(); ++i) {
        current += static_cast<uintptr_t>(offsets[i]);
        if (i + 1 == offsets.size())
            break;
        const auto next = target.read_pointer(current);
        if (!next || *next == 0)
            return std::nullopt;
        current = *next;
    }
    return current;
}

} // namespace patty
