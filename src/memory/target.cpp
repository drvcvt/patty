#include "patty/memory/target.h"

#include "../util.h"

#include <algorithm>
#include <map>

namespace patty {

std::vector<Module> Target::modules() {
    auto regions = this->regions();
    std::sort(regions.begin(), regions.end(),
              [](const Region& a, const Region& b) { return a.base < b.base; });

    // A module is one contiguous run of regions with the same name, plus
    // anonymous memory directly after it (.bss). Unreadable gaps inside the
    // run are fine. A file mapped again somewhere else (Linux maps e.g.
    // libffi trampolines far away) is a separate run; the largest run wins.
    std::map<std::string, Module> best;  // keyed by lowercase name
    std::optional<Module> run;
    std::string run_key;
    auto close_run = [&] {
        if (run) {
            auto [it, inserted] = best.try_emplace(run_key, *run);
            if (!inserted && run->size > it->second.size)
                it->second = *run;
        }
        run.reset();
    };

    for (const auto& region : regions) {
        const bool named = !region.name.empty() && region.name.front() != '[';
        if (run && named && detail::lower(region.name) == run_key) {
            run->size = std::max(run->end(), region.end()) - run->base;
            continue;
        }
        if (run && region.name.empty() && region.base == run->end()) {
            run->size += region.size;
            continue;
        }
        close_run();
        if (named) {
            run = Module{region.name, region.base, region.size};
            run_key = detail::lower(region.name);
        }
    }
    close_run();

    std::vector<Module> result;
    result.reserve(best.size());
    for (auto& [key, module] : best)
        result.push_back(std::move(module));
    std::sort(result.begin(), result.end(),
              [](const Module& a, const Module& b) { return a.base < b.base; });
    return result;
}

std::optional<uintptr_t> Target::read_pointer(uintptr_t address) {
    if (pointer_size() == 4) {
        auto value = read<uint32_t>(address);
        return value ? std::optional<uintptr_t>(*value) : std::nullopt;
    }
    auto value = read<uint64_t>(address);
    return value ? std::optional<uintptr_t>(static_cast<uintptr_t>(*value)) : std::nullopt;
}

std::vector<uint8_t> Target::read_bytes(uintptr_t address, size_t size) {
    std::vector<uint8_t> bytes(size);
    if (size > 0 && !read(address, bytes.data(), size))
        return {};
    return bytes;
}

std::optional<std::string> Target::read_string(uintptr_t address, size_t max_length) {
    // Read in small pieces so a string close to the end of a region still
    // comes back; fall back to single bytes once a piece fails.
    constexpr size_t piece = 64;
    std::string result;
    char buffer[piece];

    while (result.size() < max_length) {
        const size_t want = std::min(piece, max_length - result.size());
        const uintptr_t at = address + result.size();
        size_t got = want;
        if (!read(at, buffer, want)) {
            got = 0;
            while (got < want && read(at + got, buffer + got, 1))
                ++got;
        }
        for (size_t i = 0; i < got; ++i) {
            if (buffer[i] == '\0')
                return result;
            result.push_back(buffer[i]);
        }
        if (got < want)
            break;
    }

    if (result.empty()) {
        char first = 0;
        if (!read(address, &first, 1))
            return std::nullopt;
    }
    return result;
}

std::optional<Region> Target::region_at(uintptr_t address) {
    for (auto& region : regions())
        if (region.contains(address))
            return std::move(region);
    return std::nullopt;
}

std::optional<Module> Target::module(std::string_view name) {
    const auto wanted = detail::lower(name);
    for (auto& module : modules())
        if (detail::lower(module.name) == wanted)
            return std::move(module);
    return std::nullopt;
}

std::optional<Module> Target::module_at(uintptr_t address) {
    for (auto& module : modules())
        if (module.contains(address))
            return std::move(module);
    return std::nullopt;
}

} // namespace patty
