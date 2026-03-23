#pragma once

#include "region.h"
#include <functional>
#include <optional>
#include <string>

namespace patty {

struct RegionFilter {
    std::optional<bool> executable;
    std::optional<bool> writable;
    std::optional<bool> readable;
    std::optional<size_t> min_size;
    std::optional<size_t> max_size;
    std::optional<uint32_t> type_mask;
    std::optional<std::string> module_name;
    std::function<bool(const MemoryRegion&)> custom;

    bool matches(const MemoryRegion& region) const {
        if (executable && region.isExecutable() != *executable)
            return false;
        if (writable && region.isWritable() != *writable)
            return false;
        if (readable && region.isReadable() != *readable)
            return false;
        if (min_size && region.size < *min_size)
            return false;
        if (max_size && region.size > *max_size)
            return false;
        if (type_mask && !(region.type & *type_mask))
            return false;
        if (module_name && region.name != *module_name)
            return false;
        if (custom && !custom(region))
            return false;
        return true;
    }

    static RegionFilter codeOnly() {
        RegionFilter f;
        f.executable = true;
        return f;
    }

    static RegionFilter dataOnly() {
        RegionFilter f;
        f.writable = true;
        f.executable = false;
        return f;
    }

    static RegionFilter forModule(const std::string& name) {
        RegionFilter f;
        f.module_name = name;
        return f;
    }

    std::vector<MemoryRegion> apply(const std::vector<MemoryRegion>& regions) const {
        std::vector<MemoryRegion> result;
        for (const auto& r : regions) {
            if (matches(r))
                result.push_back(r);
        }
        return result;
    }
};

} // namespace patty
