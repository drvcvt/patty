#pragma once

#include "../region/region.h"
#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>
#include <string>
#include <optional>
#include <type_traits>

namespace patty {

class IMemoryProvider {
public:
    virtual ~IMemoryProvider() = default;

    virtual bool read(uintptr_t address, void* buffer, size_t size) = 0;
    virtual std::vector<MemoryRegion> regions() = 0;
    virtual uintptr_t baseAddress() const { return 0; }
    virtual bool is64Bit() const { return true; }

    template<typename T>
    std::optional<T> read(uintptr_t address) {
        static_assert(std::is_trivially_copyable_v<T>);
        T value{};
        if (read(address, &value, sizeof(T)))
            return value;
        return std::nullopt;
    }

    std::vector<uint8_t> readBytes(uintptr_t address, size_t size) {
        std::vector<uint8_t> buf(size);
        if (read(address, buf.data(), size))
            return buf;
        return {};
    }

    std::string readString(uintptr_t address, size_t maxLen = 256) {
        std::vector<char> buf(maxLen, 0);
        if (!read(address, buf.data(), maxLen))
            return {};
        buf.back() = '\0';
        return std::string(buf.data());
    }
};

} // namespace patty
