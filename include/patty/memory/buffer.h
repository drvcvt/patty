#pragma once

#include "provider.h"
#include <span>
#include <algorithm>

namespace patty {

class BufferProvider : public IMemoryProvider {
public:
    BufferProvider(std::span<const uint8_t> data, uintptr_t base = 0)
        : m_data(data.begin(), data.end()), m_base(base) {}

    BufferProvider(std::vector<uint8_t>&& data, uintptr_t base = 0)
        : m_data(std::move(data)), m_base(base) {}

    bool read(uintptr_t address, void* buffer, size_t size) override {
        if (address < m_base) return false;
        size_t offset = address - m_base;
        if (offset + size > m_data.size()) return false;
        std::memcpy(buffer, m_data.data() + offset, size);
        return true;
    }

    std::vector<MemoryRegion> regions() override {
        MemoryRegion r;
        r.base = m_base;
        r.size = m_data.size();
        r.protection = 0x20; // PAGE_EXECUTE_READ
        r.type = 0;
        r.name = "buffer";
        return {r};
    }

    uintptr_t baseAddress() const override { return m_base; }

    size_t size() const { return m_data.size(); }
    const uint8_t* data() const { return m_data.data(); }

private:
    std::vector<uint8_t> m_data;
    uintptr_t m_base;
};

} // namespace patty
