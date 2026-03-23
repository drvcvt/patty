#pragma once

#include "provider.h"
#include <string>
#include <optional>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <tlhelp32.h>
#endif

namespace patty {

#ifdef _WIN32

class ProcessProvider : public IMemoryProvider {
public:
    ~ProcessProvider() override;

    static std::optional<ProcessProvider> open(uint32_t pid);
    static std::optional<ProcessProvider> openByName(const std::string& name);
    static ProcessProvider fromHandle(HANDLE handle, bool owning = false);
    static std::vector<uint32_t> findPIDs(const std::string& name);

    bool read(uintptr_t address, void* buffer, size_t size) override;
    std::vector<MemoryRegion> regions() override;
    bool is64Bit() const override { return m_is64bit; }

    uint32_t pid() const { return m_pid; }
    HANDLE handle() const { return m_handle; }

    ProcessProvider(ProcessProvider&& other) noexcept;
    ProcessProvider& operator=(ProcessProvider&& other) noexcept;
    ProcessProvider(const ProcessProvider&) = delete;
    ProcessProvider& operator=(const ProcessProvider&) = delete;

private:
    ProcessProvider() = default;

    HANDLE m_handle = nullptr;
    uint32_t m_pid = 0;
    bool m_is64bit = true;
    bool m_owning = true;

    // Cached regions (invalidated on re-query)
    mutable std::vector<MemoryRegion> m_cached_regions;
    mutable bool m_regions_valid = false;

    static std::string getModuleName(HANDLE process, uintptr_t address);
};

#endif // _WIN32

} // namespace patty
