#include "patty/memory/process.h"

#ifdef _WIN32

#include <psapi.h>
#include <algorithm>
#include <cctype>

namespace patty {

ProcessProvider::~ProcessProvider() {
    if (m_handle && m_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(m_handle);
        m_handle = nullptr;
    }
}

ProcessProvider::ProcessProvider(ProcessProvider&& other) noexcept
    : m_handle(other.m_handle)
    , m_pid(other.m_pid)
    , m_is64bit(other.m_is64bit)
    , m_cached_regions(std::move(other.m_cached_regions))
    , m_regions_valid(other.m_regions_valid) {
    other.m_handle = nullptr;
    other.m_pid = 0;
    other.m_regions_valid = false;
}

ProcessProvider& ProcessProvider::operator=(ProcessProvider&& other) noexcept {
    if (this != &other) {
        if (m_handle && m_handle != INVALID_HANDLE_VALUE)
            CloseHandle(m_handle);
        m_handle = other.m_handle;
        m_pid = other.m_pid;
        m_is64bit = other.m_is64bit;
        m_cached_regions = std::move(other.m_cached_regions);
        m_regions_valid = other.m_regions_valid;
        other.m_handle = nullptr;
        other.m_pid = 0;
        other.m_regions_valid = false;
    }
    return *this;
}

std::optional<ProcessProvider> ProcessProvider::open(uint32_t pid) {
    HANDLE handle = OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        FALSE,
        pid
    );

    if (!handle || handle == INVALID_HANDLE_VALUE)
        return std::nullopt;

    ProcessProvider provider;
    provider.m_handle = handle;
    provider.m_pid = pid;

    BOOL isWow64 = FALSE;
    if (IsWow64Process(handle, &isWow64)) {
        provider.m_is64bit = !isWow64;
    }

    return provider;
}

std::optional<ProcessProvider> ProcessProvider::openByName(const std::string& name) {
    auto pids = findPIDs(name);
    if (pids.empty()) return std::nullopt;
    return open(pids[0]);
}

std::vector<uint32_t> ProcessProvider::findPIDs(const std::string& name) {
    std::vector<uint32_t> result;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return result;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);

    auto toLower = [](std::string s) {
        std::transform(s.begin(), s.end(), s.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        return s;
    };

    std::string lower_name = toLower(name);

    if (Process32First(snap, &pe)) {
        do {
            if (toLower(pe.szExeFile) == lower_name) {
                result.push_back(pe.th32ProcessID);
            }
        } while (Process32Next(snap, &pe));
    }

    CloseHandle(snap);
    return result;
}

bool ProcessProvider::read(uintptr_t address, void* buffer, size_t size) {
    SIZE_T bytesRead = 0;
    BOOL success = ReadProcessMemory(
        m_handle,
        reinterpret_cast<LPCVOID>(address),
        buffer,
        size,
        &bytesRead
    );
    return success && bytesRead == size;
}

std::vector<MemoryRegion> ProcessProvider::regions() {
    if (m_regions_valid)
        return m_cached_regions;

    m_cached_regions.clear();

    MEMORY_BASIC_INFORMATION mbi{};
    uintptr_t addr = 0;
    uintptr_t max_addr = m_is64bit ? 0x7FFFFFFFFFFF : 0x7FFFFFFF;

    while (addr < max_addr) {
        if (VirtualQueryEx(m_handle, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == 0)
            break;

        if (mbi.State == MEM_COMMIT && mbi.RegionSize >= 0x1000) {
            if (!(mbi.Protect & PAGE_GUARD) && !(mbi.Protect & PAGE_NOACCESS) && mbi.Protect != 0) {
                MemoryRegion region;
                region.base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
                region.size = mbi.RegionSize;
                region.protection = mbi.Protect;
                region.type = mbi.Type;
                region.name = getModuleName(m_handle, region.base);
                m_cached_regions.push_back(std::move(region));
            }
        }

        uintptr_t next = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (next <= addr) break;
        addr = next;
    }

    m_regions_valid = true;
    return m_cached_regions;
}

std::string ProcessProvider::getModuleName(HANDLE process, uintptr_t address) {
    char name[MAX_PATH] = {};
    DWORD len = GetMappedFileNameA(process, reinterpret_cast<LPVOID>(address),
                                    name, MAX_PATH);
    if (len == 0) return {};

    std::string path(name, len);
    auto pos = path.rfind('\\');
    if (pos != std::string::npos)
        return path.substr(pos + 1);
    return path;
}

} // namespace patty

#endif // _WIN32
