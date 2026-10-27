#include "patty/memory/process.h"
#include "patty/error.h"

#include "../util.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>

#include <algorithm>

namespace patty {

namespace {

HANDLE handle_of(const std::unique_ptr<void, void (*)(void*)>& handle) {
    return static_cast<HANDLE>(handle.get());
}

void close_handle(void* handle) {
    CloseHandle(static_cast<HANDLE>(handle));
}

std::string system_error(DWORD code) {
    char* text = nullptr;
    const DWORD length = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, code, 0, reinterpret_cast<LPSTR>(&text), 0, nullptr);
    std::string message = length ? std::string(text, length) : "error " + std::to_string(code);
    LocalFree(text);
    while (!message.empty() && (message.back() == '\n' || message.back() == '\r' || message.back() == '.'))
        message.pop_back();
    return message;
}

std::string mapped_name(HANDLE process, uintptr_t address) {
    char path[MAX_PATH] = {};
    const DWORD length = GetMappedFileNameA(process, reinterpret_cast<LPVOID>(address), path, MAX_PATH);
    if (length == 0)
        return {};
    const std::string full(path, length);
    const auto slash = full.find_last_of('\\');
    return slash == std::string::npos ? full : full.substr(slash + 1);
}

} // namespace

Process Process::open(uint32_t pid) {
    HANDLE handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!handle)
        throw Error("cannot open pid " + std::to_string(pid) + ": " + system_error(GetLastError()));

    Process process;
    process.m_pid = pid;
    process.m_handle = {handle, &close_handle};

    BOOL wow64 = FALSE;
    if (IsWow64Process(handle, &wow64) && wow64)
        process.m_pointer_size = 4;

    char name[MAX_PATH] = {};
    if (GetModuleBaseNameA(handle, nullptr, name, MAX_PATH))
        process.m_name = name;
    return process;
}

Process Process::open(std::string_view name) {
    const auto pids = find(name);
    if (pids.empty())
        throw Error("no process named " + std::string(name));
    return open(pids.front());
}

Process Process::current() {
    return open(static_cast<uint32_t>(GetCurrentProcessId()));
}

std::vector<uint32_t> Process::find(std::string_view name) {
    std::vector<uint32_t> result;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return result;

    const auto wanted = detail::lower(name);
    PROCESSENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    if (Process32First(snapshot, &entry)) {
        do {
            if (detail::lower(entry.szExeFile) == wanted)
                result.push_back(entry.th32ProcessID);
        } while (Process32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);
    std::sort(result.begin(), result.end());
    return result;
}

std::vector<ProcessInfo> Process::list() {
    std::vector<ProcessInfo> result;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return result;
    PROCESSENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    if (Process32First(snapshot, &entry)) {
        do {
            result.push_back({entry.th32ProcessID, entry.szExeFile});
        } while (Process32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);
    std::sort(result.begin(), result.end(), [](const ProcessInfo& a, const ProcessInfo& b) { return a.pid < b.pid; });
    return result;
}

bool Process::read(uintptr_t address, void* buffer, size_t size) {
    SIZE_T done = 0;
    return size == 0 ||
           (ReadProcessMemory(handle_of(m_handle), reinterpret_cast<LPCVOID>(address), buffer, size, &done) &&
            done == size);
}

std::vector<Region> Process::regions() {
    std::vector<Region> regions;
    const HANDLE handle = handle_of(m_handle);
    const uintptr_t limit = m_pointer_size == 4 ? 0x7FFFFFFF : 0x7FFFFFFFFFFF;

    MEMORY_BASIC_INFORMATION info{};
    uintptr_t address = 0;
    while (address < limit &&
           VirtualQueryEx(handle, reinterpret_cast<LPCVOID>(address), &info, sizeof(info)) != 0) {
        const DWORD protect = info.Protect;
        const bool usable = info.State == MEM_COMMIT && protect != 0 &&
                            !(protect & PAGE_GUARD) && !(protect & PAGE_NOACCESS);
        if (usable) {
            const auto base = reinterpret_cast<uintptr_t>(info.BaseAddress);
            const bool exec = protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                                         PAGE_EXECUTE_WRITECOPY);
            const bool write = protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE |
                                          PAGE_EXECUTE_WRITECOPY);
            const bool read = !(protect & PAGE_EXECUTE);  // execute-only pages cannot be read
            regions.push_back({base, info.RegionSize, read, write, exec,
                               info.Type == MEM_IMAGE || info.Type == MEM_MAPPED ? mapped_name(handle, base) : ""});
        }
        const uintptr_t next = reinterpret_cast<uintptr_t>(info.BaseAddress) + info.RegionSize;
        if (next <= address)
            break;
        address = next;
    }
    return regions;
}

std::string Process::describe() const {
    return "pid " + std::to_string(m_pid) + " (" + m_name + ")";
}

} // namespace patty
