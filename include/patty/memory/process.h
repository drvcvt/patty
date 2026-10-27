#pragma once

#include "target.h"

#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace patty {

struct ProcessInfo {
    uint32_t pid = 0;
    std::string name;  // Wine/Proton processes show their Windows exe name
};

// A running process, opened read-only. Supported on Linux and Windows.
//
// Linux reads memory with process_vm_readv and nothing else: no ptrace, no
// attach, no /proc/<pid>/mem. The process is never stopped. The kernel still
// requires ptrace-level *permission* for process_vm_readv, so with
// kernel.yama.ptrace_scope >= 1 the binary needs CAP_SYS_PTRACE (or root) to
// read processes it did not start itself.
//
// Windows uses OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION) and
// ReadProcessMemory.
class Process final : public Target {
public:
    // Opens a process for reading. Throws patty::Error with the reason
    // (no such process, missing permission, ...). Linux probes one real read
    // so a permission problem fails here instead of producing empty scans.
    static Process open(uint32_t pid);

    // Opens the lowest pid whose executable name matches (see find()).
    static Process open(std::string_view name);

    // The calling process.
    static Process current();

    // Pids whose executable name equals `name`, case-insensitively, ascending.
    // Linux matches comm, the executable path and argv[0], so Wine/Proton
    // processes are found by their Windows name ("Game.exe").
    static std::vector<uint32_t> find(std::string_view name);

    // Every process this user can see, sorted by pid.
    static std::vector<ProcessInfo> list();

    using Target::read;
    bool read(Address address, void* buffer, size_t size) override;
    std::vector<Region> regions() override;
    size_t pointer_size() const override { return m_pointer_size; }
    std::string describe() const override;

    uint32_t pid() const { return m_pid; }
    const std::string& name() const { return m_name; }

private:
    Process() = default;

    uint32_t m_pid = 0;
    size_t m_pointer_size = 8;
    std::string m_name;
    // Windows process handle, closed on destruction. Unused on Linux.
    std::unique_ptr<void, void (*)(void*)> m_handle{nullptr, nullptr};
};

} // namespace patty
