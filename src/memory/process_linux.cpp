#include "patty/memory/process.h"
#include "patty/error.h"

#include "../util.h"

#include <sys/uio.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>

// Memory is only ever read with process_vm_readv. /proc is used for the text
// files maps (regions), comm and cmdline (names); never /proc/<pid>/mem.

namespace patty {

namespace {

std::string proc_path(uint32_t pid, const char* leaf) {
    return "/proc/" + std::to_string(pid) + "/" + leaf;
}

// Handles '/' and '\' so Wine's argv[0] ("C:\Games\Game.exe") works too.
std::string base_name(std::string_view path) {
    const auto pos = path.find_last_of("/\\");
    return std::string(pos == std::string_view::npos ? path : path.substr(pos + 1));
}

std::string first_line(const std::string& path, char delimiter = '\n') {
    std::ifstream in(path, std::ios::binary);
    std::string line;
    std::getline(in, line, delimiter);
    return line;
}

bool readv(uint32_t pid, uintptr_t address, void* buffer, size_t size) {
    iovec local{buffer, size};
    iovec remote{reinterpret_cast<void*>(address), size};
    return process_vm_readv(static_cast<pid_t>(pid), &local, 1, &remote, 1, 0) ==
           static_cast<ssize_t>(size);
}

struct Mapping {
    Region region;
    uint64_t file_offset = 0;
    std::string path;
};

std::vector<Mapping> read_maps(uint32_t pid) {
    std::vector<Mapping> mappings;
    // Line format: start-end perms offset dev inode [path]
    std::ifstream maps(proc_path(pid, "maps"));
    std::string line;
    while (std::getline(maps, line)) {
        std::istringstream fields(line);
        std::string range, perms, offset, device, inode, path;
        if (!(fields >> range >> perms >> offset >> device >> inode))
            continue;
        std::getline(fields, path);
        path.erase(0, path.find_first_not_of(' '));

        const auto dash = range.find('-');
        if (dash == std::string::npos || perms.size() < 3 || perms[0] != 'r')
            continue;
        // Readable on paper, but process_vm_readv refuses these.
        if (path == "[vvar]" || path == "[vvar_vclock]" || path == "[vsyscall]")
            continue;

        const uintptr_t start = std::stoull(range.substr(0, dash), nullptr, 16);
        const uintptr_t end = std::stoull(range.substr(dash + 1), nullptr, 16);
        if (end <= start)
            continue;

        Mapping m;
        m.region = {start, end - start, true, perms[1] == 'w', perms[2] == 'x',
                    path.empty() || path[0] == '[' ? path : base_name(path)};
        m.file_offset = std::stoull(offset, nullptr, 16);
        m.path = std::move(path);
        mappings.push_back(std::move(m));
    }
    return mappings;
}

} // namespace

Process Process::open(uint32_t pid) {
    if (pid == 0)
        throw Error("invalid pid 0");

    if (!std::ifstream(proc_path(pid, "maps"))) {
        if (errno == EACCES)
            throw Error("cannot read /proc/" + std::to_string(pid) +
                        "/maps: permission denied (process of another user?)");
        throw Error("no such process: " + std::to_string(pid));
    }

    Process process;
    process.m_pid = pid;
    process.m_name = first_line(proc_path(pid, "comm"));

    const auto mappings = read_maps(pid);

    // Probe a real read: maps stays readable under yama ptrace_scope, reads do not.
    bool readable = false;
    for (const auto& m : mappings) {
        uint8_t byte = 0;
        if (readv(pid, m.region.base, &byte, 1)) {
            readable = true;
            break;
        }
        if (errno == EPERM)
            throw Error("not allowed to read pid " + std::to_string(pid) +
                        " (kernel.yama.ptrace_scope=" +
                        first_line("/proc/sys/kernel/yama/ptrace_scope") +
                        "). patty only uses process_vm_readv, but the kernel gates it like ptrace. "
                        "Run scripts/setup.sh once, or: sudo setcap cap_sys_ptrace=ep $(command -v patty)");
        if (errno == ESRCH)
            throw Error("process " + std::to_string(pid) + " exited");
    }
    if (!readable)
        throw Error("no readable memory in pid " + std::to_string(pid));

    // Bitness from the ELF header of the main executable, read from memory:
    // the first file mapping at offset 0 is the executable (or Wine's preloader).
    for (const auto& m : mappings) {
        if (m.path.empty() || m.path[0] == '[' || m.file_offset != 0)
            continue;
        unsigned char ident[5] = {};
        if (readv(pid, m.region.base, ident, sizeof(ident)) && std::memcmp(ident, "\x7F" "ELF", 4) == 0)
            process.m_pointer_size = ident[4] == 1 ? 4 : 8;
        break;
    }
    return process;
}

Process Process::open(std::string_view name) {
    const auto pids = find(name);
    if (pids.empty())
        throw Error("no process named " + std::string(name));
    return open(pids.front());
}

Process Process::current() {
    return open(static_cast<uint32_t>(getpid()));
}

std::vector<uint32_t> Process::find(std::string_view name) {
    std::vector<uint32_t> result;
    const auto wanted = detail::lower(name);

    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator("/proc", ec)) {
        const auto dir = entry.path().filename().string();
        if (dir.empty() || !std::all_of(dir.begin(), dir.end(), [](unsigned char c) { return std::isdigit(c); }))
            continue;
        const auto pid = static_cast<uint32_t>(std::stoul(dir));

        std::error_code link_error;
        const auto exe = std::filesystem::read_symlink(proc_path(pid, "exe"), link_error);
        if (detail::lower(first_line(proc_path(pid, "comm"))) == wanted ||
            (!link_error && detail::lower(exe.filename().string()) == wanted) ||
            detail::lower(base_name(first_line(proc_path(pid, "cmdline"), '\0'))) == wanted)
            result.push_back(pid);
    }
    std::sort(result.begin(), result.end());
    return result;
}

bool Process::read(uintptr_t address, void* buffer, size_t size) {
    return size == 0 || readv(m_pid, address, buffer, size);
}

std::vector<Region> Process::regions() {
    std::vector<Region> regions;
    for (auto& m : read_maps(m_pid))
        regions.push_back(std::move(m.region));
    return regions;
}

std::string Process::describe() const {
    return "pid " + std::to_string(m_pid) + " (" + m_name + ")";
}

} // namespace patty
