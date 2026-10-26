#include <gtest/gtest.h>
#include <patty/patty.h>

#include <algorithm>
#include <csignal>
#include <fstream>
#include <sys/wait.h>
#include <unistd.h>

using namespace patty;

namespace {

// Built at runtime so the bytes never sit in .rodata of both processes.
std::vector<uint8_t> make_marker(uint64_t salt) {
    std::vector<uint8_t> marker = {'P', 'T', 'Y', 'M', 'A', 'R', 'K', '!'};
    for (int i = 0; i < 8; ++i)
        marker.push_back(static_cast<uint8_t>((salt ^ 0x5A5AA5A5C3C3F00Full) >> (i * 8)));
    return marker;
}

bool has_match_at(const ScanResult& result, uintptr_t address) {
    return std::any_of(result.begin(), result.end(), [&](const Match& m) { return m.address == address; });
}

bool has_cap_sys_ptrace() {
    std::ifstream status("/proc/self/status");
    std::string line;
    while (std::getline(status, line))
        if (line.rfind("CapEff:", 0) == 0)
            return (std::stoull(line.substr(7), nullptr, 16) >> 19) & 1;
    return false;
}

} // namespace

TEST(LinuxProcess, ScansItself) {
    auto self = Process::current();
    EXPECT_EQ(self.pid(), static_cast<uint32_t>(getpid()));
    EXPECT_EQ(self.pointer_size(), sizeof(void*));
    EXPECT_EQ(self.name(), "patty_tests");

    const auto module = self.module("patty_tests");
    ASSERT_TRUE(module);
    EXPECT_EQ(self.read<uint32_t>(module->base), 0x464C457Fu);  // "\x7FELF"

    const auto marker = make_marker(static_cast<uint64_t>(getpid()));
    const auto result = Scanner(self).find(Pattern::raw(marker), {.data_only = true});
    EXPECT_TRUE(has_match_at(result, reinterpret_cast<uintptr_t>(marker.data())));
}

TEST(LinuxProcess, ReadsAForkedChild) {
    int fds[2];
    ASSERT_EQ(pipe(fds), 0);
    const pid_t child = fork();
    ASSERT_GE(child, 0);
    if (child == 0) {
        close(fds[0]);
        const auto marker = make_marker(static_cast<uint64_t>(getpid()));
        const auto address = reinterpret_cast<uintptr_t>(marker.data());
        if (write(fds[1], &address, sizeof(address)) != sizeof(address))
            _exit(1);
        for (;;)
            pause();
    }

    close(fds[1]);
    uintptr_t address = 0;
    const bool got_address = read(fds[0], &address, sizeof(address)) == sizeof(address);
    close(fds[0]);

    const auto expected = make_marker(static_cast<uint64_t>(child));
    std::vector<uint8_t> actual;
    ScanResult result;
    std::string error;
    try {
        auto process = Process::open(static_cast<uint32_t>(child));
        actual = process.read_bytes(address, expected.size());
        result = Scanner(process).find(Pattern::raw(expected));
    } catch (const Error& e) {
        error = e.what();
    }
    kill(child, SIGKILL);
    waitpid(child, nullptr, 0);

    ASSERT_TRUE(got_address);
    ASSERT_TRUE(error.empty()) << error;
    EXPECT_EQ(actual, expected);
    EXPECT_TRUE(has_match_at(result, address));
}

TEST(LinuxProcess, FailsClosedWithoutPermission) {
    std::ifstream scope_file("/proc/sys/kernel/yama/ptrace_scope");
    int scope = 0;
    if (!(scope_file >> scope) || scope == 0 || has_cap_sys_ptrace())
        GTEST_SKIP() << "reading other processes is not restricted here";

    try {
        Process::open(static_cast<uint32_t>(getppid()));
        FAIL() << "opened a non-descendant without permission";
    } catch (const Error& e) {
        EXPECT_NE(std::string(e.what()).find("ptrace_scope"), std::string::npos) << e.what();
    }
}

TEST(LinuxProcess, MissingProcessAndName) {
    EXPECT_THROW(Process::open(0x7FFFFFF0u), Error);
    EXPECT_THROW(Process::open("no-such-process-patty"), Error);
}

TEST(LinuxProcess, FindsItselfByName) {
    const auto pids = Process::find("PATTY_TESTS");
    EXPECT_NE(std::find(pids.begin(), pids.end(), static_cast<uint32_t>(getpid())), pids.end());
}
