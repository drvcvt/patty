#include <gtest/gtest.h>
#include <patty/core/scanner.h>
#include <patty/memory/buffer.h>

using namespace patty;

class ScannerTest : public ::testing::Test {
protected:
    // Build a buffer with known patterns embedded
    std::vector<uint8_t> makeTestBuffer() {
        std::vector<uint8_t> buf(4096, 0xCC); // Fill with INT3

        // Place pattern at offset 0x100
        // MOV rax, [rip+disp32]: 48 8B 05 XX XX XX XX
        buf[0x100] = 0x48;
        buf[0x101] = 0x8B;
        buf[0x102] = 0x05;
        buf[0x103] = 0x10; // disp32 = 0x00000010
        buf[0x104] = 0x00;
        buf[0x105] = 0x00;
        buf[0x106] = 0x00;

        // Place same pattern at offset 0x200
        buf[0x200] = 0x48;
        buf[0x201] = 0x8B;
        buf[0x202] = 0x05;
        buf[0x203] = 0x20; // disp32 = 0x00000020
        buf[0x204] = 0x00;
        buf[0x205] = 0x00;
        buf[0x206] = 0x00;

        // Place a unique pattern at offset 0x300
        buf[0x300] = 0xDE;
        buf[0x301] = 0xAD;
        buf[0x302] = 0xBE;
        buf[0x303] = 0xEF;

        return buf;
    }
};

TEST_F(ScannerTest, BasicScan) {
    auto buf = makeTestBuffer();
    auto provider = std::make_shared<BufferProvider>(std::move(buf), 0x10000);
    Scanner scanner(provider);

    auto pattern = Pattern::fromAOB("48 8B 05 ?? ?? ?? ??", "test");
    auto result = scanner.scan(pattern);

    EXPECT_EQ(result.pattern_name, "test");
    ASSERT_EQ(result.matches.size(), 2);
    EXPECT_EQ(result.matches[0].address, 0x10100);
    EXPECT_EQ(result.matches[1].address, 0x10200);
}

TEST_F(ScannerTest, MaxResults) {
    auto buf = makeTestBuffer();
    auto provider = std::make_shared<BufferProvider>(std::move(buf), 0x10000);
    Scanner scanner(provider);

    auto pattern = Pattern::fromAOB("48 8B 05 ?? ?? ?? ??");
    ScanConfig config;
    config.max_results = 1;
    auto result = scanner.scan(pattern, config);

    ASSERT_EQ(result.matches.size(), 1);
    EXPECT_EQ(result.matches[0].address, 0x10100);
}

TEST_F(ScannerTest, UniquePattern) {
    auto buf = makeTestBuffer();
    auto provider = std::make_shared<BufferProvider>(std::move(buf), 0x10000);
    Scanner scanner(provider);

    auto pattern = Pattern::fromAOB("DE AD BE EF", "deadbeef");
    auto result = scanner.scan(pattern);

    ASSERT_EQ(result.matches.size(), 1);
    EXPECT_EQ(result.matches[0].address, 0x10300);
}

TEST_F(ScannerTest, NoMatch) {
    auto buf = makeTestBuffer();
    auto provider = std::make_shared<BufferProvider>(std::move(buf), 0x10000);
    Scanner scanner(provider);

    auto pattern = Pattern::fromAOB("FF FE FD FC FB FA");
    auto result = scanner.scan(pattern);

    EXPECT_TRUE(result.matches.empty());
}

TEST_F(ScannerTest, RIPRelativeResolve) {
    auto buf = makeTestBuffer();
    auto provider = std::make_shared<BufferProvider>(std::move(buf), 0x10000);
    Scanner scanner(provider);

    auto pattern = Pattern::fromAOB("48 8B 05 ?? ?? ?? ??", "rip_test")
        .withOffset(3)
        .withResolve(ResolveType::RIPRelative);

    auto result = scanner.scan(pattern);

    ASSERT_EQ(result.matches.size(), 2);
    // First match at 0x10100, result_offset=3 -> resolve at 0x10103
    // disp32 at 0x10103 = 0x10, resolved = 0x10103 + 4 + 0x10 = 0x10117
    EXPECT_EQ(result.matches[0].resolved, 0x10117);
}

TEST_F(ScannerTest, MultiPatternScan) {
    auto buf = makeTestBuffer();
    auto provider = std::make_shared<BufferProvider>(std::move(buf), 0x10000);
    Scanner scanner(provider);

    std::vector<Pattern> patterns = {
        Pattern::fromAOB("48 8B 05 ?? ?? ?? ??", "pattern1"),
        Pattern::fromAOB("DE AD BE EF", "pattern2"),
    };

    auto result = scanner.scan(std::span<const Pattern>(patterns));

    ASSERT_EQ(result.results.size(), 2);
    EXPECT_EQ(result.results[0].matches.size(), 2); // pattern1 matches twice
    EXPECT_EQ(result.results[1].matches.size(), 1); // pattern2 matches once
}

TEST_F(ScannerTest, ScanStatistics) {
    auto buf = makeTestBuffer();
    auto provider = std::make_shared<BufferProvider>(std::move(buf), 0x10000);
    Scanner scanner(provider);

    auto pattern = Pattern::fromAOB("DE AD BE EF");
    auto result = scanner.scan(pattern);

    EXPECT_GT(result.elapsed_ms, 0.0);
    EXPECT_EQ(result.bytes_scanned, 4096);
    EXPECT_EQ(result.regions_scanned, 1);
}

TEST_F(ScannerTest, EmptyBuffer) {
    auto provider = std::make_shared<BufferProvider>(std::vector<uint8_t>{});
    Scanner scanner(provider);

    auto pattern = Pattern::fromAOB("48 8B");
    auto result = scanner.scan(pattern);

    EXPECT_TRUE(result.matches.empty());
}
