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

TEST_F(ScannerTest, ScanForValue) {
    // Place a known 64-bit value in the buffer
    std::vector<uint8_t> buf(4096, 0);
    uint64_t target = 0xDEADBEEFCAFEBABE;
    memcpy(buf.data() + 0x200, &target, 8);
    memcpy(buf.data() + 0x800, &target, 8);

    auto provider = std::make_shared<BufferProvider>(std::move(buf), 0x10000);
    Scanner scanner(provider);

    auto result = scanner.scanForValue(target, 8);
    ASSERT_EQ(result.matches.size(), 2);
    EXPECT_EQ(result.matches[0].address, 0x10200);
    EXPECT_EQ(result.matches[1].address, 0x10800);
}

TEST_F(ScannerTest, ScanForPointer) {
    std::vector<uint8_t> buf(4096, 0);
    uintptr_t ptr = 0x00007FF612340000;
    memcpy(buf.data() + 0x100, &ptr, 8);

    auto provider = std::make_shared<BufferProvider>(std::move(buf), 0x10000);
    Scanner scanner(provider);

    auto result = scanner.scanForPointer(ptr);
    ASSERT_EQ(result.matches.size(), 1);
    EXPECT_EQ(result.matches[0].address, 0x10100);
}

TEST_F(ScannerTest, ScanForPointersBatch) {
    std::vector<uint8_t> buf(4096, 0);
    uintptr_t ptr1 = 0xAAAAAAAAAAAAAAAA;
    uintptr_t ptr2 = 0xBBBBBBBBBBBBBBBB;
    memcpy(buf.data() + 0x100, &ptr1, 8);
    memcpy(buf.data() + 0x200, &ptr2, 8);

    auto provider = std::make_shared<BufferProvider>(std::move(buf), 0x10000);
    Scanner scanner(provider);

    std::vector<uintptr_t> targets = {ptr1, ptr2, 0xCCCCCCCCCCCCCCCC};
    auto result = scanner.scanForPointers(std::span(targets));
    ASSERT_EQ(result.results.size(), 3);
    EXPECT_EQ(result.results[0].matches.size(), 1);
    EXPECT_EQ(result.results[1].matches.size(), 1);
    EXPECT_EQ(result.results[2].matches.size(), 0);
}

TEST_F(ScannerTest, ProbeObject) {
    std::vector<uint8_t> buf(0x1000, 0);
    uintptr_t base = 0x10000;

    // offset 0x00: zero
    // offset 0x08: small int (42)
    uint64_t small = 42;
    memcpy(buf.data() + 0x08, &small, 8);
    // offset 0x10: pointer to 0x10500 (valid region, points to ASCII)
    uintptr_t str_ptr = base + 0x500;
    memcpy(buf.data() + 0x10, &str_ptr, 8);
    // Place a string at 0x500
    const char* hello = "Hello World";
    memcpy(buf.data() + 0x500, hello, strlen(hello) + 1);

    auto provider = std::make_shared<BufferProvider>(std::move(buf), base);
    Scanner scanner(provider);

    auto probe = scanner.probeObject(base, 0x20);
    ASSERT_EQ(probe.fields.size(), 4); // 0x00, 0x08, 0x10, 0x18
    EXPECT_EQ(probe.fields[0].classification, "zero");
    EXPECT_EQ(probe.fields[1].classification, "small_int");
    EXPECT_EQ(probe.fields[2].classification, "string_ptr");
    EXPECT_EQ(probe.fields[2].detail, "Hello World");
}

TEST_F(ScannerTest, ScanWithFilter) {
    auto buf = makeTestBuffer();
    auto provider = std::make_shared<BufferProvider>(std::move(buf), 0x10000);
    Scanner scanner(provider);

    auto pattern = Pattern::fromAOB("48 8B 05 ?? ?? ?? ??", "filtered");

    // Without filter: 2 matches
    auto all = scanner.scan(pattern);
    ASSERT_EQ(all.matches.size(), 2);

    // With filter: only keep matches at address > 0x10150
    auto filtered = scanner.scan(pattern, ScanConfig{}, [](const Match& m) {
        return m.address > 0x10150;
    });
    ASSERT_EQ(filtered.matches.size(), 1);
    EXPECT_EQ(filtered.matches[0].address, 0x10200);
}

TEST(PatternTest_String, FromString) {
    auto p = Pattern::fromString("Hello", "str_test");
    ASSERT_EQ(p.bytes.size(), 5);
    EXPECT_EQ(p.bytes[0].value, 'H');
    EXPECT_EQ(p.bytes[4].value, 'o');
    EXPECT_FALSE(p.bytes[0].wildcard);
}

TEST(PatternTest_String, FromSSOStringInline) {
    auto p = Pattern::fromSSOString("Hello", "sso_test");
    // SSO layout: 16 bytes buffer + 8 bytes size + 8 bytes capacity = 32
    ASSERT_EQ(p.bytes.size(), 32);
    // First byte: 'H'
    EXPECT_EQ(p.bytes[0].value, 'H');
    EXPECT_FALSE(p.bytes[0].wildcard);
    // After string + null: wildcards
    EXPECT_TRUE(p.bytes[6].wildcard);
    // Size at offset 16: 5 (little-endian)
    EXPECT_EQ(p.bytes[16].value, 5);
    EXPECT_FALSE(p.bytes[16].wildcard);
    // Capacity at offset 24: 15 for SSO
    EXPECT_EQ(p.bytes[24].value, 15);
    EXPECT_FALSE(p.bytes[24].wildcard);
}

TEST(PatternTest_String, FromSSOStringHeap) {
    std::string long_str = "This is a longer string that exceeds SSO";
    auto p = Pattern::fromSSOString(long_str, "sso_heap");
    ASSERT_EQ(p.bytes.size(), 32);
    // Heap pointer: wildcards
    EXPECT_TRUE(p.bytes[0].wildcard);
    EXPECT_TRUE(p.bytes[7].wildcard);
    // Size at offset 16: string length
    EXPECT_EQ(p.bytes[16].value, static_cast<uint8_t>(long_str.size()));
    EXPECT_FALSE(p.bytes[16].wildcard);
    // Capacity: wildcard (unknown heap allocation)
    EXPECT_TRUE(p.bytes[24].wildcard);
}

TEST(RegionTest, Make) {
    auto r = MemoryRegion::make(0x1000, 0x2000, true, true, false, "test");
    EXPECT_EQ(r.base, 0x1000);
    EXPECT_EQ(r.size, 0x2000);
    EXPECT_TRUE(r.isWritable());
    EXPECT_TRUE(r.isReadable());
    EXPECT_FALSE(r.isExecutable());
    EXPECT_EQ(r.name, "test");

    auto rx = MemoryRegion::make(0x1000, 0x100, true, false, true);
    EXPECT_TRUE(rx.isExecutable());
    EXPECT_FALSE(rx.isWritable());
}
