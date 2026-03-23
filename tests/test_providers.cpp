#include <gtest/gtest.h>
#include <patty/memory/buffer.h>
#include <patty/memory/file.h>
#include <patty/resolve/rip_relative.h>
#include <patty/resolve/pointer_chain.h>

using namespace patty;

// --- BufferProvider tests ---

TEST(BufferProviderTest, ReadBasic) {
    std::vector<uint8_t> data = {0x48, 0x8B, 0x05, 0x10, 0x20};
    BufferProvider provider(data, 0x1000);

    uint8_t buf[3];
    EXPECT_TRUE(provider.read(0x1000, buf, 3));
    EXPECT_EQ(buf[0], 0x48);
    EXPECT_EQ(buf[1], 0x8B);
    EXPECT_EQ(buf[2], 0x05);
}

TEST(BufferProviderTest, ReadOutOfBounds) {
    std::vector<uint8_t> data = {0x48, 0x8B};
    BufferProvider provider(data, 0x1000);

    uint8_t buf[3];
    EXPECT_FALSE(provider.read(0x1000, buf, 3));
}

TEST(BufferProviderTest, ReadBeforeBase) {
    std::vector<uint8_t> data = {0x48, 0x8B};
    BufferProvider provider(data, 0x1000);

    uint8_t buf[1];
    EXPECT_FALSE(provider.read(0x500, buf, 1));
}

TEST(BufferProviderTest, ReadTyped) {
    std::vector<uint8_t> data(8, 0);
    data[0] = 0x10;
    data[1] = 0x00;
    data[2] = 0x00;
    data[3] = 0x00;
    BufferProvider provider(data, 0x1000);

    int32_t val = 0;
    ASSERT_TRUE(provider.read(0x1000, &val, sizeof(val)));
    EXPECT_EQ(val, 0x10);
}

TEST(BufferProviderTest, Regions) {
    std::vector<uint8_t> data(1024);
    BufferProvider provider(data, 0x2000);

    auto regions = provider.regions();
    ASSERT_EQ(regions.size(), 1);
    EXPECT_EQ(regions[0].base, 0x2000);
    EXPECT_EQ(regions[0].size, 1024);
}

TEST(BufferProviderTest, BaseAddress) {
    std::vector<uint8_t> data(100);
    BufferProvider provider(data, 0x400000);
    EXPECT_EQ(provider.baseAddress(), 0x400000);
}

// --- RIP-relative resolution ---

TEST(ResolveTest, RIPRelative) {
    // Simulate: at address 0x1003, there's a disp32 = 0x10
    // Resolved should be: 0x1003 + 4 + 0x10 = 0x1017
    std::vector<uint8_t> data(0x100, 0);
    data[3] = 0x10; // disp32 at offset 3
    data[4] = 0x00;
    data[5] = 0x00;
    data[6] = 0x00;
    BufferProvider provider(data, 0x1000);

    auto result = resolve::ripRelative(provider, 0x1003);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, 0x1017);
}

TEST(ResolveTest, RIPRelativeNegative) {
    // disp32 = -0x10 = 0xFFFFFFF0
    std::vector<uint8_t> data(0x100, 0);
    int32_t disp = -0x10;
    memcpy(data.data() + 0x50, &disp, 4);
    BufferProvider provider(data, 0x1000);

    auto result = resolve::ripRelative(provider, 0x1050);
    ASSERT_TRUE(result.has_value());
    // 0x1050 + 4 + (-0x10) = 0x1044
    EXPECT_EQ(*result, 0x1044);
}

// --- Pointer chain ---

TEST(ResolveTest, PointerChain) {
    // Build a pointer chain:
    // At 0x1000+0x10: pointer to 0x1080
    // At 0x1080+0x08: pointer to 0x10F0
    // We want: base=0x1000, offsets=[0x10, 0x08, 0x00]
    std::vector<uint8_t> data(0x200, 0);

    // At offset 0x10: store pointer 0x1080
    uint64_t ptr1 = 0x1080;
    memcpy(data.data() + 0x10, &ptr1, 8);

    // At offset 0x88 (0x1080 - 0x1000 + 0x08): store pointer 0x10F0
    uint64_t ptr2 = 0x10F0;
    memcpy(data.data() + 0x88, &ptr2, 8);

    BufferProvider provider(data, 0x1000);

    auto result = resolve::pointerChain(provider, 0x1000, {0x10, 0x08, 0x00});
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, 0x10F0);
}

// --- FileProvider tests ---

TEST(FileProviderTest, OpenNonexistent) {
    auto f = FileProvider::open("__nonexistent_file_12345__.bin");
    EXPECT_FALSE(f.has_value());
}
