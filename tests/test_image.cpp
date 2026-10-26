#include <gtest/gtest.h>
#include <patty/patty.h>

#include <cstring>
#include <filesystem>
#include <fstream>

using namespace patty;

namespace {

template <typename T>
void put(std::vector<uint8_t>& file, size_t at, T value) {
    std::memcpy(file.data() + at, &value, sizeof(T));
}

// Minimal PE32+ with one .text section whose file offset (0x200) differs
// from its virtual address (0x1000), like every real executable.
std::filesystem::path write_pe() {
    std::vector<uint8_t> file(0x400, 0);
    file[0] = 'M';
    file[1] = 'Z';
    put<uint32_t>(file, 0x3C, 0x40);
    put<uint32_t>(file, 0x40, 0x00004550);   // "PE\0\0"
    const size_t coff = 0x44, opt = coff + 20;
    put<uint16_t>(file, coff, 0x8664);
    put<uint16_t>(file, coff + 2, 1);         // sections
    put<uint16_t>(file, coff + 16, 0xF0);     // optional header size
    put<uint16_t>(file, opt, 0x20B);          // PE32+
    put<uint64_t>(file, opt + 24, 0x140000000);
    put<uint32_t>(file, opt + 56, 0x2000);    // SizeOfImage
    put<uint32_t>(file, opt + 60, 0x200);     // SizeOfHeaders
    const size_t section = opt + 0xF0;
    std::memcpy(file.data() + section, ".text", 5);
    put<uint32_t>(file, section + 8, 0x100);       // VirtualSize
    put<uint32_t>(file, section + 12, 0x1000);     // VirtualAddress
    put<uint32_t>(file, section + 16, 0x200);      // SizeOfRawData
    put<uint32_t>(file, section + 20, 0x200);      // PointerToRawData
    put<uint32_t>(file, section + 36, 0x60000020); // code | execute | read

    // mov rax, [rip+0x0FF9]  at VA 0x1000
    const uint8_t code[] = {0x48, 0x8B, 0x05, 0xF9, 0x0F, 0x00, 0x00};
    std::memcpy(file.data() + 0x200, code, sizeof(code));

    const auto path = std::filesystem::temp_directory_path() / "patty-test.exe";
    std::ofstream(path, std::ios::binary).write(reinterpret_cast<const char*>(file.data()),
                                                static_cast<std::streamsize>(file.size()));
    return path;
}

} // namespace

TEST(Image, MapsPeSectionsAtTheirVirtualAddress) {
    const auto path = write_pe();
    auto image = Image::open(path);
    std::filesystem::remove(path);

    EXPECT_EQ(image.format(), Image::Format::PE);
    EXPECT_EQ(image.base(), 0x140000000u);
    EXPECT_EQ(image.describe(), "patty-test.exe (PE32+)");
    const auto text = image.region_at(0x140001000);
    ASSERT_TRUE(text);
    EXPECT_EQ(text->name, ".text");
    EXPECT_TRUE(text->executable);
    EXPECT_EQ(image.read<uint16_t>(0x140000000), 0x5A4D);  // headers are mapped too

    const auto hit = Scanner(image).find(Pattern::aob("48 8B 05 ?? ?? ?? ??").rip(3), {.code_only = true});
    ASSERT_EQ(hit.size(), 1u);
    EXPECT_EQ(hit[0].address, 0x140001000u);
    EXPECT_EQ(hit[0].resolved, 0x140001007u + 0x0FF9);

    auto rebased = Image::open(write_pe(), 0x10000);
    EXPECT_EQ(rebased.region_at(0x11000)->name, ".text");
}

TEST(Image, ElfMatchesWhatTheLoaderMapped) {
#ifdef __linux__
    // Compare our own executable, loaded from disk, with how it is mapped right now.
    auto image = Image::open("/proc/self/exe");
    ASSERT_EQ(image.format(), Image::Format::ELF);
    EXPECT_EQ(image.pointer_size(), sizeof(void*));

    std::optional<Region> text;
    for (const auto& region : image.regions())
        if (region.name == ".text")
            text = region;
    ASSERT_TRUE(text);
    EXPECT_TRUE(text->executable);

    auto self = Process::current();
    const auto module = self.module(image.name());
    ASSERT_TRUE(module);
    const uintptr_t offset = text->base - image.base();
    EXPECT_EQ(image.read_bytes(text->base, 256), self.read_bytes(module->base + offset, 256));
#else
    GTEST_SKIP() << "Linux only";
#endif
}

TEST(Image, RawAndBrokenFiles) {
    const auto path = std::filesystem::temp_directory_path() / "patty-test.bin";
    std::ofstream(path, std::ios::binary) << "MZ but nothing else of a PE header follows here, really nothing at all";
    EXPECT_THROW(Image::open(path), Error);
    auto raw = Image::open_raw(path, 0x1000);
    EXPECT_EQ(raw.format(), Image::Format::Raw);
    EXPECT_EQ(raw.read<uint16_t>(0x1000), 0x5A4D);
    std::filesystem::remove(path);

    EXPECT_THROW(Image::open("/nonexistent/file"), Error);
}
