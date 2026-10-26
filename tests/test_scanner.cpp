#include <gtest/gtest.h>
#include <patty/patty.h>

#include <algorithm>
#include <cstring>
#include <map>

using namespace patty;

namespace {

// 0x100 and 0x200: "mov rax, [rip+disp]" with different displacements.
// 0x300: DE AD BE EF once.
Image sample(uintptr_t base = 0x10000) {
    std::vector<uint8_t> bytes(0x1000, 0xCC);
    const uint8_t first[] = {0x48, 0x8B, 0x05, 0x10, 0x00, 0x00, 0x00};
    const uint8_t second[] = {0x48, 0x8B, 0x05, 0x20, 0x00, 0x00, 0x00};
    const uint8_t marker[] = {0xDE, 0xAD, 0xBE, 0xEF};
    std::memcpy(bytes.data() + 0x100, first, sizeof(first));
    std::memcpy(bytes.data() + 0x200, second, sizeof(second));
    std::memcpy(bytes.data() + 0x300, marker, sizeof(marker));
    return Image::from_bytes(std::move(bytes), base);
}

// Several regions with gaps between them; reads of `holes` pages fail.
class Patchwork final : public Target {
public:
    void add(Region region, std::vector<uint8_t> data) {
        m_parts.emplace(region.base, Part{std::move(region), std::move(data)});
    }
    void hole(uintptr_t page) { m_holes.push_back(page); }

    bool read(uintptr_t address, void* buffer, size_t size) override {
        for (const uintptr_t page : m_holes)
            if (address < page + 0x1000 && address + size > page)
                return false;
        for (const auto& [base, part] : m_parts) {
            if (address >= base && address + size <= part.region.end()) {
                std::memcpy(buffer, part.data.data() + (address - base), size);
                return true;
            }
        }
        return false;
    }
    std::vector<Region> regions() override {
        std::vector<Region> out;
        for (const auto& [base, part] : m_parts)
            out.push_back(part.region);
        return out;
    }
    std::string describe() const override { return "patchwork"; }

private:
    struct Part { Region region; std::vector<uint8_t> data; };
    std::map<uintptr_t, Part> m_parts;
    std::vector<uintptr_t> m_holes;
};

std::vector<uint8_t> filled_with_marker(size_t size, size_t at) {
    std::vector<uint8_t> data(size, 0x90);
    const uint8_t marker[] = {0xDE, 0xAD, 0xBE, 0xEF};
    std::memcpy(data.data() + at, marker, sizeof(marker));
    return data;
}

} // namespace

TEST(Scanner, FindsAllMatchesSorted) {
    auto image = sample();
    const auto result = Scanner(image).find(Pattern::aob("48 8B 05 ?? ?? ?? ??"));
    ASSERT_EQ(result.size(), 2u);
    EXPECT_EQ(result[0].address, 0x10100u);
    EXPECT_EQ(result[1].address, 0x10200u);
    EXPECT_FALSE(result[0].resolved) << "no resolve steps, nothing resolved";
    EXPECT_EQ(result[0].value(), 0x10100u);
    EXPECT_GT(result.bytes_scanned, 0u);
}

TEST(Scanner, ResolvesRipRelative) {
    auto image = sample();
    const auto result = Scanner(image).find(Pattern::aob("48 8B 05 ?? ?? ?? ??").rip(3));
    ASSERT_EQ(result.size(), 2u);
    EXPECT_EQ(result[0].resolved, 0x10100u + 7 + 0x10);
    EXPECT_EQ(result[1].resolved, 0x10200u + 7 + 0x20);
}

TEST(Scanner, FailedDerefIsFlagged) {
    auto image = sample();
    // 0xCCCC... is not a mapped address, so the deref after rip fails.
    const auto result = Scanner(image).find(Pattern::aob("48 8B 05 ?? ?? ?? ??").rip(3).deref().deref());
    ASSERT_EQ(result.size(), 2u);
    EXPECT_TRUE(result[0].resolve_failed);
    EXPECT_FALSE(result[0].resolved);
}

TEST(Scanner, MaxAndMissing) {
    auto image = sample();
    Scanner scanner(image);
    EXPECT_EQ(scanner.find(Pattern::aob("48 8B 05"), {.max = 1}).size(), 1u);
    EXPECT_TRUE(scanner.find(Pattern::aob("11 22 33 44")).empty());
}

TEST(Scanner, ManyPatternsInOnePass) {
    auto image = sample();
    const std::vector<Pattern> patterns = {
        Pattern::aob("48 8B 05").named("mov"),
        Pattern::aob("?? AD BE EF").named("marker"),
        Pattern::aob("11 22 33").named("absent"),
    };
    const auto results = Scanner(image).find(patterns);
    ASSERT_EQ(results.size(), 3u);
    EXPECT_EQ(results[0].pattern, "mov");
    EXPECT_EQ(results[0].size(), 2u);
    ASSERT_EQ(results[1].size(), 1u);
    EXPECT_EQ(results[1][0].address, 0x10300u);
    EXPECT_TRUE(results[2].empty());
}

TEST(Scanner, PatternAcrossChunkBoundaryFoundOnce) {
    auto image = Image::from_bytes(filled_with_marker(0x3000, 0xFFE), 0x400000);
    for (const bool parallel : {false, true}) {
        const auto result = Scanner(image).find(Pattern::aob("DE AD BE EF"),
                                                {.parallel = parallel, .chunk_size = 0x1000});
        ASSERT_EQ(result.size(), 1u) << "parallel=" << parallel;
        EXPECT_EQ(result[0].address, 0x400FFEu);
    }
}

TEST(Scanner, RegionFilters) {
    Patchwork target;
    target.add({0x1000, 0x1000, true, false, true, "code"}, filled_with_marker(0x1000, 0x10));
    target.add({0x5000, 0x1000, true, true, false, "data"}, filled_with_marker(0x1000, 0x20));
    target.add({0x9000, 0x1000, true, false, false, "rodata"}, filled_with_marker(0x1000, 0x30));
    Scanner scanner(target);
    const auto marker = Pattern::aob("DE AD BE EF");

    EXPECT_EQ(scanner.find(marker).size(), 3u);
    ASSERT_EQ(scanner.find(marker, {.code_only = true}).size(), 1u);
    EXPECT_EQ(scanner.find(marker, {.code_only = true})[0].region.name, "code");
    EXPECT_EQ(scanner.find(marker, {.data_only = true})[0].address, 0x5020u);
    EXPECT_EQ(scanner.find(marker, {.module = "RODATA"})[0].address, 0x9030u);
    EXPECT_THROW(scanner.find(marker, {.module = "nope.dll"}), Error);

    ScanOptions custom;
    custom.filter = [](const Region& r) { return r.base >= 0x5000; };
    EXPECT_EQ(scanner.find(marker, custom).size(), 2u);
}

TEST(Scanner, UnreadablePageDoesNotHideTheRestOfTheChunk) {
    Patchwork target;
    target.add({0x10000, 0x4000, true, true, false, "heap"}, filled_with_marker(0x4000, 0x3100));
    target.hole(0x11000);
    const auto result = Scanner(target).find(Pattern::aob("DE AD BE EF"));
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0].address, 0x13100u);
    EXPECT_EQ(result.bytes_scanned, 0x3000u);
}

TEST(Scanner, ParallelMaxKeepsLowestAndSorted) {
    Patchwork target;
    for (uintptr_t i = 0; i < 6; ++i)
        target.add({0x10000 + i * 0x1000, 0x200, true, true, false, "seg"}, filled_with_marker(0x200, 0x10));
    const auto result = Scanner(target).find(Pattern::aob("DE AD BE EF"),
                                             {.max = 3, .parallel = true, .threads = 4});
    ASSERT_EQ(result.size(), 3u);
    EXPECT_TRUE(std::is_sorted(result.begin(), result.end(),
                               [](const Match& a, const Match& b) { return a.address < b.address; }));
}

TEST(Scanner, CancelStopsEarly) {
    auto image = sample();
    std::atomic_bool cancel{true};
    const auto result = Scanner(image).find(Pattern::aob("DE AD BE EF"), {.cancel = &cancel});
    EXPECT_TRUE(result.cancelled);
    EXPECT_TRUE(result.empty());
}

TEST(Scanner, FindsPointersAndValues) {
    std::vector<uint8_t> bytes(0x100, 0);
    const uint64_t pointer = 0x10040;
    std::memcpy(bytes.data() + 0x20, &pointer, 8);
    std::memcpy(bytes.data() + 0x80, &pointer, 8);
    const float health = 87.5f;
    std::memcpy(bytes.data() + 0xC0, &health, 4);
    auto image = Image::from_bytes(std::move(bytes), 0x10000);
    Scanner scanner(image);

    EXPECT_EQ(scanner.find_pointer(0x10040).size(), 2u);
    const uintptr_t both[] = {0x10040, 0xDEAD};
    const auto results = scanner.find_pointers(both);
    EXPECT_EQ(results[0].size(), 2u);
    EXPECT_TRUE(results[1].empty());
    ASSERT_EQ(scanner.find(Pattern::value(health)).size(), 1u);
    EXPECT_EQ(scanner.find(Pattern::value(health))[0].address, 0x100C0u);
}

TEST(Scanner, ProbeClassifiesFields) {
    std::vector<uint8_t> bytes(0x200, 0);
    const uint64_t to_string = 0x10100, small = 42, to_vtable = 0x10180, code = 0x10000;
    std::memcpy(bytes.data() + 0x08, &to_string, 8);
    std::memcpy(bytes.data() + 0x10, &small, 8);
    std::memcpy(bytes.data() + 0x18, &to_vtable, 8);
    std::memcpy(bytes.data() + 0x180, &code, 8);
    std::memcpy(bytes.data() + 0x100, "PlayerName", 11);
    auto image = Image::from_bytes(std::move(bytes), 0x10000);

    const auto probe = Scanner(image).probe(0x10000, 0x20);
    ASSERT_EQ(probe.fields.size(), 4u);
    EXPECT_EQ(probe.fields[0].kind, FieldKind::Zero);
    EXPECT_EQ(probe.fields[1].kind, FieldKind::String);
    EXPECT_EQ(probe.fields[1].detail, "PlayerName");
    EXPECT_EQ(probe.fields[2].kind, FieldKind::Integer);
    EXPECT_EQ(probe.fields[3].kind, FieldKind::VTable);  // the image region is executable
}

TEST(Resolve, PointerChainAndRip) {
    std::vector<uint8_t> bytes(0x100, 0);
    const uint64_t a = 0x10040, b = 0x10080;
    std::memcpy(bytes.data() + 0x10, &a, 8);
    std::memcpy(bytes.data() + 0x48, &b, 8);
    const int32_t back = -0x20;
    std::memcpy(bytes.data() + 0xA0, &back, 4);
    auto image = Image::from_bytes(std::move(bytes), 0x10000);

    EXPECT_EQ(pointer_chain(image, 0x10000, {0x10, 0x8, 0x4}), 0x10084u);
    EXPECT_FALSE(pointer_chain(image, 0x10000, {0x20, 0x0}));  // null pointer
    EXPECT_EQ(rip_relative(image, 0x100A0), 0x100A4u - 0x20);
}

TEST(Target, Helpers) {
    std::vector<uint8_t> bytes(0x40, 0);
    std::memcpy(bytes.data() + 0x3C, "abcd", 4);  // no terminator before the end
    auto image = Image::from_bytes(std::move(bytes), 0x1000, "blob");

    EXPECT_EQ(image.read_string(0x103C), "abcd");
    EXPECT_FALSE(image.read_string(0x2000));
    EXPECT_TRUE(image.read_bytes(0x1030, 0x20).empty());
    EXPECT_EQ(image.read<uint32_t>(0x103C), 0x64636261u);
    ASSERT_TRUE(image.module("BLOB"));
    EXPECT_EQ(image.module("blob")->base, 0x1000u);
    EXPECT_EQ(image.region_at(0x1010)->name, "blob");
    EXPECT_FALSE(image.region_at(0x1040));
}

TEST(Target, ModulesAreContiguousRuns) {
    Patchwork target;
    const std::vector<uint8_t> page(0x1000, 0);
    target.add({0x10000, 0x1000, true, false, false, "lib.so"}, page);
    target.add({0x11000, 0x1000, true, false, true, "lib.so"}, page);
    target.add({0x13000, 0x1000, true, true, false, "lib.so"}, page);  // after an unreadable gap
    target.add({0x14000, 0x1000, true, true, false, ""}, page);        // .bss
    target.add({0x15000, 0x1000, true, true, false, ""}, page);        // .bss continues
    target.add({0x30000, 0x1000, true, true, false, ""}, page);        // unrelated anonymous memory
    target.add({0x40000, 0x1000, true, false, true, "other.so"}, page);
    target.add({0x50000, 0x1000, true, false, true, "lib.so"}, page);  // stray second mapping

    const auto lib = target.module("lib.so");
    ASSERT_TRUE(lib);
    EXPECT_EQ(lib->base, 0x10000u);
    EXPECT_EQ(lib->end(), 0x16000u);
    EXPECT_FALSE(target.module_at(0x30000));
    EXPECT_EQ(target.module_at(0x40010)->name, "other.so");
    EXPECT_FALSE(target.module_at(0x50000)) << "the stray mapping must not stretch lib.so";
    EXPECT_EQ(target.modules().size(), 2u);
}
