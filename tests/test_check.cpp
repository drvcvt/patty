#include <gtest/gtest.h>
#include <patty/patty.h>

#include <cstring>

using namespace patty;

namespace {

// 0x10 and 0x30: "48 8B 05 rel32" both pointing at 0x80.
// 0x50: "AA BB CC DD" once. 0x60 and 0x70: "EE EE 11 22" twice.
Image sample() {
    std::vector<uint8_t> data(0x100, 0);
    auto put = [&](size_t at, std::initializer_list<uint8_t> bytes) {
        std::copy(bytes.begin(), bytes.end(), data.begin() + static_cast<long>(at));
    };
    put(0x10, {0x48, 0x8B, 0x05, 0x69, 0x00, 0x00, 0x00});  // 0x80 - (0x13 + 4)
    put(0x30, {0x48, 0x8B, 0x05, 0x49, 0x00, 0x00, 0x00});  // 0x80 - (0x33 + 4)
    put(0x50, {0xAA, 0xBB, 0xCC, 0xDD});
    put(0x60, {0xEE, 0xEE, 0x11, 0x22});
    put(0x70, {0xEE, 0xEE, 0x11, 0x22});
    return Image::from_bytes(std::move(data), 0x1000, "game.bin");
}

Profile profile() {
    Profile p;
    p.patterns.push_back(Pattern::aob("48 8B 05 ?? ?? ?? ??").rip(3).named("Global"));
    p.patterns.push_back(Pattern::aob("AA BB CC DD").named("Unique"));
    p.patterns.push_back(Pattern::aob("EE EE 11 22").named("Twice"));
    p.patterns.push_back(Pattern::aob("DE AD BE EF").named("Gone"));
    // Resolves into zeroed memory, so the deref hits a null pointer.
    p.patterns.push_back(Pattern::aob("48 8B 05 ?? ?? ?? ??").rip(3).deref().named("NullGlobal"));
    return p;
}

} // namespace

TEST(Check, ClassifiesEachPattern) {
    auto image = sample();
    const auto report = Scanner(image).check(profile(), {.module = "game.bin"});

    ASSERT_EQ(report.patterns.size(), 5u);
    const auto& global = report.patterns[0];
    EXPECT_EQ(global.status, CheckStatus::Ok) << "two sites, same resolved target";
    EXPECT_EQ(global.matches.size(), 2u);
    EXPECT_EQ(global.value, 0x1080u);
    EXPECT_EQ(global.rva, 0x80u);

    EXPECT_EQ(report.patterns[1].status, CheckStatus::Ok);
    EXPECT_EQ(report.patterns[1].rva, 0x50u);
    EXPECT_EQ(report.patterns[2].status, CheckStatus::Ambiguous);
    EXPECT_EQ(report.patterns[3].status, CheckStatus::Missing);
    EXPECT_EQ(report.patterns[4].status, CheckStatus::Unresolved);

    EXPECT_EQ(report.count(CheckStatus::Ok), 2u);
    EXPECT_FALSE(report.all_ok());
    EXPECT_EQ(to_string(CheckStatus::Unresolved), "unresolved");
}

TEST(Check, NoModuleMeansNoRva) {
    auto image = sample();
    const auto report = Scanner(image).check(profile());
    EXPECT_FALSE(report.module);
    EXPECT_EQ(report.patterns[1].status, CheckStatus::Ok);
    EXPECT_FALSE(report.patterns[1].rva);
}

TEST(Check, UnknownModuleThrows) {
    auto image = sample();
    EXPECT_THROW(Scanner(image).check(profile(), {.module = "other.dll"}), Error);
}
