#include <gtest/gtest.h>
#include <patty/core/pattern.h>
#include <patty/target/loader.h>

using namespace patty;

TEST(PatternTest, ParseAOB_Basic) {
    auto p = Pattern::fromAOB("48 8B 05");
    ASSERT_EQ(p.bytes.size(), 3);
    EXPECT_EQ(p.bytes[0].value, 0x48);
    EXPECT_EQ(p.bytes[1].value, 0x8B);
    EXPECT_EQ(p.bytes[2].value, 0x05);
    EXPECT_FALSE(p.bytes[0].wildcard);
}

TEST(PatternTest, ParseAOB_Wildcards) {
    auto p = Pattern::fromAOB("48 ?? 05 ? AA");
    ASSERT_EQ(p.bytes.size(), 5);
    EXPECT_FALSE(p.bytes[0].wildcard);
    EXPECT_TRUE(p.bytes[1].wildcard);
    EXPECT_FALSE(p.bytes[2].wildcard);
    EXPECT_TRUE(p.bytes[3].wildcard);
    EXPECT_FALSE(p.bytes[4].wildcard);
    EXPECT_EQ(p.bytes[4].value, 0xAA);
}

TEST(PatternTest, ParseAOB_WithName) {
    auto p = Pattern::fromAOB("48 8B 05 ?? ?? ?? ??", "TestPattern");
    EXPECT_EQ(p.name, "TestPattern");
    ASSERT_EQ(p.bytes.size(), 7);
}

TEST(PatternTest, ParseByteMask) {
    uint8_t bytes[] = {0x48, 0x8B, 0x05, 0x00, 0x00};
    auto p = Pattern::fromByteMask(bytes, "xx?..");
    ASSERT_EQ(p.bytes.size(), 5);
    EXPECT_FALSE(p.bytes[0].wildcard);
    EXPECT_FALSE(p.bytes[1].wildcard);
    EXPECT_TRUE(p.bytes[2].wildcard);
    EXPECT_TRUE(p.bytes[3].wildcard);
    EXPECT_TRUE(p.bytes[4].wildcard);
}

TEST(PatternTest, IsValid) {
    auto p1 = Pattern::fromAOB("48 8B");
    EXPECT_TRUE(p1.isValid());

    auto p2 = Pattern::fromAOB("?? ??");
    EXPECT_FALSE(p2.isValid());

    Pattern p3;
    EXPECT_FALSE(p3.isValid());
}

TEST(PatternTest, MatchAt) {
    auto p = Pattern::fromAOB("48 8B ?? 05");
    uint8_t data[] = {0x48, 0x8B, 0xFF, 0x05, 0x00};

    EXPECT_TRUE(p.matchAt(data, sizeof(data)));

    uint8_t data2[] = {0x48, 0x8B, 0xFF, 0x06, 0x00};
    EXPECT_FALSE(p.matchAt(data2, sizeof(data2)));
}

TEST(PatternTest, MatchAt_TooShort) {
    auto p = Pattern::fromAOB("48 8B 05");
    uint8_t data[] = {0x48, 0x8B};
    EXPECT_FALSE(p.matchAt(data, sizeof(data)));
}

TEST(PatternTest, BuilderPattern) {
    auto p = Pattern::fromAOB("48 8B 05 ?? ?? ?? ??")
        .withName("Test")
        .withOffset(3)
        .withResolve(ResolveType::RIPRelative)
        .withDescription("Test pattern");

    EXPECT_EQ(p.name, "Test");
    EXPECT_EQ(p.result_offset, 3);
    ASSERT_EQ(p.resolve_chain.size(), 1);
    EXPECT_EQ(p.resolve_chain[0].type, ResolveType::RIPRelative);
    EXPECT_EQ(p.description, "Test pattern");
}

TEST(PatternTest, InvalidHex) {
    EXPECT_THROW(Pattern::fromAOB("ZZ"), std::invalid_argument);
}

TEST(PatternTest, EmptyPattern) {
    auto p = Pattern::fromAOB("");
    EXPECT_TRUE(p.bytes.empty());
    EXPECT_FALSE(p.isValid());
}

TEST(PatternTest, CaseInsensitiveHex) {
    auto p1 = Pattern::fromAOB("aB cD eF");
    auto p2 = Pattern::fromAOB("AB CD EF");
    ASSERT_EQ(p1.bytes.size(), p2.bytes.size());
    for (size_t i = 0; i < p1.bytes.size(); ++i) {
        EXPECT_EQ(p1.bytes[i].value, p2.bytes[i].value);
    }
}


TEST(ProfileLoaderTest, ParsesStringPatternFromJson) {
    auto profile = ProfileLoader::fromJSON(R"JSON({
        "name": "strings",
        "patterns": [
            {"name": "literal", "string": "PlayerName"}
        ]
    })JSON");

    ASSERT_TRUE(profile.has_value());
    ASSERT_EQ(profile->patterns.size(), 1);
    EXPECT_EQ(profile->patterns[0].name, "literal");
    ASSERT_EQ(profile->patterns[0].bytes.size(), 10);
    EXPECT_EQ(profile->patterns[0].bytes[0].value, 'P');
    EXPECT_FALSE(profile->patterns[0].bytes[0].wildcard);
}

TEST(ProfileLoaderTest, ParsesSsoStringPatternFromJson) {
    auto profile = ProfileLoader::fromJSON(R"JSON({
        "name": "strings",
        "patterns": [
            {"name": "literal", "sso_string": "Hello"}
        ]
    })JSON");

    ASSERT_TRUE(profile.has_value());
    ASSERT_EQ(profile->patterns.size(), 1);
    EXPECT_EQ(profile->patterns[0].name, "literal");
    ASSERT_EQ(profile->patterns[0].bytes.size(), 32);
    EXPECT_EQ(profile->patterns[0].bytes[0].value, 'H');
    EXPECT_FALSE(profile->patterns[0].bytes[0].wildcard);
}
