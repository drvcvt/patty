#include <gtest/gtest.h>
#include <patty/error.h>
#include <patty/profile/profile.h>
#include <patty/scan/pattern.h>

using namespace patty;

TEST(Pattern, ParsesAob) {
    const auto p = Pattern::aob("48 8b 05 ?? ? ** FF");
    EXPECT_EQ(p.size(), 7u);
    EXPECT_EQ(p.values()[1], 0x8B);
    EXPECT_EQ(p.mask()[3], 0x00);
    EXPECT_EQ(p.mask()[5], 0x00);
    EXPECT_EQ(p.to_string(), "48 8B 05 ?? ?? ?? FF");
}

TEST(Pattern, RejectsGarbage) {
    EXPECT_THROW(Pattern::aob("48 8G"), Error);
    EXPECT_THROW(Pattern::aob("488B"), Error);
    EXPECT_THROW(Pattern::aob(""), Error);
    EXPECT_THROW(Pattern::aob("?? ??"), Error);
}

TEST(Pattern, RawWithMask) {
    const uint8_t bytes[] = {0x48, 0x8B, 0x05, 0x00};
    const auto p = Pattern::raw(bytes, "xx?x");
    EXPECT_EQ(p.to_string(), "48 8B ?? 00");
    EXPECT_THROW(Pattern::raw(bytes, "xx"), Error);
}

TEST(Pattern, TextAndValues) {
    EXPECT_EQ(Pattern::text("Hi").to_string(), "48 69");
    EXPECT_EQ(Pattern::integer(0x1234, 2).to_string(), "34 12");
    EXPECT_EQ(Pattern::value(uint32_t{0xC0FFEE}).to_string(), "EE FF C0 00");
    EXPECT_THROW(Pattern::integer(1, 9), Error);
}

TEST(Pattern, MsvcStringInlineAndHeap) {
    const auto small = Pattern::msvc_string("Hello");
    ASSERT_EQ(small.size(), 32u);
    EXPECT_EQ(small.values()[0], 'H');
    EXPECT_EQ(small.mask()[5], 0xFF);   // terminator is fixed
    EXPECT_EQ(small.mask()[6], 0x00);   // rest of the buffer is not
    EXPECT_EQ(small.values()[16], 5);   // size
    EXPECT_EQ(small.values()[24], 15);  // inline capacity

    const auto big = Pattern::msvc_string("this one does not fit inline");
    EXPECT_EQ(big.mask()[0], 0x00);     // heap pointer
    EXPECT_EQ(big.values()[16], 28);
    EXPECT_EQ(big.mask()[24], 0x00);    // capacity unknown
}

TEST(Pattern, BuilderChains) {
    const auto p = Pattern::aob("48 8B 05 ?? ?? ?? ??").rip(3).deref().add(8).named("Player");
    EXPECT_EQ(p.name(), "Player");
    ASSERT_EQ(p.steps().size(), 4u);
    EXPECT_EQ(p.steps()[0], (ResolveStep{ResolveStep::Kind::Add, 3}));
    EXPECT_EQ(p.steps()[1].kind, ResolveStep::Kind::Rip);
    EXPECT_EQ(p.steps()[2].kind, ResolveStep::Kind::Deref);
    EXPECT_EQ(p.steps()[3], (ResolveStep{ResolveStep::Kind::Add, 8}));
}

TEST(Profile, ParsesAllPatternKinds) {
    const auto profile = Profile::parse(R"({
        "name": "Game", "version": "1.2", "module": "Game.exe",
        "patterns": [
            {"name": "World", "aob": "48 8B 05 ?? ?? ?? ??", "result_offset": 3, "resolve": ["rip"]},
            {"name": "Sig", "ida": "E8 ? ? ? ?", "resolve": [{"type": "add", "extra": 1}, "rip_relative"]},
            {"name": "Banner", "string": "patty"},
            {"name": "Label", "sso_string": "Hi"}
        ]})");

    EXPECT_EQ(profile.name, "Game");
    EXPECT_EQ(profile.module, "Game.exe");
    ASSERT_EQ(profile.patterns.size(), 4u);
    EXPECT_EQ(profile.patterns[0].steps().size(), 2u);  // result_offset becomes an add step
    EXPECT_EQ(profile.patterns[1].steps()[0], (ResolveStep{ResolveStep::Kind::Add, 1}));
    EXPECT_EQ(profile.patterns[2].to_string(), "70 61 74 74 79");
    EXPECT_EQ(profile.patterns[3].size(), 32u);
}

TEST(Profile, ErrorsNameThePattern) {
    try {
        Profile::parse(R"({"patterns": [{"name": "A", "aob": "90"}, {"name": "Broken", "aob": "ZZ"}]})");
        FAIL() << "expected patty::Error";
    } catch (const Error& e) {
        const std::string message = e.what();
        EXPECT_NE(message.find("#2 (Broken)"), std::string::npos) << message;
        EXPECT_NE(message.find("ZZ"), std::string::npos) << message;
    }
    EXPECT_THROW(Profile::parse("{not json"), Error);
    EXPECT_THROW(Profile::parse(R"({"patterns": [{"name": "x"}]})"), Error);
    EXPECT_THROW(Profile::load("/nonexistent/profile.json"), Error);
}
