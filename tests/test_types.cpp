#include <gtest/gtest.h>
#include <patty/patty.h>

#include <cstring>

using namespace patty;

namespace {

// The toygame player, as seen from outside.
struct Player {
    float health;
    int level;
    Remote<char> name;
    Remote<Player> target;
};

static_assert(sizeof(Remote<Player>) == 8);
static_assert(sizeof(Remote32<Player>) == 4);
static_assert(Readable<Player>);
static_assert(!Readable<int*>);
static_assert(is_remote_v<Remote<int>> && !is_remote_v<int>);

// 0x1000: player, 0x1040: enemy, 0x1080/0x1090: names, 0x10C0: global pointer to the player.
Image toy() {
    std::vector<uint8_t> bytes(0x100, 0);
    const Player player{87.5f, 12, Remote<char>(0x1080), Remote<Player>(0x1040)};
    const Player enemy{40.0f, 3, Remote<char>(0x1090), Remote<Player>()};
    const Remote<Player> global(0x1000);
    std::memcpy(bytes.data() + 0x00, &player, sizeof(player));
    std::memcpy(bytes.data() + 0x40, &enemy, sizeof(enemy));
    std::memcpy(bytes.data() + 0x80, "PlayerOne", 10);
    std::memcpy(bytes.data() + 0x90, "Grunt", 6);
    std::memcpy(bytes.data() + 0xC0, &global, sizeof(global));
    return Image::from_bytes(std::move(bytes), 0x1000, "toy");
}

} // namespace

TEST(Types, RemoteArithmeticAndMembers) {
    const Remote<Player> p(0x1000);
    EXPECT_EQ((p + 2).address(), 0x1000u + 2 * sizeof(Player));
    EXPECT_EQ((p + 2 - 1).address(), 0x1000u + sizeof(Player));
    EXPECT_EQ(p[&Player::level].address(), 0x1004u);
    EXPECT_EQ(p[&Player::target].address(), 0x1010u);
    EXPECT_EQ(offset_of(&Player::name), 8u);
    EXPECT_EQ(p.as<uint32_t>().address(), 0x1000u);
    EXPECT_TRUE(p < p + 1);
    EXPECT_FALSE(Remote<Player>());
}

TEST(Types, ReadsStructsAndFollowsMembers) {
    auto game = toy();
    const auto global = Remote<Remote<Player>>(0x10C0);

    const auto player = game.read(global);
    ASSERT_TRUE(player && *player);
    EXPECT_EQ(game.read(*player)->health, 87.5f);
    EXPECT_EQ(game.read_string(game.read(*player)->name), "PlayerOne");

    EXPECT_EQ(game.read(*player, &Player::level), 12);
    EXPECT_EQ(game.read(*player, &Player::target, &Player::health), 40.0f);
    EXPECT_EQ(game.read(*player, &Player::target, &Player::level), 3);
    // The enemy's target is null, so the walk stops there.
    EXPECT_FALSE(game.read(*player, &Player::target, &Player::target, &Player::health));

    const auto both = game.read_array(Remote<Player>(0x1000), 1);
    ASSERT_EQ(both.size(), 1u);
    EXPECT_EQ(both[0].level, 12);
    EXPECT_TRUE(game.read_array<Player>(0x10F0, 4).empty());
}

TEST(Types, ScannerHelpers) {
    auto game = toy();
    Scanner scan{game};

    const auto health = scan.find_value(87.5f);
    ASSERT_EQ(health.size(), 1u);
    EXPECT_EQ(health[0].as<float>().address(), 0x1000u);
    EXPECT_EQ(game.read(health[0].as<Player>(), &Player::level), 12);

    const auto both = scan.find({Pattern::text("PlayerOne"), Pattern::text("Grunt")});
    ASSERT_EQ(both.size(), 2u);
    EXPECT_EQ(both[1][0].address, 0x1090u);
}

TEST(Types, SignatureLiteral) {
    using namespace patty::literals;
    const auto sig = "48 8b 05 ?? ?? ?? ??"_sig.rip(3);
    EXPECT_EQ(sig.to_string(), "48 8B 05 ?? ?? ?? ??");
    EXPECT_EQ(sig.steps().size(), 2u);
    static_assert(detail::valid_aob("48 ?? * 0f"));
    static_assert(!detail::valid_aob("48 8G"));
    static_assert(!detail::valid_aob("?? ??"));
    static_assert(!detail::valid_aob(""));
}

#ifdef __cpp_lib_format
TEST(Types, FormatsRemote) {
    EXPECT_EQ(std::format("{:#x}", Remote<int>(0x7ff6a001)), "0x7ff6a001");
}
#endif
