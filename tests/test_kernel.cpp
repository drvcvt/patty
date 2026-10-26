// Every search kernel and the chunked scanner must agree with a naive matcher.
#include <gtest/gtest.h>
#include <patty/patty.h>

#include "scan/kernel.h"

#include <algorithm>
#include <random>

using namespace patty;
using patty::detail::Kernel;

namespace {

// A small alphabet makes partial and full matches frequent.
std::vector<uint8_t> random_bytes(std::mt19937& rng, size_t size) {
    static constexpr uint8_t alphabet[] = {0x00, 0x48, 0x8B, 0x05, 0xDE, 0xAD, 0xFF, 0x90};
    std::vector<uint8_t> bytes(size);
    for (auto& b : bytes)
        b = rng() % 4 ? alphabet[rng() % std::size(alphabet)] : static_cast<uint8_t>(rng());
    return bytes;
}

// Usually cut from the data itself so it is found, with random wildcards.
Pattern random_pattern(std::mt19937& rng, const std::vector<uint8_t>& data) {
    const size_t size = 1 + rng() % 12;
    std::vector<uint8_t> bytes(size);
    if (data.size() >= size && rng() % 4) {
        const size_t at = rng() % (data.size() - size + 1);
        std::copy_n(data.begin() + static_cast<long>(at), size, bytes.begin());
    } else {
        bytes = random_bytes(rng, size);
    }
    std::string mask(size, 'x');
    for (auto& m : mask)
        if (rng() % 3 == 0)
            m = '?';
    mask[rng() % size] = 'x';
    return Pattern::raw(bytes, mask);
}

std::vector<size_t> naive(const Pattern& p, const std::vector<uint8_t>& data, size_t limit) {
    std::vector<size_t> out;
    for (size_t s = 0; s < limit && s + p.size() <= data.size(); ++s)
        if (p.matches(data.data() + s))
            out.push_back(s);
    return out;
}

} // namespace

TEST(Kernel, AllKernelsMatchNaive) {
    std::mt19937 rng(1234);
    for (int round = 0; round < 3000; ++round) {
        const auto data = random_bytes(rng, rng() % 700);
        const auto pattern = random_pattern(rng, data);
        const size_t limit = rng() % 2 ? data.size() : rng() % (data.size() + 1);
        const auto expected = naive(pattern, data, limit);
        const detail::Needle needle(pattern);

        for (const Kernel kernel : {Kernel::Scalar, Kernel::Sse2, Kernel::Avx2}) {
            if (!detail::supported(kernel))
                continue;
            std::vector<size_t> got;
            detail::find_matches(needle, data, limit, got, kernel);
            ASSERT_EQ(got, expected) << detail::name(kernel) << " round " << round << " pattern "
                                     << pattern.to_string() << " size " << data.size() << " limit " << limit;
        }
    }
}

TEST(Kernel, PicksRareAnchors) {
    const detail::Needle needle(Pattern::aob("48 8B 05 ?? ?? ?? ?? 48 85 C0"));
    EXPECT_NE(needle.first_byte, 0x48) << "0x48 is the second most common byte in x64 code";
    EXPECT_TRUE(needle.has_second);
    EXPECT_NE(needle.first, needle.second);
}

TEST(Kernel, ScannerAcrossChunksMatchesNaive) {
    std::mt19937 rng(99);
    for (int round = 0; round < 40; ++round) {
        const auto data = random_bytes(rng, 0x5000 + rng() % 0x3000);
        std::vector<Pattern> patterns;
        for (int i = 0; i < 1 + static_cast<int>(rng() % 4); ++i)
            patterns.push_back(random_pattern(rng, data));
        auto image = Image::from_bytes(data, 0x100000);

        for (const bool parallel : {false, true}) {
            const auto results = Scanner(image).find(patterns, {.parallel = parallel, .chunk_size = 0x1000});
            for (size_t i = 0; i < patterns.size(); ++i) {
                std::vector<size_t> got;
                for (const auto& m : results[i])
                    got.push_back(m.address - 0x100000);
                ASSERT_EQ(got, naive(patterns[i], data, data.size()))
                    << "round " << round << " parallel " << parallel << " pattern " << patterns[i].to_string();
            }
        }
    }
}
