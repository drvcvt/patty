#include "kernel.h"

#include <algorithm>
#include <bit>
#include <cstring>

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#define PATTY_X86 1
#include <immintrin.h>
#ifdef _MSC_VER
#include <intrin.h>
#define PATTY_TARGET(isa)
#else
#define PATTY_TARGET(isa) __attribute__((target(isa)))
#endif
#endif

namespace patty::detail {

namespace {

// Rank of each byte value by frequency, 0 = rarest, 255 = most common.
// Each file weighted equally: projectpitt.exe (Godot), GameAssembly.dll and
// UnityPlayer.dll (Unity), D3D12Core.dll, amdxcffx64.dll, th06nc.exe,
// libLLVM, libc and libpython. Most common: 00 48 FF 8B 0F 01 24 89.
constexpr uint8_t kRank[256] = {
    255, 250, 240, 234, 235, 225, 211, 191, 236, 167, 177, 164, 208, 195, 220, 251,
    239, 197, 120, 101, 159, 162, 117,  83, 222,  96,  94,  76, 135, 103, 142, 217,
    245, 148, 102, 129, 249, 155, 104,  85, 223, 171,  61, 137, 141,  69, 149, 109,
    224, 204, 105, 183, 133, 131,  75,  78, 215, 194,  80, 161, 126, 130,  55,  86,
    228, 247, 189, 178, 244, 226, 169, 160, 254, 231,  66,  97, 243, 201, 112, 119,
    214,  74, 121, 151, 190, 157, 128, 139, 176, 115,  39, 113, 172, 114,  79, 200,
    198, 193, 143, 184, 187, 219, 227, 116, 170, 179,  21,  93, 186, 138, 192, 196,
    210,  18, 205, 199, 238, 218, 123, 118, 185, 108,  47,  31, 145,  43,  54,  77,
    229, 216, 150, 242, 232, 233,  72,  81, 174, 248,   4, 252, 140, 241,  28,  42,
    202,  10,   7,  11,  95,  36,   2,  13, 122,  23,  12,  15,  73,  48,  27,  30,
    173,  91,  64,  70, 124,  90,  65,  51, 152,  60,  44,  35,  68,  20,  14,  46,
    136,   5,   0,   1,  32,   6, 134,  88, 168,  87,  82,   8,  52,  29,  33,  26,
    237, 221, 158, 203, 181, 107, 154, 212, 207, 166,  98, 100, 230,  22,  71,  84,
    180, 106, 156,  58,  25,  53,  45,  56, 146,  57,  38,  62,  24,   3,  17,  63,
    188,  99,  67,  16,  92,   9,  34,  37, 246, 213,  49, 165, 144,  50,  41,  89,
    175,  59, 125, 209,  40,  19, 147, 111, 182, 127, 163, 110, 132, 153, 206, 253,
};

// Number of candidate starts: s < limit and s + size <= length.
size_t candidates(size_t length, size_t size, size_t limit) {
    return length < size ? 0 : std::min(limit, length - size + 1);
}

void scan_scalar(const Needle& n, const uint8_t* data, size_t count, std::vector<size_t>& out) {
    const uint8_t* cursor = data + n.first;
    const uint8_t* end = cursor + count;
    while (cursor < end) {
        const auto* hit = static_cast<const uint8_t*>(
            std::memchr(cursor, n.first_byte, static_cast<size_t>(end - cursor)));
        if (!hit)
            return;
        const size_t s = static_cast<size_t>(hit - data) - n.first;
        if ((!n.has_second || data[s + n.second] == n.second_byte) && n.pattern->matches(data + s))
            out.push_back(s);
        cursor = hit + 1;
    }
}

// Checks the tail that does not fill a whole vector.
void scan_tail(const Needle& n, const uint8_t* data, size_t from, size_t count, std::vector<size_t>& out) {
    for (size_t s = from; s < count; ++s)
        if (data[s + n.first] == n.first_byte && data[s + n.second] == n.second_byte &&
            n.pattern->matches(data + s))
            out.push_back(s);
}

#ifdef PATTY_X86

void verify(const Needle& n, const uint8_t* data, size_t at, uint32_t mask, std::vector<size_t>& out) {
    while (mask) {
        const size_t start = at + static_cast<size_t>(std::countr_zero(mask));
        if (n.pattern->matches(data + start))
            out.push_back(start);
        mask &= mask - 1;
    }
}

// Both anchor bytes are compared for 16 (SSE2) or 32 (AVX2) starts at once;
// only starts where both match get the full comparison. The loads stay inside
// data: s + width <= count keeps s + offset + width - 1 below length.
PATTY_TARGET("sse2")
void scan_sse2(const Needle& n, const uint8_t* data, size_t count, std::vector<size_t>& out) {
    const __m128i first = _mm_set1_epi8(static_cast<char>(n.first_byte));
    const __m128i second = _mm_set1_epi8(static_cast<char>(n.second_byte));
    size_t s = 0;
    for (; s + 16 <= count; s += 16) {
        const __m128i a = _mm_loadu_si128(reinterpret_cast<const __m128i*>(data + s + n.first));
        const __m128i b = _mm_loadu_si128(reinterpret_cast<const __m128i*>(data + s + n.second));
        verify(n, data, s, static_cast<uint32_t>(_mm_movemask_epi8(
                               _mm_and_si128(_mm_cmpeq_epi8(a, first), _mm_cmpeq_epi8(b, second)))), out);
    }
    scan_tail(n, data, s, count, out);
}

PATTY_TARGET("avx2")
inline __m256i avx2_hits(const uint8_t* a, const uint8_t* b, __m256i first, __m256i second) {
    const __m256i x = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(a));
    const __m256i y = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(b));
    return _mm256_and_si256(_mm256_cmpeq_epi8(x, first), _mm256_cmpeq_epi8(y, second));
}

PATTY_TARGET("avx2")
void scan_avx2(const Needle& n, const uint8_t* data, size_t count, std::vector<size_t>& out) {
    const __m256i first = _mm256_set1_epi8(static_cast<char>(n.first_byte));
    const __m256i second = _mm256_set1_epi8(static_cast<char>(n.second_byte));
    const uint8_t* a = data + n.first;
    const uint8_t* b = data + n.second;

    size_t s = 0;
    // 64 starts per step; most steps have no candidate and end after one vptest.
    for (; s + 64 <= count; s += 64) {
        const __m256i low = avx2_hits(a + s, b + s, first, second);
        const __m256i high = avx2_hits(a + s + 32, b + s + 32, first, second);
        const __m256i any = _mm256_or_si256(low, high);
        if (_mm256_testz_si256(any, any))
            continue;
        verify(n, data, s, static_cast<uint32_t>(_mm256_movemask_epi8(low)), out);
        verify(n, data, s + 32, static_cast<uint32_t>(_mm256_movemask_epi8(high)), out);
    }
    for (; s + 32 <= count; s += 32)
        verify(n, data, s, static_cast<uint32_t>(_mm256_movemask_epi8(avx2_hits(a + s, b + s, first, second))), out);
    scan_tail(n, data, s, count, out);
}

bool cpu_has_avx2() {
#ifdef _MSC_VER
    int info[4];
    __cpuid(info, 1);
    const bool os_saves_ymm = (info[2] & (1 << 27)) && (info[2] & (1 << 28)) && (_xgetbv(0) & 6) == 6;
    if (!os_saves_ymm)
        return false;
    __cpuidex(info, 7, 0);
    return info[1] & (1 << 5);
#else
    __builtin_cpu_init();
    return __builtin_cpu_supports("avx2");
#endif
}

#endif

} // namespace

Needle::Needle(const Pattern& p) : pattern(&p) {
    const auto mask = p.mask();
    const auto values = p.values();
    bool found = false;
    for (size_t i = 0; i < p.size(); ++i) {
        if (!mask[i])
            continue;
        if (!found || kRank[values[i]] < kRank[first_byte]) {
            first = i;
            first_byte = values[i];
            found = true;
        }
    }
    for (size_t i = 0; i < p.size(); ++i) {
        if (!mask[i] || i == first)
            continue;
        if (!has_second || kRank[values[i]] < kRank[second_byte]) {
            second = i;
            second_byte = values[i];
            has_second = true;
        }
    }
}

bool supported(Kernel kernel) {
    switch (kernel) {
    case Kernel::Scalar:
        return true;
#ifdef PATTY_X86
    case Kernel::Sse2:
        return true;
    case Kernel::Avx2: {
        static const bool avx2 = cpu_has_avx2();
        return avx2;
    }
#else
    default:
        return false;
#endif
    }
    return false;
}

Kernel best_kernel() {
    static const Kernel best = supported(Kernel::Avx2) ? Kernel::Avx2
                             : supported(Kernel::Sse2) ? Kernel::Sse2
                                                       : Kernel::Scalar;
    return best;
}

const char* name(Kernel kernel) {
    switch (kernel) {
    case Kernel::Scalar: return "scalar";
    case Kernel::Sse2:   return "sse2";
    case Kernel::Avx2:   return "avx2";
    }
    return "?";
}

void find_matches(const Needle& needle, std::span<const uint8_t> data, size_t limit,
                  std::vector<size_t>& starts, Kernel kernel) {
    const size_t count = candidates(data.size(), needle.pattern->size(), limit);
    if (count == 0)
        return;
    // A single fixed byte has nothing to pair with; memchr is as good as it gets.
    if (!needle.has_second || kernel == Kernel::Scalar) {
        scan_scalar(needle, data.data(), count, starts);
        return;
    }
#ifdef PATTY_X86
    if (kernel == Kernel::Avx2)
        scan_avx2(needle, data.data(), count, starts);
    else
        scan_sse2(needle, data.data(), count, starts);
#else
    scan_scalar(needle, data.data(), count, starts);
#endif
}

} // namespace patty::detail
