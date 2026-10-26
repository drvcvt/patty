#include "patty/memory/image.h"
#include "patty/error.h"
#include "mapped_file.h"

#include <algorithm>
#include <cstring>

namespace patty {

namespace {

// Upper bound for an image's virtual size. Real executables stay far below
// this; anything larger is a corrupt header.
constexpr uint64_t kMaxImageSize = uint64_t{4} << 30;

// Bounds-checked little-endian field reads from the raw file.
class Reader {
public:
    Reader(std::span<const uint8_t> data, const char* format) : m_data(data), m_format(format) {}

    template <typename T>
    T get(uint64_t offset) const {
        if (offset > m_data.size() || sizeof(T) > m_data.size() - offset)
            fail("header points past the end of the file");
        T value;
        std::memcpy(&value, m_data.data() + offset, sizeof(T));
        return value;
    }

    [[noreturn]] void fail(const std::string& why) const {
        throw Error(std::string("malformed ") + m_format + ": " + why + " (use open_raw / --raw to skip headers)");
    }

private:
    std::span<const uint8_t> m_data;
    const char* m_format;
};

// Follows symlinks so /proc/self/exe or a "game" link shows the real file name.
std::string display_name(const std::filesystem::path& path) {
    std::error_code ec;
    const auto resolved = std::filesystem::canonical(path, ec);
    return (ec ? path : resolved).filename().string();
}

std::string section_name(const char* raw, size_t max) {
    return std::string(raw, strnlen(raw, max));
}

} // namespace

struct ImageLoader {
    // Maps [offset, offset + size) of the image to file bytes at file_offset;
    // whatever the file does not cover reads as zero.
    static void segment(Image& image, uint64_t offset, uint64_t size, uint64_t file_offset, uint64_t file_size) {
        if (size == 0)
            return;
        const uint64_t available = file_offset < image.m_file.size() ? image.m_file.size() - file_offset : 0;
        image.m_segments.push_back({static_cast<size_t>(offset), static_cast<size_t>(size),
                                    static_cast<size_t>(file_offset),
                                    static_cast<size_t>(std::min({file_size, size, available}))});
    }

    static void finish(Image& image) {
        std::sort(image.m_segments.begin(), image.m_segments.end(),
                  [](const Image::Segment& a, const Image::Segment& b) { return a.offset < b.offset; });
        std::sort(image.m_regions.begin(), image.m_regions.end(),
                  [](const Region& a, const Region& b) { return a.base < b.base; });
    }

    static void flat(Image& image, uintptr_t base) {
        image.m_format = Image::Format::Raw;
        image.m_base = base;
        image.m_size = image.m_file.size();
        segment(image, 0, image.m_size, 0, image.m_size);
        image.m_regions = {{base, image.m_size, true, false, true, image.m_name}};
    }

    static void pe(Image& image, std::optional<uintptr_t> base) {
        const Reader r(image.m_file, "PE");
        const uint32_t nt = r.get<uint32_t>(0x3C);
        if (r.get<uint32_t>(nt) != 0x00004550)  // "PE\0\0"
            r.fail("missing PE signature");

        const uint64_t coff = uint64_t{nt} + 4;
        const uint16_t section_count = r.get<uint16_t>(coff + 2);
        const uint16_t optional_size = r.get<uint16_t>(coff + 16);
        const uint64_t opt = coff + 20;

        const uint16_t magic = r.get<uint16_t>(opt);
        if (magic != 0x10B && magic != 0x20B)
            r.fail("unknown optional header magic");
        const bool pe64 = magic == 0x20B;
        const uint64_t preferred = pe64 ? r.get<uint64_t>(opt + 24) : r.get<uint32_t>(opt + 28);
        const uint32_t image_size = r.get<uint32_t>(opt + 56);
        const uint32_t headers_size = r.get<uint32_t>(opt + 60);
        if (image_size == 0 || image_size > kMaxImageSize || headers_size > image_size)
            r.fail("implausible SizeOfImage");

        image.m_format = Image::Format::PE;
        image.m_pointer_size = pe64 ? 8 : 4;
        image.m_base = base.value_or(static_cast<uintptr_t>(preferred));
        image.m_size = image_size;
        segment(image, 0, headers_size, 0, headers_size);
        if (headers_size > 0)
            image.m_regions.push_back({image.m_base, headers_size, true, false, false, "headers"});

        const uint64_t table = opt + optional_size;
        for (uint16_t i = 0; i < section_count; ++i) {
            const uint64_t sh = table + uint64_t{i} * 40;
            char raw_name[8];
            for (int c = 0; c < 8; ++c)
                raw_name[c] = static_cast<char>(r.get<uint8_t>(sh + c));
            const uint32_t virtual_size = r.get<uint32_t>(sh + 8);
            const uint32_t virtual_address = r.get<uint32_t>(sh + 12);
            const uint32_t raw_size = r.get<uint32_t>(sh + 16);
            const uint32_t raw_offset = r.get<uint32_t>(sh + 20);
            const uint32_t flags = r.get<uint32_t>(sh + 36);

            if (virtual_address >= image_size)
                continue;
            const uint64_t room = image_size - virtual_address;
            const uint64_t mapped = std::min<uint64_t>(virtual_size ? virtual_size : raw_size, room);
            segment(image, virtual_address, mapped, raw_offset, raw_size);

            image.m_regions.push_back({image.m_base + virtual_address, static_cast<size_t>(mapped),
                                       true, (flags & 0x80000000) != 0, (flags & 0x20000000) != 0,
                                       section_name(raw_name, 8)});
        }
    }

    template <typename Addr>
    static void elf(Image& image, std::optional<uintptr_t> base) {
        constexpr bool is64 = sizeof(Addr) == 8;
        const Reader r(image.m_file, "ELF");
        if (r.get<uint8_t>(5) != 1)
            r.fail("only little-endian ELF is supported");

        const uint64_t ph_off = r.get<Addr>(is64 ? 32 : 28);
        const uint64_t sh_off = r.get<Addr>(is64 ? 40 : 32);
        const uint16_t ph_size = r.get<uint16_t>(is64 ? 54 : 42);
        const uint16_t ph_count = r.get<uint16_t>(is64 ? 56 : 44);
        const uint16_t sh_size = r.get<uint16_t>(is64 ? 58 : 46);
        const uint16_t sh_count = r.get<uint16_t>(is64 ? 60 : 48);
        const uint16_t sh_names = r.get<uint16_t>(is64 ? 62 : 50);

        struct Load { uint64_t vaddr, memsz, offset, filesz; uint32_t flags; };
        std::vector<Load> loads;
        for (uint16_t i = 0; i < ph_count; ++i) {
            const uint64_t ph = ph_off + uint64_t{i} * ph_size;
            if (r.get<uint32_t>(ph) != 1)  // PT_LOAD
                continue;
            if (is64)
                loads.push_back({r.get<uint64_t>(ph + 16), r.get<uint64_t>(ph + 40),
                                 r.get<uint64_t>(ph + 8), r.get<uint64_t>(ph + 32),
                                 r.get<uint32_t>(ph + 4)});
            else
                loads.push_back({r.get<uint32_t>(ph + 8), r.get<uint32_t>(ph + 20),
                                 r.get<uint32_t>(ph + 4), r.get<uint32_t>(ph + 16),
                                 r.get<uint32_t>(ph + 24)});
        }
        if (loads.empty())
            r.fail("no loadable segments");

        uint64_t low = UINT64_MAX, high = 0;
        for (const auto& load : loads) {
            low = std::min(low, load.vaddr & ~uint64_t{0xFFF});
            high = std::max(high, load.vaddr + load.memsz);
        }
        if (high <= low || high - low > kMaxImageSize)
            r.fail("implausible segment layout");

        image.m_format = Image::Format::ELF;
        image.m_pointer_size = sizeof(Addr);
        image.m_base = base.value_or(static_cast<uintptr_t>(low));
        image.m_size = static_cast<size_t>(high - low);
        for (const auto& load : loads)
            segment(image, load.vaddr - low, load.memsz, load.offset, load.filesz);

        // Name regions after allocated sections when the section table is
        // there; stripped binaries fall back to their segments.
        const uint64_t names_off = sh_count ? r.get<Addr>(sh_off + uint64_t{sh_names} * sh_size + (is64 ? 24 : 16)) : 0;
        for (uint16_t i = 0; i < sh_count; ++i) {
            const uint64_t sh = sh_off + uint64_t{i} * sh_size;
            const uint64_t flags = r.get<Addr>(sh + 8);
            const uint64_t addr = r.get<Addr>(sh + (is64 ? 16 : 12));
            const uint64_t size = r.get<Addr>(sh + (is64 ? 32 : 20));
            // Allocated, non-TLS (TLS templates overlap other sections).
            if (!(flags & 0x2) || (flags & 0x400) || size == 0 || addr < low || addr + size > high)
                continue;
            std::string name;
            for (uint64_t at = names_off + r.get<uint32_t>(sh); name.size() < 64; ++at) {
                const char c = static_cast<char>(r.get<uint8_t>(at));
                if (c == '\0') break;
                name.push_back(c);
            }
            image.m_regions.push_back({image.m_base + static_cast<uintptr_t>(addr - low),
                                       static_cast<size_t>(size), true, (flags & 0x1) != 0,
                                       (flags & 0x4) != 0, std::move(name)});
        }
        if (image.m_regions.empty()) {
            for (size_t i = 0; i < loads.size(); ++i)
                image.m_regions.push_back({image.m_base + static_cast<uintptr_t>(loads[i].vaddr - low),
                                           static_cast<size_t>(loads[i].memsz), true,
                                           (loads[i].flags & 0x2) != 0, (loads[i].flags & 0x1) != 0,
                                           "LOAD" + std::to_string(i)});
        }
    }
};

Image Image::open(const std::filesystem::path& path, std::optional<uintptr_t> base) {
    const auto mapped = detail::MappedFile::open(path);
    Image image;
    image.m_name = display_name(path);
    image.m_storage = mapped;
    image.m_file = mapped->bytes();

    const auto file = image.m_file;
    const bool elf = file.size() >= 0x34 && std::memcmp(file.data(), "\x7F" "ELF", 4) == 0;
    if (file.size() >= 0x40 && file[0] == 'M' && file[1] == 'Z')
        ImageLoader::pe(image, base);
    else if (elf && file[4] == 2)
        ImageLoader::elf<uint64_t>(image, base);
    else if (elf && file[4] == 1)
        ImageLoader::elf<uint32_t>(image, base);
    else
        ImageLoader::flat(image, base.value_or(0));
    ImageLoader::finish(image);
    return image;
}

Image Image::open_raw(const std::filesystem::path& path, uintptr_t base) {
    const auto mapped = detail::MappedFile::open(path);
    Image image;
    image.m_name = display_name(path);
    image.m_storage = mapped;
    image.m_file = mapped->bytes();
    ImageLoader::flat(image, base);
    return image;
}

Image Image::from_bytes(std::vector<uint8_t> bytes, uintptr_t base, std::string name) {
    auto owned = std::make_shared<const std::vector<uint8_t>>(std::move(bytes));
    Image image;
    image.m_name = std::move(name);
    image.m_file = *owned;
    image.m_storage = std::move(owned);
    ImageLoader::flat(image, base);
    return image;
}

const Image::Segment* Image::segment_at(size_t offset) const {
    auto next = std::upper_bound(m_segments.begin(), m_segments.end(), offset,
                                 [](size_t value, const Segment& s) { return value < s.offset; });
    if (next == m_segments.begin())
        return nullptr;
    const Segment& candidate = *std::prev(next);
    return offset < candidate.offset + candidate.size ? &candidate : nullptr;
}

bool Image::read(uintptr_t address, void* buffer, size_t size) {
    if (address < m_base || address - m_base > m_size || size > m_size - (address - m_base))
        return false;
    auto* out = static_cast<uint8_t*>(buffer);
    size_t offset = address - m_base;
    while (size > 0) {
        size_t take;
        if (const Segment* s = segment_at(offset)) {
            const size_t inside = offset - s->offset;
            take = std::min(size, s->size - inside);
            const size_t from_file = inside < s->file_size ? std::min(take, s->file_size - inside) : 0;
            std::memcpy(out, m_file.data() + s->file_offset + inside, from_file);
            std::memset(out + from_file, 0, take - from_file);
        } else {
            // A gap between segments (alignment padding) reads as zero.
            auto next = std::upper_bound(m_segments.begin(), m_segments.end(), offset,
                                         [](size_t value, const Segment& s) { return value < s.offset; });
            const size_t gap_end = next == m_segments.end() ? m_size : next->offset;
            take = std::min(size, gap_end - offset);
            std::memset(out, 0, take);
        }
        out += take;
        offset += take;
        size -= take;
    }
    return true;
}

std::span<const uint8_t> Image::view(uintptr_t address, size_t size) {
    if (address < m_base)
        return {};
    const size_t offset = address - m_base;
    const Segment* s = segment_at(offset);
    if (!s)
        return {};
    const size_t inside = offset - s->offset;
    if (inside > s->file_size || size > s->file_size - inside)
        return {};
    return m_file.subspan(s->file_offset + inside, size);
}

std::vector<Module> Image::modules() {
    return {{m_name, m_base, m_size}};
}

std::string Image::describe() const {
    switch (m_format) {
    case Format::PE:  return m_name + " (PE" + (m_pointer_size == 8 ? "32+" : "32") + ")";
    case Format::ELF: return m_name + " (ELF" + std::to_string(m_pointer_size * 8) + ")";
    case Format::Raw: break;
    }
    return m_name + " (raw)";
}

} // namespace patty
