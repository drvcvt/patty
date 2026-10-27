#pragma once

#include "target.h"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace patty {

// A binary loaded from disk or memory, laid out the way a loader would map it:
// PE sections and ELF segments sit at their virtual addresses, so addresses,
// RIP-relative operands and RVAs match what you see in IDA or a live process.
// Files are memory-mapped, not copied; copies of an Image share the mapping.
class Image final : public Target {
public:
    enum class Format { Raw, PE, ELF };

    // Loads a file. PE and ELF files are mapped at their preferred base unless
    // `base` is given; anything else becomes one flat region (see open_raw).
    // Throws patty::Error if the file cannot be read or its headers are broken.
    static Image open(const std::filesystem::path& path,
                      std::optional<Address> base = std::nullopt);

    // Loads a file as one flat region at `base`, ignoring any headers.
    // Use this for memory dumps or when header parsing gets in the way.
    static Image open_raw(const std::filesystem::path& path, Address base = 0);

    // Wraps bytes as one flat region at `base`.
    static Image from_bytes(std::vector<uint8_t> bytes, Address base = 0,
                            std::string name = "buffer");

    using Target::read;
    bool read(Address address, void* buffer, size_t size) override;
    // Zero-copy: points into the mapped file when the range is backed by
    // file bytes (not by zero-filled .bss or alignment gaps).
    std::span<const uint8_t> view(Address address, size_t size) override;
    std::vector<Region> regions() override { return m_regions; }
    // The whole image as one module named after the file.
    std::vector<Module> modules() override;
    size_t pointer_size() const override { return m_pointer_size; }
    std::string describe() const override;

    Format format() const { return m_format; }
    Address base() const { return m_base; }
    size_t size() const { return m_size; }
    const std::string& name() const { return m_name; }

private:
    Image() = default;

    // A piece of the image backed by file bytes; offsets are relative to base.
    // Everything inside [base, base + size) that no segment covers reads as zero.
    struct Segment {
        size_t offset = 0;
        size_t size = 0;
        size_t file_offset = 0;
        size_t file_size = 0;  // <= size, the rest is zero-filled
    };
    const Segment* segment_at(size_t offset) const;

    std::shared_ptr<const void> m_storage;  // the file mapping or owned bytes
    std::span<const uint8_t> m_file;
    std::vector<Segment> m_segments;        // sorted by offset, non-overlapping
    Address m_base = 0;
    size_t m_size = 0;
    std::vector<Region> m_regions;
    std::string m_name;
    Format m_format = Format::Raw;
    size_t m_pointer_size = 8;

    friend struct ImageLoader;
};

} // namespace patty
