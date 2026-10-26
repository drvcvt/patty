#pragma once

#include "target.h"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace patty {

// A binary loaded from disk or memory, laid out the way a loader would map it:
// PE sections and ELF segments sit at their virtual addresses, so addresses,
// RIP-relative operands and RVAs match what you see in IDA or a live process.
class Image final : public Target {
public:
    enum class Format { Raw, PE, ELF };

    // Loads a file. PE and ELF files are mapped at their preferred base unless
    // `base` is given; anything else becomes one flat region (see open_raw).
    // Throws patty::Error if the file cannot be read or its headers are broken.
    static Image open(const std::filesystem::path& path,
                      std::optional<uintptr_t> base = std::nullopt);

    // Loads a file as one flat region at `base`, ignoring any headers.
    // Use this for memory dumps or when header parsing gets in the way.
    static Image open_raw(const std::filesystem::path& path, uintptr_t base = 0);

    // Wraps bytes as one flat region at `base`.
    static Image from_bytes(std::vector<uint8_t> bytes, uintptr_t base = 0,
                            std::string name = "buffer");

    using Target::read;
    bool read(uintptr_t address, void* buffer, size_t size) override;
    std::vector<Region> regions() override { return m_regions; }
    // The whole image as one module named after the file.
    std::vector<Module> modules() override;
    size_t pointer_size() const override { return m_pointer_size; }
    std::string describe() const override;

    Format format() const { return m_format; }
    uintptr_t base() const { return m_base; }
    const std::string& name() const { return m_name; }
    // The mapped image; byte 0 is at base().
    std::span<const uint8_t> memory() const { return m_memory; }

private:
    Image() = default;

    std::vector<uint8_t> m_memory;
    uintptr_t m_base = 0;
    std::vector<Region> m_regions;
    std::string m_name;
    Format m_format = Format::Raw;
    size_t m_pointer_size = 8;

    friend struct ImageLoader;
};

} // namespace patty
