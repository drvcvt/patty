#pragma once

#include "provider.h"
#include <string>
#include <fstream>
#include <optional>

namespace patty {

class FileProvider : public IMemoryProvider {
public:
    static std::optional<FileProvider> open(const std::string& path, bool parse_pe = true);
    static std::optional<FileProvider> open(const std::string& path, uintptr_t base,
                                             bool parse_pe = true);

    bool read(uintptr_t address, void* buffer, size_t size) override;
    std::vector<MemoryRegion> regions() override;
    uintptr_t baseAddress() const override { return m_base; }

    size_t fileSize() const { return m_data.size(); }
    const std::string& filePath() const { return m_path; }

private:
    FileProvider() = default;

    std::vector<uint8_t> m_data;
    uintptr_t m_base = 0;
    std::string m_path;
    std::vector<MemoryRegion> m_regions;

    void parsePE();
    void parseELF();
    void buildFlatRegion();
};

} // namespace patty
