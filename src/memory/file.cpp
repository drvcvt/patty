#include "patty/memory/file.h"
#include <cstring>
#include <algorithm>

namespace patty {

std::optional<FileProvider> FileProvider::open(const std::string& path, bool parse_pe) {
    return open(path, 0, parse_pe);
}

std::optional<FileProvider> FileProvider::open(const std::string& path, uintptr_t base,
                                                bool parse_pe) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return std::nullopt;

    auto size = file.tellg();
    if (size <= 0) return std::nullopt;

    FileProvider provider;
    provider.m_path = path;
    provider.m_data.resize(static_cast<size_t>(size));
    provider.m_base = base;

    file.seekg(0);
    file.read(reinterpret_cast<char*>(provider.m_data.data()), size);

    if (!file) return std::nullopt;

    if (parse_pe && provider.m_data.size() >= 2) {
        if (provider.m_data[0] == 'M' && provider.m_data[1] == 'Z') {
            provider.parsePE();
        } else if (provider.m_data[0] == 0x7F && provider.m_data.size() >= 4 &&
                   provider.m_data[1] == 'E' && provider.m_data[2] == 'L' &&
                   provider.m_data[3] == 'F') {
            provider.parseELF();
        } else {
            provider.buildFlatRegion();
        }
    } else {
        provider.buildFlatRegion();
    }

    return provider;
}

bool FileProvider::read(uintptr_t address, void* buffer, size_t size) {
    uintptr_t offset = address - m_base;
    if (offset + size > m_data.size()) return false;
    std::memcpy(buffer, m_data.data() + offset, size);
    return true;
}

std::vector<MemoryRegion> FileProvider::regions() {
    return m_regions;
}

void FileProvider::parsePE() {
    if (m_data.size() < 64) {
        buildFlatRegion();
        return;
    }

    uint32_t pe_offset = 0;
    std::memcpy(&pe_offset, m_data.data() + 0x3C, 4);

    if (pe_offset + 4 > m_data.size() || pe_offset > 0x10000) {
        buildFlatRegion();
        return;
    }

    if (m_data[pe_offset] != 'P' || m_data[pe_offset + 1] != 'E' ||
        m_data[pe_offset + 2] != 0 || m_data[pe_offset + 3] != 0) {
        buildFlatRegion();
        return;
    }

    size_t coff_offset = pe_offset + 4;
    if (coff_offset + 20 > m_data.size()) {
        buildFlatRegion();
        return;
    }

    uint16_t machine = 0;
    std::memcpy(&machine, m_data.data() + coff_offset, 2);

    uint16_t num_sections = 0;
    std::memcpy(&num_sections, m_data.data() + coff_offset + 2, 2);

    uint16_t optional_header_size = 0;
    std::memcpy(&optional_header_size, m_data.data() + coff_offset + 16, 2);

    bool is_pe64 = (machine == 0x8664);
    size_t opt_offset = coff_offset + 20;

    uintptr_t image_base = 0;
    if (is_pe64 && opt_offset + 24 + 8 <= m_data.size()) {
        uint64_t ib = 0;
        std::memcpy(&ib, m_data.data() + opt_offset + 24, 8);
        image_base = static_cast<uintptr_t>(ib);
    } else if (!is_pe64 && opt_offset + 28 + 4 <= m_data.size()) {
        uint32_t ib = 0;
        std::memcpy(&ib, m_data.data() + opt_offset + 28, 4);
        image_base = static_cast<uintptr_t>(ib);
    }

    if (m_base == 0)
        m_base = image_base;

    size_t section_offset = opt_offset + optional_header_size;

    m_regions.clear();

    for (uint16_t i = 0; i < num_sections; ++i) {
        size_t sh = section_offset + i * 40;
        if (sh + 40 > m_data.size()) break;

        char section_name[9] = {};
        std::memcpy(section_name, m_data.data() + sh, 8);

        uint32_t virtual_size = 0, virtual_addr = 0;
        uint32_t raw_size = 0;
        uint32_t characteristics = 0;

        std::memcpy(&virtual_size, m_data.data() + sh + 8, 4);
        std::memcpy(&virtual_addr, m_data.data() + sh + 12, 4);
        std::memcpy(&raw_size, m_data.data() + sh + 16, 4);
        std::memcpy(&characteristics, m_data.data() + sh + 36, 4);

        MemoryRegion region;
        region.base = m_base + virtual_addr;
        region.size = std::max(virtual_size, raw_size);
        region.name = section_name;

        uint32_t prot = 0;
        if (characteristics & 0x20000000) prot |= 0x20;
        if (characteristics & 0x40000000) prot |= 0x02;
        if (characteristics & 0x80000000) prot |= 0x04;
        if (prot == 0) prot = 0x02;
        region.protection = prot;

        region.type = 0x1000000;

        m_regions.push_back(std::move(region));
    }

    if (m_regions.empty())
        buildFlatRegion();
}

void FileProvider::parseELF() {
    if (m_data.size() < 64) {
        buildFlatRegion();
        return;
    }

    uint8_t ei_class = m_data[4];
    bool is_elf64 = (ei_class == 2);

    if (is_elf64) {
        if (m_data.size() < 64) { buildFlatRegion(); return; }

        uint64_t ph_offset = 0;
        uint16_t ph_entry_size = 0, ph_num = 0;
        std::memcpy(&ph_offset, m_data.data() + 32, 8);
        std::memcpy(&ph_entry_size, m_data.data() + 54, 2);
        std::memcpy(&ph_num, m_data.data() + 56, 2);

        m_regions.clear();
        for (uint16_t i = 0; i < ph_num; ++i) {
            size_t ph = static_cast<size_t>(ph_offset) + i * ph_entry_size;
            if (ph + 56 > m_data.size()) break;

            uint32_t p_type = 0;
            uint32_t p_flags = 0;
            uint64_t p_vaddr = 0, p_filesz = 0, p_memsz = 0;

            std::memcpy(&p_type, m_data.data() + ph, 4);
            std::memcpy(&p_flags, m_data.data() + ph + 4, 4);
            std::memcpy(&p_vaddr, m_data.data() + ph + 16, 8);
            std::memcpy(&p_filesz, m_data.data() + ph + 32, 8);
            std::memcpy(&p_memsz, m_data.data() + ph + 40, 8);

            if (p_type != 1) continue;

            MemoryRegion region;
            region.base = m_base + static_cast<uintptr_t>(p_vaddr);
            region.size = static_cast<size_t>(std::max(p_filesz, p_memsz));

            uint32_t prot = 0x02;
            if (p_flags & 0x1) prot |= 0x20;
            if (p_flags & 0x2) prot |= 0x04;
            region.protection = prot;

            m_regions.push_back(std::move(region));
        }
    } else {
        if (m_data.size() < 52) { buildFlatRegion(); return; }

        uint32_t ph_offset = 0;
        uint16_t ph_entry_size = 0, ph_num = 0;
        std::memcpy(&ph_offset, m_data.data() + 28, 4);
        std::memcpy(&ph_entry_size, m_data.data() + 42, 2);
        std::memcpy(&ph_num, m_data.data() + 44, 2);

        m_regions.clear();
        for (uint16_t i = 0; i < ph_num; ++i) {
            size_t ph = static_cast<size_t>(ph_offset) + i * ph_entry_size;
            if (ph + 32 > m_data.size()) break;

            uint32_t p_type = 0, p_vaddr = 0, p_filesz = 0, p_memsz = 0, p_flags = 0;
            std::memcpy(&p_type, m_data.data() + ph, 4);
            std::memcpy(&p_vaddr, m_data.data() + ph + 8, 4);
            std::memcpy(&p_filesz, m_data.data() + ph + 16, 4);
            std::memcpy(&p_memsz, m_data.data() + ph + 20, 4);
            std::memcpy(&p_flags, m_data.data() + ph + 24, 4);

            if (p_type != 1) continue;

            MemoryRegion region;
            region.base = m_base + p_vaddr;
            region.size = std::max(p_filesz, p_memsz);
            uint32_t prot = 0x02;
            if (p_flags & 0x1) prot |= 0x20;
            if (p_flags & 0x2) prot |= 0x04;
            region.protection = prot;

            m_regions.push_back(std::move(region));
        }
    }

    if (m_regions.empty())
        buildFlatRegion();
}

void FileProvider::buildFlatRegion() {
    m_regions.clear();
    MemoryRegion region;
    region.base = m_base;
    region.size = m_data.size();
    region.protection = 0x02;
    region.name = m_path;
    m_regions.push_back(std::move(region));
}

} // namespace patty
