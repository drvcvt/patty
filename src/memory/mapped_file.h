#pragma once

// Read-only memory mapping of a whole file. Not installed.

#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>

namespace patty::detail {

class MappedFile {
public:
    // Throws patty::Error if the file cannot be opened or mapped.
    // Note: truncating the file while it is mapped makes later reads crash
    // (SIGBUS); replacing it (new inode, as updaters do) is fine.
    static std::shared_ptr<const MappedFile> open(const std::filesystem::path& path);

    MappedFile() = default;
    ~MappedFile();
    MappedFile(const MappedFile&) = delete;
    MappedFile& operator=(const MappedFile&) = delete;

    std::span<const uint8_t> bytes() const { return {m_data, m_size}; }

private:
    const uint8_t* m_data = nullptr;
    size_t m_size = 0;
    void* m_handle = nullptr;  // Windows file mapping handle
};

} // namespace patty::detail
