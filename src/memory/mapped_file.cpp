#include "mapped_file.h"
#include "patty/error.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#endif

namespace patty::detail {

#ifdef _WIN32

std::shared_ptr<const MappedFile> MappedFile::open(const std::filesystem::path& path) {
    auto file = std::make_shared<MappedFile>();
    HANDLE handle = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE)
        throw Error("cannot open " + path.string());

    LARGE_INTEGER size{};
    if (!GetFileSizeEx(handle, &size)) {
        CloseHandle(handle);
        throw Error("cannot read " + path.string());
    }
    file->m_size = static_cast<size_t>(size.QuadPart);
    if (file->m_size == 0) {
        CloseHandle(handle);
        return file;
    }

    HANDLE mapping = CreateFileMappingW(handle, nullptr, PAGE_READONLY, 0, 0, nullptr);
    CloseHandle(handle);
    if (!mapping)
        throw Error("cannot map " + path.string());
    file->m_handle = mapping;
    file->m_data = static_cast<const uint8_t*>(MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0));
    if (!file->m_data)
        throw Error("cannot map " + path.string());
    return file;
}

MappedFile::~MappedFile() {
    if (m_data)
        UnmapViewOfFile(m_data);
    if (m_handle)
        CloseHandle(static_cast<HANDLE>(m_handle));
}

#else

std::shared_ptr<const MappedFile> MappedFile::open(const std::filesystem::path& path) {
    auto file = std::make_shared<MappedFile>();
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        throw Error("cannot open " + path.string() + ": " + std::strerror(errno));

    struct stat info{};
    if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode)) {
        ::close(fd);
        throw Error("cannot read " + path.string() + ": not a regular file");
    }
    file->m_size = static_cast<size_t>(info.st_size);
    if (file->m_size == 0) {
        ::close(fd);
        return file;
    }

    void* data = mmap(nullptr, file->m_size, PROT_READ, MAP_PRIVATE, fd, 0);
    ::close(fd);
    if (data == MAP_FAILED)
        throw Error("cannot map " + path.string() + ": " + std::strerror(errno));
    file->m_data = static_cast<const uint8_t*>(data);
    return file;
}

MappedFile::~MappedFile() {
    if (m_data)
        munmap(const_cast<uint8_t*>(m_data), m_size);
}

#endif

} // namespace patty::detail
