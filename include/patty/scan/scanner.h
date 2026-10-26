#pragma once

#include "match.h"
#include "pattern.h"
#include "../memory/target.h"

#include <atomic>
#include <cstddef>
#include <functional>
#include <span>
#include <string>
#include <vector>

namespace patty {

struct Profile;
struct CheckReport;

struct ScanOptions {
    std::string module{};    // only scan inside this module; throws if it is not loaded
    bool code_only = false;  // only executable regions
    bool data_only = false;  // only writable, non-executable regions
    size_t max = 0;          // matches per pattern, 0 = unlimited
    bool parallel = false;   // scan regions on several threads
    size_t threads = 0;      // 0 = hardware concurrency
    size_t chunk_size = size_t{2} << 20;
    std::function<bool(const Region&)> filter{};  // extra region filter
    // Polled once per chunk; set it (e.g. from a SIGINT handler) to stop early.
    const std::atomic_bool* cancel = nullptr;
};

// Searches a target. The scanner only borrows the target: keep it alive for
// as long as the scanner is used.
class Scanner {
public:
    explicit Scanner(Target& target) : m_target(&target) {}

    ScanResult find(const Pattern& pattern, const ScanOptions& options = {}) const;

    // Several patterns in one pass over memory. One result per pattern, same order.
    std::vector<ScanResult> find(std::span<const Pattern> patterns,
                                 const ScanOptions& options = {}) const;

    // Places that hold `address` as a pointer of the target's width.
    ScanResult find_pointer(uintptr_t address, const ScanOptions& options = {}) const;
    std::vector<ScanResult> find_pointers(std::span<const uintptr_t> addresses,
                                          const ScanOptions& options = {}) const;

    // Classifies each pointer-sized field of the object at `address`.
    Probe probe(uintptr_t address, size_t size = 0x400) const;

    // Scans every pattern of the profile and tells which still match uniquely.
    // Uses options.module for RVAs; options.max defaults to 100 here.
    CheckReport check(const Profile& profile, const ScanOptions& options = {}) const;

    Target& target() const { return *m_target; }

private:
    Target* m_target;
};

} // namespace patty
