#pragma once

#include "pattern.h"
#include "match.h"
#include "../memory/provider.h"
#include "../region/filter.h"
#include "../resolve/rip_relative.h"
#include "../resolve/pointer_chain.h"

#include <memory>
#include <vector>
#include <functional>
#include <span>
#include <chrono>

namespace patty {

struct ScanConfig {
    size_t chunk_size = 0x200000;   // 2MB chunks
    size_t max_results = 0;         // 0 = unlimited
    RegionFilter filter;            // Region filter
    bool parallel = false;          // Multi-threaded scanning
    size_t thread_count = 0;        // 0 = hardware_concurrency

    static ScanConfig codeOnly() {
        ScanConfig c;
        c.filter = RegionFilter::codeOnly();
        return c;
    }

    static ScanConfig dataOnly() {
        ScanConfig c;
        c.filter = RegionFilter::dataOnly();
        return c;
    }

    static ScanConfig forModule(const std::string& name) {
        ScanConfig c;
        c.filter = RegionFilter::forModule(name);
        return c;
    }
};

class Scanner {
public:
    explicit Scanner(std::shared_ptr<IMemoryProvider> provider);

    using MatchFilter = std::function<bool(const Match&)>;

    ScanResult scan(const Pattern& pattern, const ScanConfig& config = {});
    ScanResult scan(const Pattern& pattern, const ScanConfig& config, MatchFilter filter);
    MultiScanResult scan(std::span<const Pattern> patterns, const ScanConfig& config = {});

    ScanResult scanCode(const Pattern& pattern);
    ScanResult scanData(const Pattern& pattern);
    ScanResult scanModule(const Pattern& pattern, const std::string& module);

    // Scan for a specific pointer/value in memory
    ScanResult scanForValue(uint64_t value, size_t value_size, const ScanConfig& config = {});
    ScanResult scanForPointer(uintptr_t target, const ScanConfig& config = {});
    MultiScanResult scanForPointers(std::span<const uintptr_t> targets, const ScanConfig& config = {});

    // Probe an object's memory layout, classifying each pointer-sized field
    ProbeResult probeObject(uintptr_t address, size_t max_size = 0x400);

    std::shared_ptr<IMemoryProvider> provider() const { return m_provider; }

private:
    std::shared_ptr<IMemoryProvider> m_provider;

    void scanBuffer(const uint8_t* data, size_t size, uintptr_t base_addr,
                    const Pattern& pattern, const CompiledPattern& compiled,
                    const MemoryRegion& region, std::vector<Match>& results,
                    size_t max_results);

    void scanBufferMulti(const uint8_t* data, size_t size, uintptr_t base_addr,
                         std::span<const Pattern> patterns,
                         std::span<const CompiledPattern> compiled_patterns,
                         const MemoryRegion& region,
                         std::vector<std::vector<Match>>& results,
                         size_t max_results);

    uintptr_t resolveMatch(uintptr_t addr, const Pattern& pattern);
    static void dedupeAndCapMatches(std::vector<Match>& matches, size_t max_results);

    std::vector<Match> scanRegions(const Pattern& pattern,
                                   const std::vector<MemoryRegion>& regions,
                                   const ScanConfig& config);
};

} // namespace patty
