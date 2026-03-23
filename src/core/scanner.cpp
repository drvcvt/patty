#include "patty/core/scanner.h"

#include <algorithm>
#include <cstring>
#include <thread>
#include <mutex>
#include <numeric>

namespace patty {

Scanner::Scanner(std::shared_ptr<IMemoryProvider> provider)
    : m_provider(std::move(provider)) {}

// --- Core buffer scanning (optimized with memchr + compiled pattern) ---

void Scanner::scanBuffer(const uint8_t* data, size_t size, uintptr_t base_addr,
                          const Pattern& pattern, const MemoryRegion& region,
                          std::vector<Match>& results, size_t max_results) {
    if (pattern.bytes.empty() || size < pattern.bytes.size())
        return;

    const size_t pattern_size = pattern.bytes.size();
    const size_t scan_end = size - pattern_size;

    // Compile pattern once for fast matching
    auto cp = pattern.compile();

    if (!cp.has_fixed) return; // All wildcards — skip

    // Use memchr to jump to next candidate position
    // This is SIMD-optimized on all modern platforms
    const uint8_t* scan_start = data + cp.first_fixed;
    const uint8_t* scan_limit = data + scan_end + cp.first_fixed;
    const uint8_t* pos = scan_start;

    while (pos <= scan_limit) {
        // Find next occurrence of first fixed byte
        const uint8_t* found = static_cast<const uint8_t*>(
            std::memchr(pos, cp.first_byte, static_cast<size_t>(scan_limit - pos + 1))
        );

        if (!found) break;

        // Calculate the actual pattern start position
        const uint8_t* match_start = found - cp.first_fixed;

        // Bounds check
        if (match_start < data || match_start + pattern_size > data + size) {
            pos = found + 1;
            continue;
        }

        // Full pattern match using compiled mask
        if (Pattern::matchCompiled(match_start, cp)) {
            size_t offset = static_cast<size_t>(match_start - data);
            Match m;
            m.address = base_addr + offset;
            m.pattern_name = pattern.name;
            m.region = region;
            m.resolved = resolveMatch(m.address + pattern.result_offset, pattern);
            results.push_back(std::move(m));

            if (max_results > 0 && results.size() >= max_results)
                return;
        }

        pos = found + 1;
    }
}

void Scanner::scanBufferMulti(const uint8_t* data, size_t size, uintptr_t base_addr,
                               std::span<const Pattern> patterns,
                               const std::vector<MemoryRegion>& region_for_each,
                               std::vector<std::vector<Match>>& results,
                               size_t max_results) {
    if (size == 0 || patterns.empty()) return;

    // Compile all patterns and build first-byte lookup table
    std::vector<CompiledPattern> compiled;
    compiled.reserve(patterns.size());
    for (const auto& p : patterns)
        compiled.push_back(p.compile());

    // Build lookup: byte value -> list of pattern indices that have this first byte
    std::vector<std::vector<size_t>> first_byte_table(256);
    for (size_t pi = 0; pi < compiled.size(); ++pi) {
        if (compiled[pi].has_fixed)
            first_byte_table[compiled[pi].first_byte].push_back(pi);
    }

    // Find minimum pattern size
    size_t min_pattern_size = SIZE_MAX;
    for (const auto& p : patterns)
        min_pattern_size = std::min(min_pattern_size, p.bytes.size());
    if (min_pattern_size == 0 || size < min_pattern_size) return;

    // Check if all patterns have first_fixed == 0 (common case)
    // If so, we can use a single memchr-style scan
    bool all_first_at_zero = true;
    for (const auto& cp : compiled) {
        if (cp.has_fixed && cp.first_fixed != 0) {
            all_first_at_zero = false;
            break;
        }
    }

    const MemoryRegion& region = region_for_each.empty() ? MemoryRegion{} : region_for_each[0];
    const size_t scan_end = size - min_pattern_size;

    if (all_first_at_zero) {
        // Fast path: all patterns have first fixed byte at position 0
        // Scan linearly and use lookup table
        for (size_t i = 0; i <= scan_end; ++i) {
            const auto& candidates = first_byte_table[data[i]];
            if (candidates.empty()) continue;

            for (size_t pi : candidates) {
                const auto& pattern = patterns[pi];
                const auto& cp = compiled[pi];
                if (i + pattern.bytes.size() > size) continue;
                if (max_results > 0 && results[pi].size() >= max_results) continue;

                if (Pattern::matchCompiled(data + i, cp)) {
                    Match m;
                    m.address = base_addr + i;
                    m.pattern_name = pattern.name;
                    m.region = region;
                    m.resolved = resolveMatch(m.address + pattern.result_offset, pattern);
                    results[pi].push_back(std::move(m));
                }
            }
        }
    } else {
        // Slow path: patterns have different first_fixed offsets
        // Fallback to checking every position
        for (size_t i = 0; i <= scan_end; ++i) {
            for (size_t pi = 0; pi < patterns.size(); ++pi) {
                const auto& pattern = patterns[pi];
                const auto& cp = compiled[pi];
                if (!cp.has_fixed) continue;
                if (i + pattern.bytes.size() > size) continue;
                if (max_results > 0 && results[pi].size() >= max_results) continue;

                // Quick check first fixed byte
                if (data[i + cp.first_fixed] != cp.first_byte) continue;

                if (Pattern::matchCompiled(data + i, cp)) {
                    Match m;
                    m.address = base_addr + i;
                    m.pattern_name = pattern.name;
                    m.region = region;
                    m.resolved = resolveMatch(m.address + pattern.result_offset, pattern);
                    results[pi].push_back(std::move(m));
                }
            }
        }
    }
}

uintptr_t Scanner::resolveMatch(uintptr_t addr, const Pattern& pattern) {
    uintptr_t current = addr;

    for (const auto& step : pattern.resolve_chain) {
        switch (step.type) {
        case ResolveType::RIPRelative: {
            auto resolved = resolve::ripRelative(*m_provider, current);
            if (!resolved) return 0;
            current = *resolved;
            break;
        }
        case ResolveType::Dereference: {
            std::optional<uint64_t> ptr;
            if (m_provider->is64Bit()) {
                ptr = m_provider->read<uint64_t>(current);
            } else {
                auto v32 = m_provider->read<uint32_t>(current);
                if (v32) ptr = static_cast<uint64_t>(*v32);
            }
            if (!ptr || *ptr == 0) return 0;
            current = static_cast<uintptr_t>(*ptr);
            break;
        }
        case ResolveType::Add:
            current += static_cast<uintptr_t>(step.extra);
            break;
        case ResolveType::None:
            break;
        }
    }

    return current;
}

// --- Region-based scanning ---

std::vector<Match> Scanner::scanRegions(const Pattern& pattern,
                                         const std::vector<MemoryRegion>& regions,
                                         const ScanConfig& config) {
    std::vector<Match> all_matches;
    std::mutex mutex;

    // Pre-allocate a reusable buffer per thread (avoid repeated alloc)
    const size_t buf_size = config.chunk_size + pattern.bytes.size();

    auto processRegion = [&](const MemoryRegion& region, std::vector<uint8_t>& buffer) {
        std::vector<Match> local_matches;
        const size_t chunk_size = config.chunk_size;
        const size_t overlap = pattern.bytes.size();

        size_t offset = 0;
        while (offset < region.size) {
            size_t read_size = std::min(chunk_size + overlap, region.size - offset);

            if (read_size > buffer.size())
                buffer.resize(read_size);

            if (!m_provider->read(region.base + offset, buffer.data(), read_size)) {
                offset += chunk_size;
                continue;
            }

            size_t remaining = config.max_results > 0
                ? config.max_results - local_matches.size()
                : 0;

            scanBuffer(buffer.data(), read_size, region.base + offset,
                       pattern, region, local_matches, remaining);

            if (config.max_results > 0 && local_matches.size() >= config.max_results)
                break;

            offset += chunk_size;
        }

        std::lock_guard lock(mutex);
        all_matches.insert(all_matches.end(),
                           std::make_move_iterator(local_matches.begin()),
                           std::make_move_iterator(local_matches.end()));
    };

    if (config.parallel && regions.size() > 1) {
        size_t n_threads = config.thread_count > 0
            ? config.thread_count
            : std::thread::hardware_concurrency();
        if (n_threads == 0) n_threads = 4;
        n_threads = std::min(n_threads, regions.size());

        std::vector<std::jthread> threads;
        std::atomic<size_t> next_region{0};

        for (size_t t = 0; t < n_threads; ++t) {
            threads.emplace_back([&]() {
                std::vector<uint8_t> thread_buffer(buf_size);
                while (true) {
                    size_t idx = next_region.fetch_add(1);
                    if (idx >= regions.size()) break;
                    if (config.max_results > 0 && all_matches.size() >= config.max_results) break;
                    processRegion(regions[idx], thread_buffer);
                }
            });
        }
        // jthreads join automatically
    } else {
        std::vector<uint8_t> buffer(buf_size);
        for (const auto& region : regions) {
            processRegion(region, buffer);
            if (config.max_results > 0 && all_matches.size() >= config.max_results)
                break;
        }
    }

    // Deduplicate by address
    std::sort(all_matches.begin(), all_matches.end(),
              [](const Match& a, const Match& b) { return a.address < b.address; });
    all_matches.erase(
        std::unique(all_matches.begin(), all_matches.end(),
                    [](const Match& a, const Match& b) { return a.address == b.address; }),
        all_matches.end());

    if (config.max_results > 0 && all_matches.size() > config.max_results)
        all_matches.resize(config.max_results);

    return all_matches;
}

// --- Public API ---

ScanResult Scanner::scan(const Pattern& pattern, const ScanConfig& config) {
    auto start = std::chrono::high_resolution_clock::now();

    auto all_regions = m_provider->regions();
    auto filtered = config.filter.apply(all_regions);

    size_t total_bytes = 0;
    for (const auto& r : filtered)
        total_bytes += r.size;

    auto matches = scanRegions(pattern, filtered, config);

    auto end = std::chrono::high_resolution_clock::now();
    double elapsed = std::chrono::duration<double, std::milli>(end - start).count();

    ScanResult result;
    result.pattern_name = pattern.name;
    result.matches = std::move(matches);
    result.elapsed_ms = elapsed;
    result.bytes_scanned = total_bytes;
    result.regions_scanned = filtered.size();
    return result;
}

MultiScanResult Scanner::scan(std::span<const Pattern> patterns, const ScanConfig& config) {
    auto start = std::chrono::high_resolution_clock::now();

    auto all_regions = m_provider->regions();
    auto filtered = config.filter.apply(all_regions);

    size_t total_bytes = 0;
    for (const auto& r : filtered)
        total_bytes += r.size;

    // Pre-allocate reusable buffer
    size_t max_overlap = 0;
    for (const auto& p : patterns)
        max_overlap = std::max(max_overlap, p.bytes.size());
    const size_t buf_size = config.chunk_size + max_overlap;
    std::vector<uint8_t> buffer(buf_size);

    // For multi-pattern: scan each region once, checking all patterns
    std::vector<std::vector<Match>> per_pattern_matches(patterns.size());

    for (const auto& region : filtered) {
        const size_t chunk_size = config.chunk_size;

        size_t offset = 0;
        while (offset < region.size) {
            size_t read_size = std::min(chunk_size + max_overlap, region.size - offset);

            if (read_size > buffer.size())
                buffer.resize(read_size);

            if (!m_provider->read(region.base + offset, buffer.data(), read_size)) {
                offset += chunk_size;
                continue;
            }

            std::vector<MemoryRegion> region_vec = {region};
            scanBufferMulti(buffer.data(), read_size, region.base + offset,
                           patterns, region_vec, per_pattern_matches, config.max_results);

            offset += chunk_size;
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    double elapsed = std::chrono::duration<double, std::milli>(end - start).count();

    MultiScanResult result;
    result.total_elapsed_ms = elapsed;
    result.total_bytes_scanned = total_bytes;

    for (size_t i = 0; i < patterns.size(); ++i) {
        ScanResult sr;
        sr.pattern_name = patterns[i].name;
        sr.matches = std::move(per_pattern_matches[i]);
        sr.elapsed_ms = elapsed;
        sr.bytes_scanned = total_bytes;
        sr.regions_scanned = filtered.size();
        result.results.push_back(std::move(sr));
    }

    return result;
}

ScanResult Scanner::scanCode(const Pattern& pattern) {
    return scan(pattern, ScanConfig::codeOnly());
}

ScanResult Scanner::scanData(const Pattern& pattern) {
    return scan(pattern, ScanConfig::dataOnly());
}

ScanResult Scanner::scanModule(const Pattern& pattern, const std::string& module) {
    return scan(pattern, ScanConfig::forModule(module));
}

} // namespace patty
