#include "patty/scan/scanner.h"
#include "patty/error.h"
#include "patty/scan/resolve.h"

#include "../util.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <mutex>
#include <thread>

namespace patty {

namespace {

constexpr size_t kPageSize = 0x1000;

std::vector<Region> select_regions(Target& target, const ScanOptions& options) {
    auto regions = target.regions();

    std::optional<Module> module;
    if (!options.module.empty()) {
        module = target.module(options.module);
        if (!module)
            throw Error("module not loaded in " + target.describe() + ": " + options.module);
    }

    std::erase_if(regions, [&](const Region& r) {
        if (!r.readable || r.size == 0)
            return true;
        if (module && (r.base < module->base || r.end() > module->end()))
            return true;
        if (options.code_only && !r.executable)
            return true;
        if (options.data_only && (!r.writable || r.executable))
            return true;
        return options.filter && !options.filter(r);
    });
    return regions;
}

// One pass over memory for a set of patterns. Work is split into chunks so a
// single huge region still spreads over all threads.
class Search {
public:
    Search(Target& target, std::span<const Pattern> patterns, const ScanOptions& options)
        : m_target(target), m_patterns(patterns), m_options(options),
          m_regions(select_regions(target, options)), m_counts(patterns.size()) {
        for (const auto& p : patterns)
            m_longest = std::max(m_longest, p.size());
        for (size_t i = 0; i < patterns.size(); ++i)
            m_by_anchor[patterns[i].values()[patterns[i].anchor()]].push_back(i);
        const size_t chunk = std::max<size_t>(m_options.chunk_size, kPageSize);
        for (size_t r = 0; r < m_regions.size(); ++r)
            for (size_t offset = 0; offset < m_regions[r].size; offset += chunk)
                m_work.push_back({r, offset});
        m_chunk = chunk;
    }

    std::vector<ScanResult> run() {
        const auto start = std::chrono::steady_clock::now();
        m_results.resize(m_patterns.size());

        size_t threads = 1;
        if (m_options.parallel) {
            threads = m_options.threads ? m_options.threads : std::thread::hardware_concurrency();
            threads = std::clamp<size_t>(threads, 1, std::max<size_t>(m_work.size(), 1));
        }
        if (threads == 1) {
            worker();
        } else {
            std::vector<std::jthread> pool;
            for (size_t t = 0; t < threads; ++t)
                pool.emplace_back([this] { worker(); });
        }

        const double elapsed = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - start).count();

        std::vector<ScanResult> out(m_patterns.size());
        for (size_t i = 0; i < m_patterns.size(); ++i) {
            auto& matches = m_results[i];
            std::sort(matches.begin(), matches.end(),
                      [](const Match& a, const Match& b) { return a.address < b.address; });
            matches.erase(std::unique(matches.begin(), matches.end(),
                                      [](const Match& a, const Match& b) { return a.address == b.address; }),
                          matches.end());
            if (m_options.max && matches.size() > m_options.max)
                matches.resize(m_options.max);

            out[i].pattern = m_patterns[i].name();
            out[i].matches = std::move(matches);
            out[i].bytes_scanned = m_bytes;
            out[i].elapsed_ms = elapsed;
            out[i].cancelled = m_cancelled;
        }
        return out;
    }

private:
    struct Work { size_t region; size_t offset; };
    using Local = std::vector<std::vector<Match>>;

    void worker() {
        std::vector<uint8_t> buffer(m_chunk + m_longest);
        Local local(m_patterns.size());
        size_t bytes = 0;

        while (!m_stop.load(std::memory_order_relaxed)) {
            if (m_options.cancel && m_options.cancel->load(std::memory_order_relaxed)) {
                m_cancelled = true;
                m_stop = true;
                break;
            }
            const size_t index = m_next.fetch_add(1, std::memory_order_relaxed);
            if (index >= m_work.size())
                break;
            const auto& work = m_work[index];
            const Region& region = m_regions[work.region];
            // Read a little past the chunk so patterns crossing its end are seen,
            // but only accept matches that start inside the chunk.
            const size_t length = std::min(m_chunk + m_longest - 1, region.size - work.offset);
            const size_t limit = std::min(m_chunk, length);
            bytes += read_and_scan(region, region.base + work.offset, length, limit, buffer, local);
        }

        std::lock_guard lock(m_mutex);
        m_bytes += bytes;
        for (size_t i = 0; i < local.size(); ++i)
            m_results[i].insert(m_results[i].end(), std::make_move_iterator(local[i].begin()),
                                std::make_move_iterator(local[i].end()));
    }

    // Returns the number of bytes inside [0, limit) that could be read.
    size_t read_and_scan(const Region& region, uintptr_t at, size_t length, size_t limit,
                         std::vector<uint8_t>& buffer, Local& local) {
        if (m_target.read(at, buffer.data(), length)) {
            scan(region, buffer.data(), length, at, limit, local);
            return limit;
        }

        // Some pages of the chunk are unreadable (guard pages, file mappings past
        // EOF, memory freed mid-scan). Scan the readable runs on their own.
        size_t bytes = 0, run = 0;
        bool in_run = false;
        auto flush = [&](size_t end) {
            if (in_run && run < limit)
                scan(region, buffer.data() + run, end - run, at + run, limit - run, local);
            in_run = false;
        };
        for (size_t offset = 0; offset < length; offset += kPageSize) {
            const size_t n = std::min(kPageSize, length - offset);
            if (m_target.read(at + offset, buffer.data() + offset, n)) {
                if (!in_run) {
                    run = offset;
                    in_run = true;
                }
                if (offset < limit)
                    bytes += std::min(n, limit - offset);
            } else {
                flush(offset);
            }
        }
        flush(length);
        return bytes;
    }

    void scan(const Region& region, const uint8_t* data, size_t length, uintptr_t at,
              size_t limit, Local& local) {
        if (m_patterns.size() == 1) {
            scan_one(region, data, length, at, limit, local);
            return;
        }
        for (size_t pos = 0; pos < length; ++pos) {
            for (size_t index : m_by_anchor[data[pos]]) {
                const Pattern& p = m_patterns[index];
                if (pos < p.anchor())
                    continue;
                const size_t start = pos - p.anchor();
                if (start >= limit || start + p.size() > length || !p.matches(data + start))
                    continue;
                record(index, region, at + start, local);
            }
        }
    }

    // Single pattern: let memchr find the anchor byte.
    void scan_one(const Region& region, const uint8_t* data, size_t length, uintptr_t at,
                  size_t limit, Local& local) {
        const Pattern& p = m_patterns[0];
        if (length < p.size())
            return;
        const size_t last = std::min(limit - 1, length - p.size());
        const uint8_t anchor = p.values()[p.anchor()];
        const uint8_t* cursor = data + p.anchor();
        const uint8_t* stop = data + last + p.anchor();

        while (cursor <= stop) {
            const auto* hit = static_cast<const uint8_t*>(
                std::memchr(cursor, anchor, static_cast<size_t>(stop - cursor) + 1));
            if (!hit)
                break;
            const uint8_t* start = hit - p.anchor();
            if (p.matches(start) && !record(0, region, at + static_cast<size_t>(start - data), local))
                break;
            cursor = hit + 1;
        }
    }

    // Returns false once this pattern has enough matches.
    bool record(size_t index, const Region& region, uintptr_t address, Local& local) {
        if (m_options.max) {
            const size_t seen = m_counts[index].fetch_add(1, std::memory_order_relaxed);
            if (seen >= m_options.max) {
                maybe_stop();
                return false;
            }
        }
        const Pattern& p = m_patterns[index];
        Match match{address, std::nullopt, false, p.name(), region};
        if (!p.steps().empty()) {
            match.resolved = resolve(m_target, address, p.steps());
            match.resolve_failed = !match.resolved;
        }
        local[index].push_back(std::move(match));
        return true;
    }

    void maybe_stop() {
        for (const auto& count : m_counts)
            if (count.load(std::memory_order_relaxed) < m_options.max)
                return;
        m_stop = true;
    }

    Target& m_target;
    std::span<const Pattern> m_patterns;
    const ScanOptions& m_options;
    std::vector<Region> m_regions;
    std::vector<Work> m_work;
    std::array<std::vector<size_t>, 256> m_by_anchor;
    size_t m_longest = 0;
    size_t m_chunk = 0;

    std::atomic_size_t m_next{0};
    std::atomic_bool m_stop{false};
    std::atomic_bool m_cancelled{false};
    std::vector<std::atomic_size_t> m_counts;

    std::mutex m_mutex;
    std::vector<std::vector<Match>> m_results;
    size_t m_bytes = 0;
};

} // namespace

ScanResult Scanner::find(const Pattern& pattern, const ScanOptions& options) const {
    return std::move(find(std::span<const Pattern>(&pattern, 1), options).front());
}

std::vector<ScanResult> Scanner::find(std::span<const Pattern> patterns,
                                      const ScanOptions& options) const {
    if (patterns.empty())
        return {};
    return Search(*m_target, patterns, options).run();
}

ScanResult Scanner::find_pointer(uintptr_t address, const ScanOptions& options) const {
    return std::move(find_pointers(std::span<const uintptr_t>(&address, 1), options).front());
}

std::vector<ScanResult> Scanner::find_pointers(std::span<const uintptr_t> addresses,
                                               const ScanOptions& options) const {
    std::vector<Pattern> patterns;
    patterns.reserve(addresses.size());
    for (const uintptr_t address : addresses)
        patterns.push_back(Pattern::integer(address, m_target->pointer_size())
                               .named("pointer_" + detail::hex(address)));
    return find(patterns, options);
}

} // namespace patty
