#include "session.h"
#include "value_type.h"

#include <iomanip>
#include <sstream>

namespace patty::cli {

namespace {

std::string summary(const ScanResult& result, bool several) {
    std::ostringstream out;
    if (several)
        out << '[' << result.pattern << "] ";
    out << result.size() << (result.size() == 1 ? " match" : " matches") << "  (" << human_size(result.bytes_scanned)
        << ", " << std::fixed << std::setprecision(1) << result.elapsed_ms << " ms"
        << (result.cancelled ? ", cancelled" : "") << ')';
    return out.str();
}

} // namespace

int Session::show(const std::vector<ScanResult>& results, const ScanOptions& options, const std::vector<uint8_t>& last) {
    const size_t width = target().pointer_size();
    const auto modules = target().modules();
    const auto regions = target().regions();
    m_hits.clear();
    size_t total = 0;

    for (const auto& result : results) {
        m_out.info() << summary(result, results.size() > 1) << '\n';
        for (const auto& match : result) {
            const auto place = where(match.address, modules, regions);
            std::string line = "  " + remember(match.value());
            line.resize(std::max<size_t>(line.size(), 8), ' ');
            line += hex(match.address, width);
            if (match.resolved)
                line += " -> " + hex(*match.resolved, width);
            else if (match.resolve_failed)
                line += " -> (unresolved)";
            line += "  " + place;

            // The pattern column only matters when several were searched (refs -).
            std::vector<std::string> fields{hex(match.value(), width), hex(match.address, width), place};
            json object{{"value", hex(match.value(), width)}, {"address", hex(match.address, width)}, {"where", place}};
            if (results.size() > 1) {
                fields.push_back(result.pattern);
                object["pattern"] = result.pattern;
            }
            if (match.resolve_failed)
                object["resolve_failed"] = true;
            m_out.record(line, fields, object);
            m_hits.push_back({match.value(), last});
        }
        if (options.max && result.size() >= options.max)
            m_out.info() << "  (stopped at " << options.max << ", -n or \"set max\" for more)\n";
        total += result.size();
    }
    return total ? 0 : 2;
}

int Session::cmd_find(Args& args) {
    int64_t offset = 0;
    std::string resolve;
    bool msvc = false;
    auto options = scan_flags(args, [&](const std::string& flag, Args& a) {
        if (flag == "-o") {
            const auto value = parse_number(a.take().text);
            if (!value)
                throw Error("-o needs a number");
            offset += static_cast<int64_t>(*value);
        } else if (flag == "-r") {
            // "-r 3" is short for "-o 3 -r rip": the rel32 operand sits at byte 3.
            const std::string spec = a.take().text;
            if (const auto at = parse_number(spec)) {
                offset += static_cast<int64_t>(*at);
                resolve = resolve.empty() ? "rip" : resolve + ",rip";
            } else {
                resolve = resolve.empty() ? spec : resolve + "," + spec;
            }
        } else if (flag == "-s") {
            msvc = true;
        } else {
            return false;
        }
        return true;
    });
    if (args.done())
        throw Error("usage: find [flags] <sig | text>");

    // Hex bytes and wildcards are a signature, anything else is text. The
    // content decides, not quoting: a shell turns "48 8B ..." into one argument.
    const auto text = args.rest();
    auto pattern = msvc ? Pattern::msvc_string(text)
                 : detail::valid_aob(text) ? Pattern::aob(text)
                 : Pattern::text(text);
    if (offset)
        pattern.add(offset);
    apply_resolve_spec(pattern, resolve);
    return show({Scanner(target()).find(pattern, options)}, options);
}

int Session::cmd_findval(Args& args) {
    auto options = scan_flags(args);
    const std::string value = args.take().text;
    const auto type = args.done() ? ValueType::guess(value) : ValueType::parse(args.take().text);
    if (type.kind() == ValueType::Kind::String)
        throw Error("for text use find");
    const auto bytes = type.encode(value, target().pointer_size());
    auto pattern = Pattern::raw(bytes).named(value + " " + type.name());
    return show({Scanner(target()).find(pattern, options)}, options, bytes);
}

int Session::cmd_refs(Args& args) {
    auto options = scan_flags(args);
    const auto targets = addresses(args);
    return show(Scanner(target()).find_pointers(targets, options), options);
}

int Session::cmd_filter(Args& args) {
    const auto type = ValueType::parse(args.take().text);
    const auto op = parse_compare(args.take().text);
    const size_t width = target().pointer_size();
    std::vector<uint8_t> given;
    if (!needs_previous(op))
        given = type.encode(args.take().text, width);

    // From a pipe: the second column is the earlier value. In the shell: the last hits.
    std::vector<Hit> candidates;
    if (args.rest() == "-") {
        for (const auto& line : input()) {
            Hit hit{line.address, {}};
            if (needs_previous(op) && !line.value.empty())
                hit.last = type.encode(line.value, width);
            candidates.push_back(std::move(hit));
        }
    } else if (!args.done()) {
        throw Error("filter takes - (addresses from a pipe) or nothing (the last hits)");
    } else {
        candidates = m_hits;
        if (candidates.empty())
            throw Error("nothing to filter yet: search first (findval, find, refs, read)");
    }

    const size_t size = type.size(width);
    const auto modules = target().modules();
    const auto regions = target().regions();
    std::vector<Hit> kept;
    for (const auto& hit : candidates) {
        std::vector<uint8_t> current;
        if (type.kind() == ValueType::Kind::String) {
            const auto text = target().read_string(hit.address);
            if (!text)
                continue;
            current.assign(text->begin(), text->end());
        } else {
            current = target().read_bytes(hit.address, size);
            if (current.empty())
                continue;
        }
        if (needs_previous(op) && hit.last.empty())
            throw Error("no earlier value for " + hex(hit.address, width) +
                        ": run findval or read first, or pipe in read's output");
        if (!type.compare(current, op, needs_previous(op) ? hit.last : given))
            continue;

        const auto shown = type.format(current);
        std::string line = "  " + remember(hit.address);
        line.resize(std::max<size_t>(line.size(), 8), ' ');
        line += hex(hit.address, width) + "  " + shown + "  " + where(hit.address, modules, regions);
        m_out.record(line, {hex(hit.address, width), shown},
                     {{"address", hex(hit.address, width)}, {"type", type.name()}, {"value", type.to_json(current)}});
        kept.push_back({hit.address, std::move(current)});
    }
    m_out.info() << kept.size() << " of " << candidates.size() << " left\n";
    m_hits = std::move(kept);
    return m_hits.empty() ? 2 : 0;
}

int Session::cmd_check(Args& args) {
    auto options = scan_flags(args);
    if (!args.done())
        m_profile = Profile::load(std::string(args.rest()));
    if (!m_profile)
        throw Error("usage: check [-m module] <profile.json>");
    options.max = 100;
    apply_profile_module(options, *m_profile, target());
    const auto report = Scanner(target()).check(*m_profile, options);
    const size_t width = target().pointer_size();

    m_out.info() << "Checked " << report.patterns.size() << " pattern(s) over " << human_size(report.bytes_scanned)
                 << " in " << std::fixed << std::setprecision(1) << report.elapsed_ms << " ms: "
                 << report.count(CheckStatus::Ok) << " ok, " << report.count(CheckStatus::Ambiguous) << " ambiguous, "
                 << report.count(CheckStatus::Missing) << " missing";
    if (const auto unresolved = report.count(CheckStatus::Unresolved))
        m_out.info() << ", " << unresolved << " unresolved";
    m_out.info() << (report.cancelled ? " (cancelled)" : "") << (m_out.table() ? "\n\n" : "\n");

    size_t name_width = 4;
    for (const auto& check : report.patterns)
        name_width = std::max(name_width, check.name.size());
    for (const auto& check : report.patterns) {
        const bool ok = check.status == CheckStatus::Ok;
        std::ostringstream line;
        line << "  " << std::left << std::setw(12) << to_string(check.status);
        if (check.status == CheckStatus::Missing)
            line << check.name;
        else
            line << std::setw(static_cast<int>(name_width + 2)) << check.name;
        if (ok) {
            line << hex(check.value, width);
            if (check.rva)
                line << "  rva " << hex(*check.rva, 4);
        } else if (check.status != CheckStatus::Missing) {
            line << check.matches.size() << " matches";
        }

        json object{{"name", check.name}, {"status", to_string(check.status)}, {"count", check.matches.size()}};
        if (ok)
            object["value"] = hex(check.value, width);
        if (check.rva)
            object["rva"] = hex(*check.rva, 4);
        m_out.record(line.str(),
                     {check.name, std::string(to_string(check.status)), ok ? hex(check.value, width) : "-",
                      check.rva ? hex(*check.rva, 4) : "-"},
                     object);
    }
    return report.all_ok() ? 0 : 2;
}

} // namespace patty::cli
