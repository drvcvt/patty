#include "patty/scan/scanner.h"

#include "../util.h"

#include <cmath>
#include <cstring>

namespace patty {

std::string_view to_string(FieldKind kind) {
    switch (kind) {
    case FieldKind::Zero:    return "zero";
    case FieldKind::Integer: return "small_int";
    case FieldKind::Float:   return "float";
    case FieldKind::Pointer: return "pointer";
    case FieldKind::VTable:  return "vtable";
    case FieldKind::String:  return "string_ptr";
    case FieldKind::Unknown: break;
    }
    return "unknown";
}

namespace {

const Region* find_region(const std::vector<Region>& regions, uintptr_t address) {
    for (const auto& region : regions)
        if (region.contains(address))
            return &region;
    return nullptr;
}

bool printable(const std::string& text) {
    for (const unsigned char c : text)
        if (c < 0x20 || c > 0x7E)
            return false;
    return true;
}

ProbeField classify(Target& target, const std::vector<Region>& regions, size_t offset, uint64_t raw) {
    ProbeField field{offset, raw, FieldKind::Unknown, {}};
    if (raw == 0) {
        field.kind = FieldKind::Zero;
        return field;
    }

    // The first 64 KiB are never mapped on Linux or Windows, so small values
    // are numbers even when an image happens to be loaded at address 0.
    const auto pointer = static_cast<uintptr_t>(raw);
    if (pointer >= 0x10000 && find_region(regions, pointer)) {
        // A pointer to a pointer into executable memory is most likely a vtable.
        if (const auto first = target.read_pointer(pointer)) {
            const Region* code = find_region(regions, *first);
            if (code && code->executable) {
                field.kind = FieldKind::VTable;
                field.detail = "-> " + detail::hex(pointer);
                return field;
            }
        }
        if (const auto text = target.read_string(pointer, 64); text && text->size() >= 2 && printable(*text)) {
            field.kind = FieldKind::String;
            field.detail = *text;
            return field;
        }
        field.kind = FieldKind::Pointer;
        field.detail = "-> " + detail::hex(pointer);
        return field;
    }

    if (raw <= 0xFFFFFF) {
        field.kind = FieldKind::Integer;
        field.detail = std::to_string(raw);
        return field;
    }

    float as_float;
    std::memcpy(&as_float, &raw, sizeof(as_float));
    const float magnitude = std::fabs(as_float);
    if (std::isfinite(as_float) && magnitude > 1e-10f && magnitude < 1e15f) {
        field.kind = FieldKind::Float;
        field.detail = std::to_string(as_float);
    }
    return field;
}

} // namespace

Probe Scanner::probe(uintptr_t address, size_t size) const {
    Probe probe;
    probe.address = address;

    const auto regions = m_target->regions();
    const Region* home = find_region(regions, address);
    if (!home)
        return probe;
    size = std::min(size, static_cast<size_t>(home->end() - address));

    std::vector<uint8_t> bytes(size);
    if (size == 0 || !m_target->read(address, bytes.data(), size))
        return probe;
    probe.size = size;

    const size_t step = m_target->pointer_size();
    for (size_t offset = 0; offset + step <= size; offset += step) {
        uint64_t raw = 0;
        std::memcpy(&raw, bytes.data() + offset, step);
        probe.fields.push_back(classify(*m_target, regions, offset, raw));
    }
    return probe;
}

} // namespace patty
