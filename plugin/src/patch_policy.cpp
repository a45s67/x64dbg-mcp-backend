#include "patch_policy.h"

#include <charconv>
#include <algorithm>
#include <cstdint>
#include <limits>

namespace mcp {

bool SafeInstruction(const std::string_view value) noexcept {
    if (value.empty() || value.size() > 128U) return false;
    for (const unsigned char byte : value) {
        if (byte < 0x20U || byte > 0x7eU || byte == ';') return false;
    }
    return true;
}

std::optional<std::vector<unsigned char>> ParsePatchBytes(const std::string_view value) {
    if (value.empty() || value.size() > 32U || value.size() % 2U != 0U) return std::nullopt;
    std::vector<unsigned char> result;
    result.reserve(value.size() / 2U);
    for (std::size_t index = 0; index < value.size(); index += 2U) {
        if (!((value[index] >= '0' && value[index] <= '9') ||
              (value[index] >= 'a' && value[index] <= 'f')) ||
            !((value[index + 1U] >= '0' && value[index + 1U] <= '9') ||
              (value[index + 1U] >= 'a' && value[index + 1U] <= 'f'))) return std::nullopt;
        unsigned int byte = 0U;
        const auto parsed = std::from_chars(value.data() + index, value.data() + index + 2U,
                                            byte, 16);
        if (parsed.ec != std::errc{} || parsed.ptr != value.data() + index + 2U) {
            return std::nullopt;
        }
        result.push_back(static_cast<unsigned char>(byte));
    }
    return result;
}

std::optional<std::vector<unsigned char>>
PreparePatchBytes(const std::span<const unsigned char> assembled,
                  const std::span<const unsigned char> expected,
                  const bool fillNop) {
    if (assembled.empty() || expected.empty() || expected.size() > 16U ||
        assembled.size() > expected.size()) return std::nullopt;
    if (assembled.size() < expected.size() && !fillNop) return std::nullopt;
    std::vector<unsigned char> result(assembled.begin(), assembled.end());
    result.resize(expected.size(), 0x90U);
    return result;
}

bool PatchRangeValid(const duint address, const std::size_t size) noexcept {
    return size >= 1U && size <= 16U &&
           static_cast<duint>(size - 1U) <= std::numeric_limits<duint>::max() - address;
}

bool PatchRecordMatches(const DBGPATCHINFO& record,
                        const duint address,
                        const unsigned char original,
                        const unsigned char patched) noexcept {
    return record.addr == address && record.oldbyte == original && record.newbyte == patched;
}

std::optional<std::vector<TrackedPatchRange>>
NormalizeTrackedPatches(std::vector<TrackedPatchByte> records) {
    if (records.size() > 65536U) return std::nullopt;
    std::sort(records.begin(), records.end(), [](const auto& left, const auto& right) {
        if (left.address != right.address) return left.address < right.address;
        return left.module < right.module;
    });
    std::vector<TrackedPatchRange> ranges;
    ranges.reserve(records.size());
    for (const auto& record : records) {
        if (record.module.empty() || record.original == record.patched) return std::nullopt;
        const bool canExtend = !ranges.empty() &&
                               static_cast<duint>(ranges.back().patched.size()) <=
                                   std::numeric_limits<duint>::max() - ranges.back().address;
        if (canExtend && record.address == ranges.back().address +
                                               static_cast<duint>(ranges.back().patched.size()) &&
            record.module == ranges.back().module) {
            ranges.back().original.push_back(record.original);
            ranges.back().patched.push_back(record.patched);
            continue;
        }
        if (!ranges.empty() &&
            (!canExtend || record.address < ranges.back().address +
                                             static_cast<duint>(ranges.back().patched.size()))) {
            return std::nullopt;
        }
        ranges.push_back(TrackedPatchRange{record.module, record.address,
                                           {record.original}, {record.patched}});
    }
    return ranges;
}

std::uint64_t TrackedPatchFingerprint(const std::span<const TrackedPatchByte> records) noexcept {
    std::uint64_t hash = 14695981039346656037ULL;
    const auto addByte = [&hash](const unsigned char value) {
        hash ^= value;
        hash *= 1099511628211ULL;
    };
    for (const auto& record : records) {
        for (const unsigned char byte : record.module) addByte(byte);
        addByte(0xffU);
        for (std::size_t shift = 0U; shift < sizeof(record.address) * 8U; shift += 8U) {
            addByte(static_cast<unsigned char>(record.address >> shift));
        }
        addByte(record.original);
        addByte(record.patched);
    }
    return hash;
}

} // namespace mcp
