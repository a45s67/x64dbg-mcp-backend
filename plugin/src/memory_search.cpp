#include "memory_search.h"

#include <algorithm>
#include <charconv>

namespace mcp {

std::optional<MemoryPattern> ParseMemoryPattern(const std::string_view patternHex,
                                                const std::string_view mask) {
    if (patternHex.empty() || patternHex.size() > 128U || patternHex.size() % 2U != 0U ||
        mask.size() != patternHex.size() / 2U || mask.empty() || mask.size() > 64U ||
        std::none_of(mask.begin(), mask.end(), [](const char value) { return value == 'x'; }) ||
        !std::all_of(mask.begin(), mask.end(), [](const char value) {
            return value == 'x' || value == '?';
        })) {
        return std::nullopt;
    }

    MemoryPattern pattern;
    pattern.bytes.reserve(mask.size());
    pattern.exact.reserve(mask.size());
    for (std::size_t index = 0U; index < patternHex.size(); index += 2U) {
        unsigned int value = 0U;
        const auto conversion = std::from_chars(patternHex.data() + index,
                                                patternHex.data() + index + 2U, value, 16);
        if (conversion.ec != std::errc{} || conversion.ptr != patternHex.data() + index + 2U ||
            value > 0xffU ||
            !std::all_of(patternHex.begin() + static_cast<std::ptrdiff_t>(index),
                         patternHex.begin() + static_cast<std::ptrdiff_t>(index + 2U),
                         [](const char digit) {
                             return (digit >= '0' && digit <= '9') ||
                                    (digit >= 'a' && digit <= 'f');
                         })) {
            return std::nullopt;
        }
        pattern.bytes.push_back(static_cast<std::uint8_t>(value));
        pattern.exact.push_back(mask[index / 2U] == 'x' ? 1U : 0U);
    }
    return pattern;
}

MemorySearchMatches FindMemoryPattern(const std::span<const std::uint8_t> bytes,
                                      const std::span<const std::uint8_t> readable,
                                      const MemoryPattern& pattern,
                                      const std::size_t candidateCount,
                                      const std::size_t limit) {
    MemorySearchMatches result;
    if (pattern.bytes.empty() || pattern.bytes.size() != pattern.exact.size() ||
        readable.size() != bytes.size() || limit == 0U || candidateCount > bytes.size() ||
        (candidateCount != 0U && pattern.bytes.size() > bytes.size()) ||
        (candidateCount != 0U &&
         candidateCount - 1U > bytes.size() - pattern.bytes.size())) {
        return result;
    }

    result.offsets.reserve((std::min)(candidateCount, limit));
    for (std::size_t candidate = 0U; candidate < candidateCount; ++candidate) {
        bool matched = true;
        for (std::size_t index = 0U; index < pattern.bytes.size(); ++index) {
            if (readable[candidate + index] == 0U ||
                (pattern.exact[index] != 0U && bytes[candidate + index] != pattern.bytes[index])) {
                matched = false;
                break;
            }
        }
        result.nextCandidate = candidate + 1U;
        if (matched) {
            result.offsets.push_back(candidate);
            if (result.offsets.size() == limit) return result;
        }
    }
    return result;
}

}  // namespace mcp
