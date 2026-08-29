#include "utf8.h"

#include <Windows.h>

#include <algorithm>
#include <limits>
#include <optional>
#include <string>

namespace mcp {
namespace {
constexpr char kReplacement[] = "\xef\xbf\xbd";

bool IsContinuation(const unsigned char byte) { return (byte & 0xc0U) == 0x80U; }

std::size_t ValidSequenceLength(const std::string_view value, const std::size_t offset) {
    const auto first = static_cast<unsigned char>(value[offset]);
    const auto remaining = value.size() - offset;
    if (first <= 0x7fU) {
        return 1U;
    }
    if (first >= 0xc2U && first <= 0xdfU && remaining >= 2U &&
        IsContinuation(static_cast<unsigned char>(value[offset + 1U]))) {
        return 2U;
    }
    if (remaining >= 3U) {
        const auto second = static_cast<unsigned char>(value[offset + 1U]);
        const auto third = static_cast<unsigned char>(value[offset + 2U]);
        const bool secondValid =
            (first == 0xe0U && second >= 0xa0U && second <= 0xbfU) ||
            ((first >= 0xe1U && first <= 0xecU) && IsContinuation(second)) ||
            (first == 0xedU && second >= 0x80U && second <= 0x9fU) ||
            ((first >= 0xeeU && first <= 0xefU) && IsContinuation(second));
        if (secondValid && IsContinuation(third)) {
            return 3U;
        }
    }
    if (remaining >= 4U) {
        const auto second = static_cast<unsigned char>(value[offset + 1U]);
        const auto third = static_cast<unsigned char>(value[offset + 2U]);
        const auto fourth = static_cast<unsigned char>(value[offset + 3U]);
        const bool secondValid =
            (first == 0xf0U && second >= 0x90U && second <= 0xbfU) ||
            ((first >= 0xf1U && first <= 0xf3U) && IsContinuation(second)) ||
            (first == 0xf4U && second >= 0x80U && second <= 0x8fU);
        if (secondValid && IsContinuation(third) && IsContinuation(fourth)) {
            return 4U;
        }
    }
    return 0U;
}

void AppendAsciiJsonEscape(std::string& output, const unsigned char byte) {
    constexpr char digits[] = "0123456789abcdef";
    switch (byte) {
        case '"': output += "\\\""; break;
        case '\\': output += "\\\\"; break;
        case '\b': output += "\\b"; break;
        case '\f': output += "\\f"; break;
        case '\n': output += "\\n"; break;
        case '\r': output += "\\r"; break;
        case '\t': output += "\\t"; break;
        default:
            if (byte < 0x20U) {
                output += "\\u00";
                output.push_back(digits[byte >> 4U]);
                output.push_back(digits[byte & 0x0fU]);
            } else {
                output.push_back(static_cast<char>(byte));
            }
    }
}

std::optional<std::wstring> ToWide(const std::string_view value) {
    if (value.empty() || value.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        return std::nullopt;
    }
    const int inputLength = static_cast<int>(value.size());
    const int required = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                                              inputLength, nullptr, 0);
    if (required <= 0) {
        return std::nullopt;
    }
    std::wstring output(static_cast<std::size_t>(required), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), inputLength,
                            output.data(), required) != required) {
        return std::nullopt;
    }
    return output;
}
}  // namespace

std::string JsonString(const std::string_view value) {
    std::string result;
    result.reserve(value.size() + 2U);
    result.push_back('"');
    for (std::size_t offset = 0; offset < value.size();) {
        const auto byte = static_cast<unsigned char>(value[offset]);
        if (byte <= 0x7fU) {
            AppendAsciiJsonEscape(result, byte);
            ++offset;
            continue;
        }
        const std::size_t sequenceLength = ValidSequenceLength(value, offset);
        if (sequenceLength == 0U) {
            result.append(kReplacement, sizeof(kReplacement) - 1U);
            ++offset;
            continue;
        }
        result.append(value.data() + offset, sequenceLength);
        offset += sequenceLength;
    }
    result.push_back('"');
    return result;
}

bool IsValidUtf8(const std::string_view value) noexcept {
    for (std::size_t offset = 0; offset < value.size();) {
        const std::size_t length = ValidSequenceLength(value, offset);
        if (length == 0U) return false;
        offset += length;
    }
    return true;
}

std::size_t Utf8SequenceLength(const std::string_view value,
                               const std::size_t offset) noexcept {
    return offset < value.size() ? ValidSequenceLength(value, offset) : 0U;
}

bool Utf8OrdinalEqualsIgnoreCase(const std::string_view left,
                                 const std::string_view right) noexcept {
    try {
        const auto wideLeft = ToWide(left);
        const auto wideRight = ToWide(right);
        if (!wideLeft || !wideRight) {
            return false;
        }
        return CompareStringOrdinal(wideLeft->data(), static_cast<int>(wideLeft->size()),
                                    wideRight->data(), static_cast<int>(wideRight->size()), TRUE) ==
               CSTR_EQUAL;
    } catch (...) {
        return false;
    }
}

bool Utf8OrdinalContainsIgnoreCase(const std::string_view haystack,
                                   const std::string_view needle) noexcept {
    return Utf8OrdinalMatchIgnoreCase(haystack, needle).has_value();
}

std::optional<std::size_t> Utf8OrdinalFindIgnoreCase(const std::string_view haystack,
                                                     const std::string_view needle) noexcept {
    const auto match = Utf8OrdinalMatchIgnoreCase(haystack, needle);
    return match ? std::optional<std::size_t>(match->offset) : std::nullopt;
}

std::optional<Utf8LiteralMatch> Utf8OrdinalMatchIgnoreCase(
    const std::string_view haystack, const std::string_view needle) noexcept {
    if (needle.empty()) return Utf8LiteralMatch{};
    try {
        const auto wideHaystack = ToWide(haystack);
        const auto wideNeedle = ToWide(needle);
        if (!wideHaystack || !wideNeedle) return std::nullopt;
        int foundLength = 0;
        const int found = FindNLSStringEx(
            LOCALE_NAME_INVARIANT, FIND_FROMSTART | NORM_IGNORECASE, wideHaystack->data(),
            static_cast<int>(wideHaystack->size()), wideNeedle->data(),
            static_cast<int>(wideNeedle->size()), &foundLength, nullptr, nullptr, 0);
        if (found < 0 || foundLength <= 0) return std::nullopt;
        const int prefixBytes = found == 0
                                    ? 0
                                    : WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                                                          wideHaystack->data(), found, nullptr, 0,
                                                          nullptr, nullptr);
        const int matchBytes = WideCharToMultiByte(
            CP_UTF8, WC_ERR_INVALID_CHARS, wideHaystack->data() + found, foundLength, nullptr, 0,
            nullptr, nullptr);
        if (prefixBytes < 0 || matchBytes <= 0) return std::nullopt;
        return Utf8LiteralMatch{static_cast<std::size_t>(prefixBytes),
                                static_cast<std::size_t>(matchBytes)};
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<Utf8MatchContext> Utf8ContextAroundMatch(
    const std::string_view value, const Utf8LiteralMatch match,
    const std::size_t contextBytes) noexcept {
    constexpr std::size_t kMaxContextBytes = 128U;
    constexpr std::size_t kMaxMatchBytes = 1024U;
    if (contextBytes > kMaxContextBytes || match.length > kMaxMatchBytes ||
        match.offset > value.size() || match.length > value.size() - match.offset ||
        !IsValidUtf8(value) || !IsValidUtf8(value.substr(match.offset, match.length))) {
        return std::nullopt;
    }
    try {
        std::size_t start = match.offset > contextBytes ? match.offset - contextBytes : 0U;
        while (start < match.offset &&
               (static_cast<unsigned char>(value[start]) & 0xc0U) == 0x80U) {
            ++start;
        }
        const std::size_t matchEnd = match.offset + match.length;
        std::size_t end = (std::min)(value.size(), matchEnd + contextBytes);
        while (end > matchEnd && !IsValidUtf8(value.substr(matchEnd, end - matchEnd))) --end;

        Utf8MatchContext result;
        result.before.assign(value.substr(start, match.offset - start));
        result.match.assign(value.substr(match.offset, match.length));
        result.after.assign(value.substr(matchEnd, end - matchEnd));
        result.text.reserve(result.before.size() + result.match.size() + result.after.size());
        result.text.append(result.before).append(result.match).append(result.after);
        result.textOffset = start;
        result.truncated = start != 0U || end != value.size();
        return result;
    } catch (...) {
        return std::nullopt;
    }
}

}  // namespace mcp
