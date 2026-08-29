#pragma once

#include <optional>
#include <string>
#include <string_view>

namespace mcp {

struct Utf8LiteralMatch {
    std::size_t offset{0};
    std::size_t length{0};
};

struct Utf8MatchContext {
    std::string before;
    std::string match;
    std::string after;
    std::string text;
    std::size_t textOffset{0};
    bool truncated{false};
};

// Returns a complete JSON string token. Invalid UTF-8 bytes are represented by U+FFFD.
std::string JsonString(std::string_view value);

bool IsValidUtf8(std::string_view value) noexcept;

// Returns the valid sequence length at offset, or zero for invalid/out-of-range input.
std::size_t Utf8SequenceLength(std::string_view value, std::size_t offset) noexcept;

// Windows ordinal case-insensitive equality for valid UTF-8. Invalid input never matches.
bool Utf8OrdinalEqualsIgnoreCase(std::string_view left, std::string_view right) noexcept;

// Windows invariant literal substring search for valid UTF-8. An empty needle matches.
bool Utf8OrdinalContainsIgnoreCase(std::string_view haystack, std::string_view needle) noexcept;

// Returns the UTF-8 byte offset of an invariant case-insensitive literal match.
std::optional<std::size_t> Utf8OrdinalFindIgnoreCase(std::string_view haystack,
                                                     std::string_view needle) noexcept;

// Returns the exact UTF-8 byte span selected by Windows invariant case folding.
std::optional<Utf8LiteralMatch> Utf8OrdinalMatchIgnoreCase(
    std::string_view haystack, std::string_view needle) noexcept;

// Builds valid UTF-8 context with at most contextBytes on each side of match.
std::optional<Utf8MatchContext> Utf8ContextAroundMatch(
    std::string_view value, Utf8LiteralMatch match, std::size_t contextBytes) noexcept;

}  // namespace mcp
