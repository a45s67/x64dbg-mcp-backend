#pragma once

#include <optional>
#include <string>
#include <string_view>

namespace mcp {

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

}  // namespace mcp
