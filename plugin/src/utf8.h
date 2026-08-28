#pragma once

#include <string>
#include <string_view>

namespace mcp {

// Returns a complete JSON string token. Invalid UTF-8 bytes are represented by U+FFFD.
std::string JsonString(std::string_view value);

// Windows ordinal case-insensitive equality for valid UTF-8. Invalid input never matches.
bool Utf8OrdinalEqualsIgnoreCase(std::string_view left, std::string_view right) noexcept;

}  // namespace mcp
