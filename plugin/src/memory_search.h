#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace mcp {

struct MemoryPattern {
    std::vector<std::uint8_t> bytes;
    std::vector<std::uint8_t> exact;
};

struct MemorySearchMatches {
    std::vector<std::size_t> offsets;
    std::size_t nextCandidate{0U};
};

std::optional<MemoryPattern> ParseMemoryPattern(std::string_view patternHex,
                                                std::string_view mask);

MemorySearchMatches FindMemoryPattern(std::span<const std::uint8_t> bytes,
                                      std::span<const std::uint8_t> readable,
                                      const MemoryPattern& pattern,
                                      std::size_t candidateCount,
                                      std::size_t limit);

}  // namespace mcp
