#pragma once

#include <Windows.h>

#include <cstdint>
#include <optional>

namespace mcp {

bool IsExecutableProtection(DWORD protection) noexcept;

// Returns nullopt when either half-open range would overflow.
std::optional<bool> HalfOpenRangesOverlap(std::uint64_t leftBase, std::uint64_t leftSize,
                                          std::uint64_t rightBase,
                                          std::uint64_t rightSize) noexcept;

}  // namespace mcp
