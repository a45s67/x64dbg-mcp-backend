#include "memory_filters.h"

#include <limits>

namespace mcp {

bool IsExecutableProtection(const DWORD protection) noexcept {
    switch (protection & 0xffU) {
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY: return true;
    default: return false;
    }
}

std::optional<bool> HalfOpenRangesOverlap(const std::uint64_t leftBase,
                                          const std::uint64_t leftSize,
                                          const std::uint64_t rightBase,
                                          const std::uint64_t rightSize) noexcept {
    if (leftSize == 0U || rightSize == 0U) return false;
    if (leftBase > (std::numeric_limits<std::uint64_t>::max)() - leftSize ||
        rightBase > (std::numeric_limits<std::uint64_t>::max)() - rightSize) {
        return std::nullopt;
    }
    return leftBase < rightBase + rightSize && rightBase < leftBase + leftSize;
}

}  // namespace mcp
