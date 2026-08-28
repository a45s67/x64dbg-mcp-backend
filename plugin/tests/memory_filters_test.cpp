#include "memory_filters.h"

#include <Windows.h>

#include <cstdint>
#include <iostream>
#include <limits>

int main() {
    bool ok = true;
    ok &= mcp::IsExecutableProtection(PAGE_EXECUTE_READ);
    ok &= mcp::IsExecutableProtection(PAGE_EXECUTE_READWRITE | PAGE_GUARD);
    ok &= !mcp::IsExecutableProtection(PAGE_READWRITE);
    ok &= !mcp::IsExecutableProtection(PAGE_NOACCESS);

    ok &= mcp::HalfOpenRangesOverlap(0x1000U, 0x1000U, 0x1800U, 0x1000U).value_or(false);
    ok &= !mcp::HalfOpenRangesOverlap(0x1000U, 0x1000U, 0x2000U, 0x1000U).value_or(true);
    ok &= !mcp::HalfOpenRangesOverlap(0x1000U, 0U, 0x1000U, 1U).value_or(true);
    ok &= !mcp::HalfOpenRangesOverlap((std::numeric_limits<std::uint64_t>::max)() - 1U,
                                      2U, 0U, 1U)
               .has_value();
    if (!ok) {
        std::cerr << "memory filter tests failed\n";
        return 1;
    }
    return 0;
}
