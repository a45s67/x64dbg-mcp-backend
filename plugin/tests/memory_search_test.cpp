#include "memory_search.h"

#include <cassert>
#include <cstdint>
#include <vector>

int main() {
    using mcp::FindMemoryPattern;
    using mcp::ParseMemoryPattern;

    assert(!ParseMemoryPattern("", ""));
    assert(!ParseMemoryPattern("4D5A", "xx"));
    assert(!ParseMemoryPattern("4d5", "xx"));
    assert(!ParseMemoryPattern("4d5a", "x"));
    assert(!ParseMemoryPattern("4d5a", "??"));
    const auto exact = ParseMemoryPattern("4141", "xx");
    const auto wildcard = ParseMemoryPattern("4100", "x?");
    assert(exact && wildcard);

    const std::vector<std::uint8_t> bytes{'A', 'A', 'A', 'B', 'A', 'Z'};
    const std::vector<std::uint8_t> readable(bytes.size(), 1U);
    const auto overlapping = FindMemoryPattern(bytes, readable, *exact, 5U, 10U);
    assert((overlapping.offsets == std::vector<std::size_t>{0U, 1U}));
    assert(overlapping.nextCandidate == 5U);

    const auto masked = FindMemoryPattern(bytes, readable, *wildcard, 5U, 10U);
    assert((masked.offsets == std::vector<std::size_t>{0U, 1U, 2U, 4U}));

    auto gap = readable;
    gap[1] = 0U;
    const auto unreadable = FindMemoryPattern(bytes, gap, *exact, 5U, 10U);
    assert(unreadable.offsets.empty());

    const auto capped = FindMemoryPattern(bytes, readable, *wildcard, 5U, 2U);
    assert((capped.offsets == std::vector<std::size_t>{0U, 1U}));
    assert(capped.nextCandidate == 2U);

    const std::vector<std::uint8_t> boundary{'x', 'M', 'Z', 'y'};
    const std::vector<std::uint8_t> boundaryReadable(boundary.size(), 1U);
    const auto mz = ParseMemoryPattern("4d5a", "xx");
    assert(mz);
    const auto across = FindMemoryPattern(boundary, boundaryReadable, *mz, 3U, 10U);
    assert((across.offsets == std::vector<std::size_t>{1U}));

    return 0;
}
