#include "patch_policy.h"

#include <array>
#include <cassert>
#include <limits>

int main() {
    using namespace mcp;
    assert(SafeInstruction("xor eax, eax"));
    assert(!SafeInstruction("nop; run"));
    assert(!SafeInstruction("nop\nrun"));
    assert(ParsePatchBytes("90cc") == std::vector<unsigned char>({0x90U, 0xccU}));
    assert(!ParsePatchBytes("90CC"));
    assert(!ParsePatchBytes("9"));
    const std::array<unsigned char, 1> assembled{0xccU};
    const std::array<unsigned char, 3> expected{0x48U, 0x31U, 0xc0U};
    assert(!PreparePatchBytes(assembled, expected, false));
    const auto padded = PreparePatchBytes(assembled, expected, true);
    assert(padded == std::vector<unsigned char>({0xccU, 0x90U, 0x90U}));
    assert(PatchRangeValid(0x1000U, 16U));
    assert(!PatchRangeValid(std::numeric_limits<duint>::max(), 2U));
    DBGPATCHINFO record{};
    record.addr = 0x1000U;
    record.oldbyte = 0x48U;
    record.newbyte = 0xccU;
    assert(PatchRecordMatches(record, 0x1000U, 0x48U, 0xccU));
    assert(!PatchRecordMatches(record, 0x1000U, 0x49U, 0xccU));
}
