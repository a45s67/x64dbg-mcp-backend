#include "patch_policy.h"

#include <array>
#include <algorithm>
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
    std::vector<TrackedPatchByte> records{
        {"sample.exe", 0x1002U, 0x03U, 0xccU},
        {"sample.exe", 0x1000U, 0x01U, 0x90U},
        {"sample.exe", 0x1001U, 0x02U, 0x91U},
        {"sample.exe", 0x2000U, 0x04U, 0x92U},
    };
    const auto normalized = NormalizeTrackedPatches(records);
    assert(normalized && normalized->size() == 2U);
    assert((*normalized)[0].address == 0x1000U);
    assert((*normalized)[0].original == std::vector<unsigned char>({1U, 2U, 3U}));
    assert((*normalized)[0].patched == std::vector<unsigned char>({0x90U, 0x91U, 0xccU}));
    assert((*normalized)[1].address == 0x2000U);
    std::sort(records.begin(), records.end(), [](const auto& left, const auto& right) {
        return left.address < right.address;
    });
    const auto fingerprint = TrackedPatchFingerprint(records);
    (void)fingerprint;
    assert(fingerprint != 0U);
    records.back().patched ^= 1U;
    assert(TrackedPatchFingerprint(records) != fingerprint);
    assert(!NormalizeTrackedPatches({{"sample.exe", 0x1000U, 0x90U, 0x90U}}));
    assert(!NormalizeTrackedPatches({{"sample.exe", 0x1000U, 0x90U, 0xccU},
                                     {"other.exe", 0x1000U, 0x90U, 0xccU}}));
}
