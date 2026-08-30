#include "pe_policy.h"

#include <array>
#include <cstdint>
#include <iostream>

namespace {
std::array<unsigned char, 512> Pe(const std::uint16_t machine,
                                  const std::uint16_t magic, const bool dll) {
    std::array<unsigned char, 512> bytes{};
    bytes[0] = 'M'; bytes[1] = 'Z'; bytes[0x3c] = 0x80U;
    bytes[0x80] = 'P'; bytes[0x81] = 'E';
    bytes[0x84] = static_cast<unsigned char>(machine);
    bytes[0x85] = static_cast<unsigned char>(machine >> 8U);
    bytes[0x94] = 0xf0U;
    if (dll) bytes[0x97] = 0x20U;
    bytes[0x98] = static_cast<unsigned char>(magic);
    bytes[0x99] = static_cast<unsigned char>(magic >> 8U);
    bytes[0xa8] = 0x34U; bytes[0xa9] = 0x12U;
    return bytes;
}
}

int main() {
#ifdef _WIN64
    constexpr std::uint16_t machine = 0x8664U;
    constexpr std::uint16_t otherMachine = 0x014cU;
    constexpr std::uint16_t magic = 0x020bU;
    constexpr std::uint16_t otherMagic = 0x010bU;
#else
    constexpr std::uint16_t machine = 0x014cU;
    constexpr std::uint16_t otherMachine = 0x8664U;
    constexpr std::uint16_t magic = 0x010bU;
    constexpr std::uint16_t otherMagic = 0x020bU;
#endif
    const auto dll = mcp::ParsePeIdentity(Pe(machine, magic, true));
    const auto exe = mcp::ParsePeIdentity(Pe(machine, magic, false));
    if (!dll || !dll->dll || dll->entryRva != 0x1234U ||
        !mcp::PeMatchesBackend(*dll, true) || mcp::PeMatchesBackend(*dll, false) ||
        !exe || !mcp::PeMatchesBackend(*exe, false)) return 1;
    const auto wrongMachine = mcp::ParsePeIdentity(Pe(otherMachine, magic, true));
    const auto wrongMagic = mcp::ParsePeIdentity(Pe(machine, otherMagic, true));
    if (!wrongMachine || mcp::PeMatchesBackend(*wrongMachine, true) ||
        !wrongMagic || mcp::PeMatchesBackend(*wrongMagic, true)) return 2;
    auto bad = Pe(machine, magic, true);
    bad[0] = 0U;
    if (mcp::ParsePeIdentity(bad) || mcp::ParsePeIdentity(
            std::span<const unsigned char>(bad.data(), 32U))) return 3;
    bad = Pe(machine, magic, true);
    bad[0x3c] = 0xffU; bad[0x3d] = 0xffU; bad[0x3e] = 0xffU; bad[0x3f] = 0x7fU;
    if (mcp::ParsePeIdentity(bad)) return 4;
    return 0;
}
