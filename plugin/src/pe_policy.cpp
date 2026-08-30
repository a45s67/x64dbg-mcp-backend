#include "pe_policy.h"

#include <algorithm>
#include <fstream>
#include <limits>
#include <vector>

namespace mcp {
namespace {
constexpr std::size_t kDosOffset = 0x3cU;
constexpr std::size_t kMaxHeaderOffset = 1024U * 1024U;
constexpr std::size_t kHeaderSlack = 512U;
constexpr std::uint16_t kMachineI386 = 0x014cU;
constexpr std::uint16_t kMachineAmd64 = 0x8664U;
constexpr std::uint16_t kMagicPe32 = 0x010bU;
constexpr std::uint16_t kMagicPe32Plus = 0x020bU;
constexpr std::uint16_t kDllCharacteristic = 0x2000U;

std::uint16_t U16(const std::span<const unsigned char> bytes,
                  const std::size_t offset) noexcept {
    return static_cast<std::uint16_t>(bytes[offset]) |
           static_cast<std::uint16_t>(bytes[offset + 1U] << 8U);
}

std::uint32_t U32(const std::span<const unsigned char> bytes,
                  const std::size_t offset) noexcept {
    return static_cast<std::uint32_t>(bytes[offset]) |
           (static_cast<std::uint32_t>(bytes[offset + 1U]) << 8U) |
           (static_cast<std::uint32_t>(bytes[offset + 2U]) << 16U) |
           (static_cast<std::uint32_t>(bytes[offset + 3U]) << 24U);
}
} // namespace

std::optional<PeIdentity>
ParsePeIdentity(const std::span<const unsigned char> bytes) noexcept {
    if (bytes.size() < 64U || bytes[0] != 'M' || bytes[1] != 'Z') return std::nullopt;
    const std::uint32_t ntOffset = U32(bytes, kDosOffset);
    constexpr std::size_t kRequiredAfterNt = 24U + 20U;
    if (ntOffset < 64U || ntOffset > kMaxHeaderOffset ||
        ntOffset > bytes.size() || bytes.size() - ntOffset < kRequiredAfterNt) {
        return std::nullopt;
    }
    const std::size_t nt = static_cast<std::size_t>(ntOffset);
    if (bytes[nt] != 'P' || bytes[nt + 1U] != 'E' || bytes[nt + 2U] != 0U ||
        bytes[nt + 3U] != 0U) return std::nullopt;
    const std::uint16_t optionalSize = U16(bytes, nt + 20U);
    if (optionalSize < 20U || bytes.size() - nt < 24U + optionalSize) return std::nullopt;
    return PeIdentity{U16(bytes, nt + 4U), U16(bytes, nt + 24U),
                      U32(bytes, nt + 24U + 16U),
                      (U16(bytes, nt + 22U) & kDllCharacteristic) != 0U};
}

std::optional<PeIdentity> ReadPeIdentity(const std::filesystem::path& path) noexcept {
    try {
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file) return std::nullopt;
        const std::streamoff size = file.tellg();
        if (size < 64) return std::nullopt;
        const auto cap = static_cast<std::streamoff>(kMaxHeaderOffset + kHeaderSlack);
        const std::size_t bounded = size > cap
                                        ? kMaxHeaderOffset + kHeaderSlack
                                        : static_cast<std::size_t>(size);
        std::vector<unsigned char> bytes(bounded);
        file.seekg(0, std::ios::beg);
        if (!file.read(reinterpret_cast<char*>(bytes.data()),
                       static_cast<std::streamsize>(bytes.size()))) return std::nullopt;
        return ParsePeIdentity(bytes);
    } catch (...) {
        return std::nullopt;
    }
}

bool PeMatchesBackend(const PeIdentity& identity, const bool requireDll) noexcept {
    if (identity.dll != requireDll) return false;
#ifdef _WIN64
    return identity.machine == kMachineAmd64 && identity.optionalMagic == kMagicPe32Plus;
#else
    return identity.machine == kMachineI386 && identity.optionalMagic == kMagicPe32;
#endif
}

} // namespace mcp
