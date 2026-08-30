#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>

namespace mcp {

struct PeIdentity {
    std::uint16_t machine{0U};
    std::uint16_t optionalMagic{0U};
    std::uint32_t entryRva{0U};
    bool dll{false};
};

[[nodiscard]] std::optional<PeIdentity>
ParsePeIdentity(std::span<const unsigned char> bytes) noexcept;

[[nodiscard]] std::optional<PeIdentity>
ReadPeIdentity(const std::filesystem::path& path) noexcept;

[[nodiscard]] bool PeMatchesBackend(const PeIdentity& identity, bool requireDll) noexcept;

} // namespace mcp
