#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace mcp::control {

struct ServerConfig {
    std::string bind;
    std::uint16_t port{0};
    std::string bearerToken;
};

struct ProfileUpdate {
    std::string text;
    std::string canonicalProfile;
};

[[nodiscard]] std::optional<ServerConfig> ParseServerConfig(
    std::string_view text, std::string& error);

[[nodiscard]] std::optional<ProfileUpdate> SetScyllaHideProfile(
    std::string_view text, std::string_view requestedProfile, std::string& error);

[[nodiscard]] bool IsCanonicalUuid(std::string_view value) noexcept;

} // namespace mcp::control
