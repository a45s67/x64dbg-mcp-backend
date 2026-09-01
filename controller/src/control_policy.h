#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

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

struct ScyllaHideConfig {
    std::string currentProfile;
    std::vector<std::string> availableProfiles;
};

[[nodiscard]] std::optional<ServerConfig> ParseServerConfig(
    std::string_view text, std::string& error);

[[nodiscard]] std::optional<ProfileUpdate> SetScyllaHideProfile(
    std::string_view text, std::string_view requestedProfile, std::string& error);

[[nodiscard]] std::optional<ScyllaHideConfig> ParseScyllaHideConfig(
    std::string_view text, std::string& error);

[[nodiscard]] bool IsCanonicalUuid(std::string_view value) noexcept;

} // namespace mcp::control
