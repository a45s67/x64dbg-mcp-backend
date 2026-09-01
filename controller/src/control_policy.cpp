#include "control_policy.h"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <limits>
#include <vector>

namespace mcp::control {
namespace {

std::string_view Trim(std::string_view value) {
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
        value.remove_prefix(1U);
    }
    while (!value.empty() &&
           (value.back() == ' ' || value.back() == '\t' || value.back() == '\r')) {
        value.remove_suffix(1U);
    }
    return value;
}

bool HasControl(const std::string_view value) {
    return std::any_of(value.begin(), value.end(), [](const unsigned char byte) {
        return byte < 0x20U || byte == 0x7fU;
    });
}

std::optional<std::string> QuotedValue(const std::string_view value) {
    const std::string_view trimmed = Trim(value);
    if (trimmed.size() < 2U || trimmed.front() != '"' || trimmed.back() != '"') {
        return std::nullopt;
    }
    const std::string_view body = trimmed.substr(1U, trimmed.size() - 2U);
    if (body.empty() || body.find('"') != std::string_view::npos || HasControl(body)) {
        return std::nullopt;
    }
    return std::string(body);
}

bool EqualInsensitive(const std::string_view left, const std::string_view right) {
    return left.size() == right.size() &&
           std::equal(left.begin(), left.end(), right.begin(), [](const char a, const char b) {
               return std::tolower(static_cast<unsigned char>(a)) ==
                      std::tolower(static_cast<unsigned char>(b));
           });
}

struct Line {
    std::size_t begin{0U};
    std::size_t contentEnd{0U};
    std::size_t end{0U};
};

std::vector<Line> Lines(const std::string_view text) {
    std::vector<Line> result;
    std::size_t begin = 0U;
    while (begin < text.size()) {
        const std::size_t newline = text.find('\n', begin);
        const std::size_t end = newline == std::string_view::npos ? text.size() : newline + 1U;
        std::size_t contentEnd = newline == std::string_view::npos ? text.size() : newline;
        if (contentEnd > begin && text[contentEnd - 1U] == '\r') --contentEnd;
        result.push_back({begin, contentEnd, end});
        begin = end;
    }
    if (text.empty()) result.push_back({0U, 0U, 0U});
    return result;
}

} // namespace

std::optional<ServerConfig> ParseServerConfig(const std::string_view text,
                                              std::string& error) {
    error.clear();
    if (text.empty() || text.size() > 64U * 1024U || text.find('\0') != std::string_view::npos) {
        error = "server config is empty or exceeds its bound";
        return std::nullopt;
    }
    std::optional<std::string> bind;
    std::optional<std::uint16_t> port;
    std::optional<std::string> token;
    for (const Line line : Lines(text)) {
        const std::string_view content = Trim(text.substr(line.begin, line.contentEnd - line.begin));
        if (content.empty() || content.front() == '#') continue;
        const std::size_t separator = content.find('=');
        if (separator == std::string_view::npos) {
            error = "server config contains a malformed line";
            return std::nullopt;
        }
        const std::string_view key = Trim(content.substr(0U, separator));
        const std::string_view value = Trim(content.substr(separator + 1U));
        if (key == "bind") {
            if (bind) {
                error = "server config repeats bind";
                return std::nullopt;
            }
            bind = QuotedValue(value);
            if (!bind || *bind != "127.0.0.1") {
                error = "controller requires bind 127.0.0.1";
                return std::nullopt;
            }
        } else if (key == "port") {
            if (port) {
                error = "server config repeats port";
                return std::nullopt;
            }
            unsigned int parsed = 0U;
            const auto conversion =
                std::from_chars(value.data(), value.data() + value.size(), parsed, 10);
            if (conversion.ec != std::errc{} || conversion.ptr != value.data() + value.size() ||
                parsed == 0U || parsed > std::numeric_limits<std::uint16_t>::max()) {
                error = "server config port is invalid";
                return std::nullopt;
            }
            port = static_cast<std::uint16_t>(parsed);
        } else if (key == "bearer_token") {
            if (token) {
                error = "server config repeats bearer_token";
                return std::nullopt;
            }
            token = QuotedValue(value);
            if (!token || token->size() < 32U || token->size() > 4096U) {
                error = "server config bearer_token is invalid";
                return std::nullopt;
            }
        } else {
            error = "server config contains an unknown field";
            return std::nullopt;
        }
    }
    if (!bind || !port || !token) {
        error = "server config is missing a required field";
        return std::nullopt;
    }
    return ServerConfig{std::move(*bind), *port, std::move(*token)};
}

std::optional<ProfileUpdate> SetScyllaHideProfile(const std::string_view text,
                                                  const std::string_view requestedProfile,
                                                  std::string& error) {
    error.clear();
    if (text.empty() || text.size() > 1024U * 1024U || text.find('\0') != std::string_view::npos) {
        error = "ScyllaHide config is empty or exceeds its bound";
        return std::nullopt;
    }
    if (requestedProfile.empty() || requestedProfile.size() > 128U ||
        HasControl(requestedProfile) || requestedProfile.front() == '[' ||
        requestedProfile.find(']') != std::string_view::npos) {
        error = "profile name is invalid";
        return std::nullopt;
    }
    const std::vector<Line> lines = Lines(text);
    std::string currentSection;
    std::optional<Line> currentProfileLine;
    std::optional<std::string> canonicalProfile;
    for (const Line line : lines) {
        const std::string_view content = Trim(text.substr(line.begin, line.contentEnd - line.begin));
        if (content.size() >= 2U && content.front() == '[' && content.back() == ']') {
            currentSection.assign(content.substr(1U, content.size() - 2U));
            if (EqualInsensitive(currentSection, requestedProfile)) {
                canonicalProfile = currentSection;
            }
            continue;
        }
        if (EqualInsensitive(currentSection, "SETTINGS")) {
            const std::size_t separator = content.find('=');
            if (separator != std::string_view::npos &&
                EqualInsensitive(Trim(content.substr(0U, separator)), "CurrentProfile")) {
                if (currentProfileLine) {
                    error = "ScyllaHide config repeats CurrentProfile";
                    return std::nullopt;
                }
                currentProfileLine = line;
            }
        }
    }
    if (!canonicalProfile) {
        error = "requested ScyllaHide profile section does not exist";
        return std::nullopt;
    }
    if (!currentProfileLine) {
        error = "ScyllaHide SETTINGS.CurrentProfile is missing";
        return std::nullopt;
    }
    const std::string replacement = "CurrentProfile=" + *canonicalProfile;
    std::string updated;
    updated.reserve(text.size() + replacement.size());
    updated.append(text.substr(0U, currentProfileLine->begin));
    updated.append(replacement);
    updated.append(text.substr(currentProfileLine->contentEnd));
    return ProfileUpdate{std::move(updated), std::move(*canonicalProfile)};
}

std::optional<ScyllaHideConfig> ParseScyllaHideConfig(const std::string_view text,
                                                       std::string& error) {
    error.clear();
    if (text.empty() || text.size() > 1024U * 1024U || text.find('\0') != std::string_view::npos) {
        error = "ScyllaHide config is empty or exceeds its bound";
        return std::nullopt;
    }
    std::string currentSection;
    std::optional<std::string> currentProfile;
    std::vector<std::string> profiles;
    for (const Line line : Lines(text)) {
        const std::string_view content = Trim(text.substr(line.begin, line.contentEnd - line.begin));
        if (content.size() >= 2U && content.front() == '[' && content.back() == ']') {
            currentSection.assign(content.substr(1U, content.size() - 2U));
            if (!EqualInsensitive(currentSection, "SETTINGS")) {
                if (currentSection.empty() || currentSection.size() > 128U ||
                    profiles.size() >= 128U || HasControl(currentSection)) {
                    error = "ScyllaHide profile catalog exceeds its bound";
                    return std::nullopt;
                }
                profiles.push_back(currentSection);
            }
            continue;
        }
        if (EqualInsensitive(currentSection, "SETTINGS")) {
            const std::size_t separator = content.find('=');
            if (separator != std::string_view::npos &&
                EqualInsensitive(Trim(content.substr(0U, separator)), "CurrentProfile")) {
                if (currentProfile) {
                    error = "ScyllaHide config repeats CurrentProfile";
                    return std::nullopt;
                }
                currentProfile = std::string(Trim(content.substr(separator + 1U)));
            }
        }
    }
    if (!currentProfile || currentProfile->empty()) {
        error = "ScyllaHide SETTINGS.CurrentProfile is missing";
        return std::nullopt;
    }
    const auto selected = std::find_if(profiles.begin(), profiles.end(), [&](const auto& profile) {
        return EqualInsensitive(profile, *currentProfile);
    });
    if (selected == profiles.end()) {
        error = "ScyllaHide CurrentProfile does not name an available profile";
        return std::nullopt;
    }
    return ScyllaHideConfig{*selected, std::move(profiles)};
}

bool IsCanonicalUuid(const std::string_view value) noexcept {
    if (value.size() != 36U) return false;
    for (std::size_t index = 0U; index < value.size(); ++index) {
        if (index == 8U || index == 13U || index == 18U || index == 23U) {
            if (value[index] != '-') return false;
        } else if (!((value[index] >= '0' && value[index] <= '9') ||
                     (value[index] >= 'a' && value[index] <= 'f'))) {
            return false;
        }
    }
    return true;
}

} // namespace mcp::control
