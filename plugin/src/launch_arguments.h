#pragma once

#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace mcp {

constexpr std::size_t kMaxLaunchArguments = 32U;
constexpr std::size_t kMaxLaunchArgumentBytes = 256U;
constexpr std::size_t kMaxLaunchArgumentTotalBytes = 512U;
constexpr std::size_t kMaxRenderedLaunchArgumentBytes = 768U;
constexpr std::size_t kX64dbgCommandBufferBytes = 1024U;

[[nodiscard]] bool ValidLaunchArgument(std::string_view value) noexcept;
[[nodiscard]] std::string QuoteWindowsArgument(std::string_view value);
[[nodiscard]] std::optional<std::string>
RenderWindowsArguments(std::span<const std::string> arguments);
[[nodiscard]] std::string EscapeX64dbgCommandArgument(std::string_view value);
[[nodiscard]] std::optional<std::string>
BuildInitCommand(std::string_view executable, std::string_view commandLine,
                 std::string_view workingDirectory);

} // namespace mcp
