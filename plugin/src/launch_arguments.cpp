#include "launch_arguments.h"

#include <Windows.h>

#include <cctype>
#include <limits>

namespace mcp {

bool ValidLaunchArgument(const std::string_view value) noexcept {
    if (value.size() > kMaxLaunchArgumentBytes ||
        value.size() > static_cast<std::size_t>((std::numeric_limits<int>::max)())) {
        return false;
    }
    if (value.empty()) return true;
    const int sourceSize = static_cast<int>(value.size());
    const int required = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                                             sourceSize, nullptr, 0);
    if (required <= 0) return false;
    std::wstring decoded(static_cast<std::size_t>(required), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), sourceSize,
                            decoded.data(), required) != required) {
        return false;
    }
    for (const wchar_t character : decoded) {
        const auto code = static_cast<unsigned int>(character);
        if (code <= 0x1fU || (code >= 0x7fU && code <= 0x9fU)) return false;
    }
    return true;
}

std::string QuoteWindowsArgument(const std::string_view value) {
    std::string result;
    result.reserve(value.size() + 2U);
    result.push_back('"');
    std::size_t backslashes = 0U;
    for (const char character : value) {
        if (character == '\\') {
            ++backslashes;
            continue;
        }
        if (character == '"') {
            result.append(backslashes * 2U + 1U, '\\');
            result.push_back('"');
        } else {
            result.append(backslashes, '\\');
            result.push_back(character);
        }
        backslashes = 0U;
    }
    result.append(backslashes * 2U, '\\');
    result.push_back('"');
    return result;
}

std::optional<std::string>
RenderWindowsArguments(const std::span<const std::string> arguments) {
    if (arguments.size() > kMaxLaunchArguments) return std::nullopt;
    std::size_t inputBytes = 0U;
    std::string result;
    for (const auto& argument : arguments) {
        if (!ValidLaunchArgument(argument) ||
            argument.size() > kMaxLaunchArgumentTotalBytes - inputBytes) {
            return std::nullopt;
        }
        inputBytes += argument.size();
        const std::string quoted = QuoteWindowsArgument(argument);
        if (!result.empty()) result.push_back(' ');
        result += quoted;
        if (result.size() > kMaxRenderedLaunchArgumentBytes) return std::nullopt;
    }
    return result;
}

std::string EscapeX64dbgCommandArgument(const std::string_view value) {
    std::string result;
    result.reserve(value.size());
    for (const char character : value) {
        if (character == '\\' || character == '"') result.push_back('\\');
        result.push_back(character);
    }
    return result;
}

bool HasPifExtension(const std::string_view path) noexcept {
    const std::size_t separator = path.find_last_of("/\\");
    const std::size_t dot = path.find_last_of('.');
    if (dot == std::string_view::npos ||
        (separator != std::string_view::npos && dot < separator)) {
        return false;
    }
    const std::string_view extension = path.substr(dot);
    return extension.size() == 4U && extension[0] == '.' &&
           std::tolower(static_cast<unsigned char>(extension[1])) == 'p' &&
           std::tolower(static_cast<unsigned char>(extension[2])) == 'i' &&
           std::tolower(static_cast<unsigned char>(extension[3])) == 'f';
}

std::optional<std::string>
BuildInitCommand(const std::string_view executable, const std::string_view commandLine,
                 const std::string_view workingDirectory) {
    std::string result = "scriptcmd init \"" + EscapeX64dbgCommandArgument(executable) +
                         "\", \"" + EscapeX64dbgCommandArgument(commandLine) +
                         "\", \"" + EscapeX64dbgCommandArgument(workingDirectory) + "\"";
    if (result.size() >= kX64dbgCommandBufferBytes) return std::nullopt;
    return result;
}

} // namespace mcp
