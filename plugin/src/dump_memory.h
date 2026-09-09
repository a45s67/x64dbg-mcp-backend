#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>

namespace mcp {
struct DumpResult {
    bool complete{false};
    bool outcomeUnknown{false};
    std::size_t bytesWritten{0};
    std::string sha256;
    const char* code{"ACCESS_DENIED"};
    const char* message{"dump was not published"};
};

[[nodiscard]] bool ValidDumpPath(std::wstring_view path) noexcept;
// The reader must fail on any unreadable byte; current verifies the paused generation.
[[nodiscard]] DumpResult DumpMemory(
    const std::wstring& path, std::uint64_t address, std::size_t length, bool overwrite,
    std::chrono::steady_clock::time_point deadline,
    const std::function<bool(std::uint64_t, unsigned char*, std::size_t)>& reader,
    const std::function<bool()>& current);
}
