#include <Windows.h>
#include <shellapi.h>

#include <algorithm>
#include <atomic>
#include <array>
#include <cstdint>
#include <limits>
#include <string>

extern "C" __declspec(dllexport) std::atomic<std::uint32_t> mcp_fixture_marker{0x1234abcdU};
extern "C" __declspec(dllexport) char mcp_fixture_discovery_ascii[] =
    "MCP_DISCOVERY_ASCII_SENTINEL";
extern "C" __declspec(dllexport) wchar_t mcp_fixture_discovery_utf16[] =
    L"MCP_DISCOVERY_UTF16_SENTINEL";

extern "C" __declspec(dllexport) __declspec(noinline) std::uint32_t
mcp_fixture_analysis_target(const std::uint32_t value) {
    return (value ^ 0x5a17c3e9U) + 0x1020304U;
}

namespace {

constexpr wchar_t kArgumentObservationFile[] = L"mcp-argv-observed.bin";
constexpr std::array<std::uint8_t, 8> kArgumentObservationMagic{
    'M', 'A', 'R', 'G', 'V', '1', '\r', '\n'};

bool WriteAll(const HANDLE file, const void* bytes, const std::size_t size) {
    const auto* cursor = static_cast<const std::uint8_t*>(bytes);
    std::size_t remaining = size;
    while (remaining != 0U) {
        const DWORD chunk = static_cast<DWORD>((std::min)(
            remaining, static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())));
        DWORD written = 0U;
        if (!WriteFile(file, cursor, chunk, &written, nullptr) || written == 0U) return false;
        cursor += written;
        remaining -= written;
    }
    return true;
}

bool WriteObservedArguments() {
    int argumentCount = 0;
    LPWSTR* arguments = CommandLineToArgvW(GetCommandLineW(), &argumentCount);
    if (!arguments || argumentCount < 1) return false;

    const HANDLE file = CreateFileW(kArgumentObservationFile, GENERIC_WRITE, 0, nullptr,
                                    CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        LocalFree(arguments);
        return false;
    }

    bool success = WriteAll(file, kArgumentObservationMagic.data(),
                            kArgumentObservationMagic.size());
    const auto count = static_cast<std::uint32_t>(argumentCount);
    success = success && WriteAll(file, &count, sizeof(count));
    for (int index = 0; success && index < argumentCount; ++index) {
        const int wideLength = lstrlenW(arguments[index]);
        const int required = wideLength == 0 ? 0 :
            WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, arguments[index],
                                wideLength, nullptr, 0, nullptr, nullptr);
        if (required < 0 || (wideLength != 0 && required == 0)) {
            success = false;
            break;
        }
        std::string utf8(static_cast<std::size_t>(required), '\0');
        if (required > 0 &&
            WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, arguments[index], wideLength,
                                utf8.data(), required, nullptr, nullptr) != required) {
            success = false;
            break;
        }
        const auto length = static_cast<std::uint32_t>(utf8.size());
        success = WriteAll(file, &length, sizeof(length)) &&
                  WriteAll(file, utf8.data(), utf8.size());
    }
    success = success && FlushFileBuffers(file) != FALSE;
    CloseHandle(file);
    LocalFree(arguments);
    return success;
}

} // namespace

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    if (!WriteObservedArguments()) return 2;
    mcp_fixture_marker.store(mcp_fixture_analysis_target(mcp_fixture_marker.load()));
    while (mcp_fixture_marker.load() != 0U) {
        Sleep(10U);
    }
    return 0;
}
