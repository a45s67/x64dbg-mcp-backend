#include <Windows.h>

#include <atomic>
#include <cstdint>

extern "C" __declspec(dllexport) std::atomic<std::uint32_t> mcp_fixture_marker{0x1234abcdU};
extern "C" __declspec(dllexport) char mcp_fixture_discovery_ascii[] =
    "MCP_DISCOVERY_ASCII_SENTINEL";
extern "C" __declspec(dllexport) wchar_t mcp_fixture_discovery_utf16[] =
    L"MCP_DISCOVERY_UTF16_SENTINEL";

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    while (mcp_fixture_marker.load() != 0U) {
        Sleep(10U);
    }
    return 0;
}
