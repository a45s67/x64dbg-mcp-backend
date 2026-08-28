#include <Windows.h>

#include <atomic>
#include <cstdint>

extern "C" __declspec(dllexport) std::atomic<std::uint32_t> mcp_fixture_marker{0x1234abcdU};

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    while (mcp_fixture_marker.load() != 0U) {
        Sleep(10U);
    }
    return 0;
}
