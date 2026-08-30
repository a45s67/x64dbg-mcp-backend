#include <Windows.h>

extern "C" __declspec(dllexport) volatile LONG mcp_dll_fixture_marker = 0;

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) InterlockedExchange(&mcp_dll_fixture_marker, 1L);
    return TRUE;
}
