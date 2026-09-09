#include <Windows.h>
#include <shellapi.h>

#include <algorithm>
#include <atomic>
#include <array>
#include <cstdint>
#include <limits>
#include <string>

extern "C" __declspec(dllexport) std::atomic<std::uint32_t> mcp_fixture_marker{0x1234abcdU};
extern "C" __declspec(dllexport) std::atomic<std::uint32_t> mcp_fixture_exception_trigger{0U};
extern "C" __declspec(dllexport) std::atomic<std::uint32_t> mcp_fixture_access_violation_trigger{0U};
extern "C" __declspec(dllexport) std::atomic<std::uint32_t> mcp_fixture_recovery_observed{0U};
extern "C" __declspec(dllexport) volatile std::uint32_t* mcp_fixture_invalid_pointer = nullptr;
extern "C" __declspec(dllexport) std::atomic<std::uint32_t> mcp_fixture_worker_ready{0U};
extern "C" __declspec(dllexport) std::atomic<std::uint32_t> mcp_fixture_main_thread_id{0U};
extern "C" __declspec(dllexport) std::atomic<std::uint32_t> mcp_fixture_worker_thread_id{0U};
extern "C" __declspec(dllexport) std::atomic<std::uint32_t> mcp_fixture_trace_wait_trigger{0U};
extern "C" __declspec(dllexport) std::atomic<std::uint32_t> mcp_fixture_trace_wait_release{0U};
extern "C" __declspec(dllexport) std::atomic<std::uint32_t> mcp_fixture_trace_wait_observed{0U};
extern "C" __declspec(dllexport) char mcp_fixture_discovery_ascii[] =
    "MCP_DISCOVERY_ASCII_SENTINEL";
extern "C" __declspec(dllexport) wchar_t mcp_fixture_discovery_utf16[] =
    L"MCP_DISCOVERY_UTF16_SENTINEL";

extern "C" __declspec(dllexport) __declspec(noinline) std::uint32_t
mcp_fixture_analysis_target(const std::uint32_t value) {
    return (value ^ 0x5a17c3e9U) + 0x1020304U;
}

extern "C" __declspec(dllexport) __declspec(noinline) std::uint32_t
mcp_fixture_run_to_interrupter(const std::uint32_t value) {
    return value ^ 1U;
}

extern "C" __declspec(dllexport) __declspec(noinline) std::uint32_t
mcp_fixture_run_to_target(const std::uint32_t value) {
    // Keep this body distinct from the interrupter. Release-link identical-code
    // folding would otherwise give both exported symbols the same address and
    // invalidate the run-to interruption fixture.
    return (value ^ 3U) + 1U;
}

extern "C" __declspec(dllexport) __declspec(noinline) std::uint32_t
mcp_fixture_access_violation(const std::uint32_t value) {
    return value ^ *mcp_fixture_invalid_pointer;
}

extern "C" __declspec(dllexport) __declspec(noinline) std::uint32_t
mcp_fixture_recovery_checkpoint(const std::uint32_t value) {
    return value;
}

extern "C" __declspec(dllexport) __declspec(noinline) std::uint32_t
mcp_fixture_access_violation_recovery(const std::uint32_t value) {
    const std::uint32_t recovered = value ^ 0xa55a3cc3U;
    mcp_fixture_recovery_observed.store(recovered);
    return mcp_fixture_recovery_checkpoint(recovered);
}

namespace {

constexpr wchar_t kArgumentObservationFile[] = L"mcp-argv-observed.bin";
constexpr std::array<std::uint8_t, 8> kArgumentObservationMagic{
    'M', 'A', 'R', 'G', 'V', '1', '\r', '\n'};
constexpr DWORD kFixtureExceptionCode = 0xe0424242U;

__declspec(noinline) void RaiseHandledFixtureException() {
    __try {
        RaiseException(kFixtureExceptionCode, 0U, 0U, nullptr);
    } __except (GetExceptionCode() == kFixtureExceptionCode ? EXCEPTION_EXECUTE_HANDLER
                                                            : EXCEPTION_CONTINUE_SEARCH) {
    }
}

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

DWORD WINAPI FixtureWorker(void*) {
    mcp_fixture_worker_thread_id.store(GetCurrentThreadId());
    mcp_fixture_worker_ready.store(1U);
    while (mcp_fixture_marker.load() != 0U) Sleep(10U);
    return 0U;
}

} // namespace

extern "C" __declspec(dllexport) __declspec(noinline) void mcp_fixture_trace_wait() {
    mcp_fixture_trace_wait_observed.store(1U);
    while (mcp_fixture_trace_wait_release.load() == 0U) Sleep(10U);
    mcp_fixture_trace_wait_observed.store(2U);
}

extern "C" __declspec(dllexport) __declspec(noinline) void mcp_fixture_trace_wait_callsite() {
    // Disassemble this export and stop at the call to mcp_fixture_trace_wait.
    // The observable store after it prevents tail-call folding on both targets.
    mcp_fixture_trace_wait();
    mcp_fixture_trace_wait_observed.store(3U);
}

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    mcp_fixture_main_thread_id.store(GetCurrentThreadId());
    if (!WriteObservedArguments()) return 2;
    const HANDLE worker = CreateThread(nullptr, 0U, FixtureWorker, nullptr, 0U, nullptr);
    if (worker == nullptr) return 3;
    CloseHandle(worker);
    mcp_fixture_marker.store(mcp_fixture_analysis_target(mcp_fixture_marker.load()));
    std::uint32_t value = mcp_fixture_marker.load();
    while (value != 0U) {
        if (mcp_fixture_trace_wait_trigger.exchange(0U) != 0U) {
            mcp_fixture_trace_wait_callsite();
        }
        if (mcp_fixture_exception_trigger.exchange(0U) != 0U) {
            RaiseHandledFixtureException();
        }
        if (mcp_fixture_access_violation_trigger.exchange(0U) != 0U) {
            mcp_fixture_marker.store(
                mcp_fixture_access_violation(mcp_fixture_marker.load()));
        }
        value = mcp_fixture_run_to_interrupter(value);
        value = mcp_fixture_run_to_target(value);
        mcp_fixture_marker.store(value);
        Sleep(10U);
        value = mcp_fixture_marker.load();
    }
    return 0;
}
