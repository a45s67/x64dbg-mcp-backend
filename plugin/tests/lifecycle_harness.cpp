#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>

#include <array>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <thread>

#include <string>
#include <string_view>

#include "runtime.h"
#include "_plugins.h"

namespace {
std::string PostMcp(const unsigned short port, const std::string_view body) {
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
        return {};
    }
    SOCKET socketValue = INVALID_SOCKET;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (std::chrono::steady_clock::now() < deadline) {
        socketValue = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (socketValue == INVALID_SOCKET) {
            break;
        }
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(port);
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (connect(socketValue, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == 0) {
            break;
        }
        closesocket(socketValue);
        socketValue = INVALID_SOCKET;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    if (socketValue == INVALID_SOCKET) {
        WSACleanup();
        return {};
    }
    const std::string request =
        "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer "
        "0123456789abcdef0123456789abcdef\r\nContent-Type: application/json\r\n"
        "Accept: application/json\r\nConnection: close\r\nContent-Length: " +
        std::to_string(body.size()) + "\r\n\r\n" + std::string(body);
    std::size_t sent = 0;
    while (sent < request.size()) {
        const int chunk = send(socketValue, request.data() + sent,
                               static_cast<int>(request.size() - sent), 0);
        if (chunk <= 0) {
            closesocket(socketValue);
            WSACleanup();
            return {};
        }
        sent += static_cast<std::size_t>(chunk);
    }
    std::string response;
    std::array<char, 4096> buffer{};
    for (;;) {
        const int count = recv(socketValue, buffer.data(), static_cast<int>(buffer.size()), 0);
        if (count <= 0) {
            break;
        }
        response.append(buffer.data(), static_cast<std::size_t>(count));
        if (response.size() > 65536U) {
            break;
        }
    }
    closesocket(socketValue);
    WSACleanup();
    return response;
}

bool ExerciseStateTool(const unsigned short port) {
    constexpr std::string_view body =
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"debugger.state\",\"arguments\":{}}}";
    const std::string response = PostMcp(port, body);
    return response.starts_with("HTTP/1.1 200") &&
           response.find("\\\"debuggee_state\\\":\\\"absent\\\"") != std::string::npos;
}

bool ExerciseActiveWaitShutdown(mcp::Runtime& runtime, const unsigned short port) {
    runtime.OnDebuggerEvent(CB_RESUMEDEBUG, nullptr);
    std::atomic_bool completed{false};
    std::thread request([port, &completed] {
        constexpr std::string_view body =
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"debugger.wait_for_pause\",\"arguments\":{\"after_generation\":9007199254740991,\"timeout_ms\":9000}}}";
        (void)PostMcp(port, body);
        completed.store(true);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    const auto start = std::chrono::steady_clock::now();
    runtime.Stop();
    request.join();
    return completed.load() &&
           std::chrono::steady_clock::now() - start < std::chrono::seconds(3);
}

bool ExercisePauseCallbacks(mcp::Runtime& runtime) {
    runtime.OnDebuggerEvent(CB_RESUMEDEBUG, nullptr);
    BRIDGEBP breakpoint{};
    breakpoint.type = bp_normal;
    breakpoint.addr = static_cast<duint>(0x401000U);
    breakpoint.hitCount = 3U;
    PLUG_CB_BREAKPOINT breakpointInfo{&breakpoint};
    runtime.OnDebuggerEvent(CB_BREAKPOINT, &breakpointInfo);
    const mcp::PauseObservation specific = runtime.PauseForTesting();
    const std::optional<std::uint64_t> snapshot = runtime.BeginPausedSnapshotForTesting();
    if (!snapshot || !runtime.PausedSnapshotCurrentForTesting(*snapshot)) {
        return false;
    }
    runtime.OnDebuggerEvent(CB_PAUSEDEBUG, nullptr);
    const mcp::PauseObservation afterGeneric = runtime.PauseForTesting();
    if (specific.kind != mcp::PauseReasonKind::breakpoint || !specific.hasAddress ||
        specific.address != 0x401000U || specific.hitCount != 3U ||
        specific.generation == 0U || afterGeneric.generation != specific.generation ||
        afterGeneric.kind != mcp::PauseReasonKind::breakpoint) {
        return false;
    }

    runtime.OnDebuggerEvent(CB_RESUMEDEBUG, nullptr);
    if (runtime.PausedSnapshotCurrentForTesting(*snapshot)) {
        return false;
    }
    EXCEPTION_DEBUG_INFO exception{};
    exception.ExceptionRecord.ExceptionCode = EXCEPTION_ACCESS_VIOLATION;
    exception.ExceptionRecord.ExceptionAddress = reinterpret_cast<void*>(0x402000U);
    exception.dwFirstChance = 1U;
    PLUG_CB_EXCEPTION exceptionInfo{&exception};
    runtime.OnDebuggerEvent(CB_EXCEPTION, &exceptionInfo);
    const mcp::PauseObservation capturedException = runtime.PauseForTesting();
    return capturedException.kind == mcp::PauseReasonKind::exception &&
           capturedException.hasExceptionCode &&
           capturedException.exceptionCode == EXCEPTION_ACCESS_VIOLATION &&
           capturedException.hasAddress && capturedException.address == 0x402000U &&
           capturedException.firstChance && capturedException.generation > specific.generation;
}

bool ExerciseSessionOriginCallbacks(mcp::Runtime& runtime) {
    runtime.OnDebuggerEvent(CB_STOPDEBUG, nullptr);
    runtime.OnDebuggerEvent(CB_INITDEBUG, nullptr);
    if (runtime.SessionOriginForTesting() != mcp::SessionOrigin::none) return false;
    PLUG_CB_ATTACH attach{0x1234U};
    runtime.OnDebuggerEvent(CB_ATTACH, &attach);
    if (runtime.SessionOriginForTesting() != mcp::SessionOrigin::attached) return false;
    PROCESS_INFORMATION process{};
    process.dwProcessId = attach.dwProcessId;
    PLUG_CB_DETACH detach{&process};
    runtime.OnDebuggerEvent(CB_DETACH, &detach);
    if (runtime.SessionOriginForTesting() != mcp::SessionOrigin::attached) return false;
    runtime.OnDebuggerEvent(CB_STOPDEBUG, nullptr);
    return runtime.SessionOriginForTesting() == mcp::SessionOrigin::none;
}
} // namespace

int wmain(const int argc, wchar_t** argv) {
    if (argc < 3 || argc > 4) {
        std::cerr << "usage: lifecycle_harness <server-exe> <unused-port> "
                     "[sidecar-crash|installed-config|active-wait-shutdown]\n";
        return 2;
    }
    const bool installedConfig = argc == 4 && std::wstring_view(argv[3]) == L"installed-config";
    std::filesystem::path serverPath = argv[1];
    std::filesystem::path temporaryDirectory;
    std::filesystem::path configPath;
    if (installedConfig) {
#ifdef _WIN64
        constexpr wchar_t configName[] = L"x64dbg-mcp-server-x64.toml";
#else
        constexpr wchar_t configName[] = L"x64dbg-mcp-server-x32.toml";
#endif
        temporaryDirectory = std::filesystem::temp_directory_path() /
                             (L"x64dbg-mcp-installed-config-" +
                              std::to_wstring(GetCurrentProcessId()));
        std::filesystem::create_directory(temporaryDirectory);
        serverPath = temporaryDirectory / std::filesystem::path(argv[1]).filename();
        std::filesystem::copy_file(argv[1], serverPath,
                                   std::filesystem::copy_options::overwrite_existing);
        configPath = temporaryDirectory / configName;
        std::ofstream config(configPath, std::ios::binary | std::ios::trunc);
        config << "bind = \"127.0.0.1\"\nport = " << std::filesystem::path(argv[2]).string()
               << "\nbearer_token = \"0123456789abcdef0123456789abcdef\"\n";
        if (!config) {
            std::cerr << "could not create installed-layout config\n";
            return 3;
        }
        SetEnvironmentVariableW(L"X64DBG_MCP_PORT", nullptr);
        SetEnvironmentVariableW(L"X64DBG_MCP_TOKEN", nullptr);
    }
    struct ConfigCleanup {
        std::filesystem::path directory;
        ~ConfigCleanup() {
            if (!directory.empty()) {
                std::error_code error;
                std::filesystem::remove_all(directory, error);
            }
        }
    } cleanup{temporaryDirectory};
    if (SetEnvironmentVariableW(L"X64DBG_MCP_SERVER_PATH", serverPath.c_str()) == FALSE ||
        (!installedConfig &&
         (SetEnvironmentVariableW(L"X64DBG_MCP_PORT", argv[2]) == FALSE ||
          SetEnvironmentVariableW(L"X64DBG_MCP_TOKEN",
                                  L"0123456789abcdef0123456789abcdef") == FALSE))) {
        return 3;
    }

    mcp::Runtime runtime;
    if (!runtime.Start()) {
        std::cerr << "runtime startup failed\n";
        return 4;
    }
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(7);
    while (!runtime.IsReady() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    if (!runtime.IsReady()) {
        runtime.Stop();
        std::cerr << "authenticated handshake did not complete\n";
        return 5;
    }
    const unsigned long parsedPort = wcstoul(argv[2], nullptr, 10);
    if (parsedPort == 0UL || parsedPort > 65535UL ||
        !ExerciseStateTool(static_cast<unsigned short>(parsedPort))) {
        runtime.Stop();
        std::cerr << "end-to-end debugger.state call failed\n";
        return 7;
    }
    if (!ExercisePauseCallbacks(runtime)) {
        runtime.Stop();
        std::cerr << "callback pause observation contract failed\n";
        return 9;
    }
    if (!ExerciseSessionOriginCallbacks(runtime)) {
        runtime.Stop();
        std::cerr << "attach/detach session-origin callback contract failed\n";
        return 11;
    }
    if (argc == 4 && std::wstring_view(argv[3]) == L"active-wait-shutdown") {
        if (!ExerciseActiveWaitShutdown(runtime, static_cast<unsigned short>(parsedPort))) {
            std::cerr << "active callback wait delayed runtime shutdown\n";
            return 10;
        }
        return 0;
    }
    if (argc == 4 && std::wstring_view(argv[3]) == L"sidecar-crash") {
        const DWORD sidecarId = runtime.SidecarProcessIdForTesting();
        HANDLE process = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, sidecarId);
        if (process == nullptr || TerminateProcess(process, ERROR_PROCESS_ABORTED) == FALSE ||
            WaitForSingleObject(process, 2000U) != WAIT_OBJECT_0) {
            if (process != nullptr) {
                CloseHandle(process);
            }
            runtime.Stop();
            std::cerr << "could not inject sidecar crash\n";
            return 8;
        }
        CloseHandle(process);
    }
    const auto start = std::chrono::steady_clock::now();
    runtime.Stop();
    if (std::chrono::steady_clock::now() - start > std::chrono::seconds(7)) {
        std::cerr << "runtime shutdown exceeded deadline\n";
        return 6;
    }
    return 0;
}
