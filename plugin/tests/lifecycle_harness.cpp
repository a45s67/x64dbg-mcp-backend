#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>

#include <array>
#include <chrono>
#include <iostream>
#include <thread>

#include <string>
#include <string_view>

#include "runtime.h"

namespace {
bool ExerciseStateTool(const unsigned short port) {
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
        return false;
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
        return false;
    }
    constexpr char body[] =
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"debugger.state\",\"arguments\":{}}}";
    const std::string request =
        "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer "
        "0123456789abcdef0123456789abcdef\r\nContent-Type: application/json\r\n"
        "Accept: application/json\r\nConnection: close\r\nContent-Length: " +
        std::to_string(sizeof(body) - 1U) + "\r\n\r\n" + body;
    std::size_t sent = 0;
    while (sent < request.size()) {
        const int chunk = send(socketValue, request.data() + sent,
                               static_cast<int>(request.size() - sent), 0);
        if (chunk <= 0) {
            closesocket(socketValue);
            WSACleanup();
            return false;
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
    return response.starts_with("HTTP/1.1 200") &&
           response.find("\\\"debuggee_state\\\":\\\"absent\\\"") != std::string::npos;
}
} // namespace

int wmain(const int argc, wchar_t** argv) {
    if (argc < 3 || argc > 4) {
        std::cerr << "usage: lifecycle_harness <server-exe> <unused-port> [sidecar-crash]\n";
        return 2;
    }
    if (SetEnvironmentVariableW(L"X64DBG_MCP_SERVER_PATH", argv[1]) == FALSE ||
        SetEnvironmentVariableW(L"X64DBG_MCP_PORT", argv[2]) == FALSE ||
        SetEnvironmentVariableW(L"X64DBG_MCP_TOKEN",
                                L"0123456789abcdef0123456789abcdef") == FALSE) {
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
