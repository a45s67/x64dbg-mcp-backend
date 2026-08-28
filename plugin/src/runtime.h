#pragma once

#include <Windows.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <string>
#include <thread>
#include <mutex>
#include <vector>

#include "debugger_executor.h"

namespace mcp {

enum class PluginState : std::uint8_t { starting, ready, draining, stopped };
enum class DebuggeeState : std::uint8_t { absent, starting, paused, running, stopping, exited };

class Runtime final {
public:
    Runtime() = default;
    Runtime(const Runtime&) = delete;
    Runtime& operator=(const Runtime&) = delete;
    ~Runtime();

    bool Start();
    void Stop() noexcept;
    void OnDebuggerEvent(int callbackType, void* callbackInfo) noexcept;
    [[nodiscard]] bool IsReady() const noexcept;
#ifdef MCP_LIFECYCLE_HARNESS
    [[nodiscard]] DWORD SidecarProcessIdForTesting() const noexcept;
#endif

private:
    bool CreateEndpoint();
    bool LaunchSidecar();
    void Worker() noexcept;
    void CloseHandleValue(HANDLE& handle) noexcept;
    std::string StateResponse(const std::string& requestId) const;
    bool WaitForState(DebuggeeState expected, std::uint64_t afterGeneration,
                      std::chrono::steady_clock::time_point deadline) noexcept;
    [[nodiscard]] std::uint64_t ObservedGeneration(DebuggeeState state) const noexcept;

    std::atomic<PluginState> pluginState_{PluginState::stopped};
    std::atomic<DebuggeeState> debuggeeState_{DebuggeeState::absent};
    std::atomic<std::uint64_t> generation_{0};
    std::atomic<std::uint64_t> pausedGeneration_{0};
    std::atomic<std::uint64_t> runningGeneration_{0};
    std::atomic<std::uint64_t> absentGeneration_{0};
    std::atomic<std::uint32_t> processId_{0};
    std::atomic<std::uint32_t> activeThreadId_{0};
    HANDLE instanceMutex_{nullptr};
    HANDLE pipe_{INVALID_HANDLE_VALUE};
    HANDLE nonceWriter_{nullptr};
    HANDLE sidecarProcess_{nullptr};
    HANDLE sidecarJob_{nullptr};
    std::thread worker_;
    DebuggerExecutor executor_;
    std::mutex stateMutex_;
    std::condition_variable stateChanged_;
    std::wstring pipeName_;
    std::string nonce_;
};

} // namespace mcp
