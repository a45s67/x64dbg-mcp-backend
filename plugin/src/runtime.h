#pragma once

#include <Windows.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <string>
#include <thread>
#include <mutex>
#include <optional>
#include <vector>

#include "command_fence.h"
#include "debugger_executor.h"

namespace mcp {

enum class PluginState : std::uint8_t { starting, ready, draining, stopped };
enum class DebuggeeState : std::uint8_t { absent, starting, paused, running, stopping, exited };
enum class SessionOrigin : std::uint8_t { none, launched, attached };
enum class PauseReasonKind : std::uint8_t {
    unknown,
    processCreated,
    systemBreakpoint,
    breakpoint,
    exception,
    step,
    userPause
};

struct PauseObservation {
    std::uint64_t generation{0};
    PauseReasonKind kind{PauseReasonKind::unknown};
    std::uint64_t address{0};
    std::uint64_t exceptionCode{0};
    std::uint32_t hitCount{0};
    std::uint8_t breakpointType{0};
    bool hasAddress{false};
    bool hasExceptionCode{false};
    bool firstChance{false};
};

class Runtime final {
public:
    Runtime() = default;
    Runtime(const Runtime&) = delete;
    Runtime& operator=(const Runtime&) = delete;
    ~Runtime();

    bool Start();
    void Stop() noexcept;
    void OnDebuggerEvent(int callbackType, void* callbackInfo) noexcept;
    bool OnCommandFence(std::uint64_t token) noexcept;
    [[nodiscard]] bool IsReady() const noexcept;
#ifdef MCP_LIFECYCLE_HARNESS
    [[nodiscard]] DWORD SidecarProcessIdForTesting() const noexcept;
    [[nodiscard]] PauseObservation PauseForTesting() noexcept;
    [[nodiscard]] std::optional<std::uint64_t> BeginPausedSnapshotForTesting() noexcept;
    [[nodiscard]] bool PausedSnapshotCurrentForTesting(std::uint64_t generation) noexcept;
    [[nodiscard]] SessionOrigin SessionOriginForTesting() const noexcept;
#endif

private:
    bool CreateEndpoint();
    bool LaunchSidecar();
    void Worker() noexcept;
    void CloseHandleValue(HANDLE& handle) noexcept;
    std::string StateResponse(const std::string& requestId);
    bool WaitForState(DebuggeeState expected, std::uint64_t afterGeneration,
                      std::chrono::steady_clock::time_point deadline) noexcept;
    bool WaitForPauseReason(PauseReasonKind reason, std::uint64_t afterGeneration,
                            std::chrono::steady_clock::time_point deadline) noexcept;
    bool WaitForActionableLaunchPause(std::uint64_t afterGeneration,
                                      std::chrono::steady_clock::time_point deadline) noexcept;
    bool WaitForAttachPause(std::uint32_t processId, std::uint64_t afterGeneration,
                            std::chrono::steady_clock::time_point deadline) noexcept;
    bool WaitForDetach(std::uint32_t processId, std::uint64_t afterGeneration,
                       std::chrono::steady_clock::time_point deadline) noexcept;
    [[nodiscard]] std::uint64_t ObservedGeneration(DebuggeeState state) const noexcept;
    [[nodiscard]] std::optional<std::uint64_t> BeginPausedSnapshot() noexcept;
    [[nodiscard]] std::optional<std::uint64_t> BeginActiveSnapshot() noexcept;
    [[nodiscard]] bool PausedSnapshotCurrent(std::uint64_t generation) noexcept;
    [[nodiscard]] bool ActiveSnapshotCurrent(std::uint64_t generation) noexcept;
    [[nodiscard]] bool PauseObservationCurrent(std::uint64_t generation,
                                               std::uint64_t pauseGeneration) noexcept;

    std::atomic<PluginState> pluginState_{PluginState::stopped};
    std::atomic<DebuggeeState> debuggeeState_{DebuggeeState::absent};
    std::atomic<SessionOrigin> sessionOrigin_{SessionOrigin::none};
    std::atomic<std::uint64_t> generation_{0};
    std::atomic<std::uint64_t> pausedGeneration_{0};
    std::atomic<std::uint64_t> runningGeneration_{0};
    std::atomic<std::uint64_t> absentGeneration_{0};
    std::atomic<std::uint32_t> processId_{0};
    std::atomic<std::uint32_t> activeThreadId_{0};
    std::atomic<std::uint32_t> attachProcessId_{0};
    std::atomic<std::uint64_t> attachGeneration_{0};
    std::atomic<std::uint32_t> detachProcessId_{0};
    std::atomic<std::uint64_t> detachGeneration_{0};
    HANDLE instanceMutex_{nullptr};
    HANDLE pipe_{INVALID_HANDLE_VALUE};
    HANDLE nonceWriter_{nullptr};
    HANDLE sidecarProcess_{nullptr};
    HANDLE sidecarJob_{nullptr};
    std::thread worker_;
    DebuggerExecutor executor_;
    CommandFence commandFence_;
    std::mutex stateMutex_;
    std::condition_variable stateChanged_;
    PauseObservation latestPause_;
    std::wstring pipeName_;
    std::string nonce_;
    std::string instanceId_;
};

} // namespace mcp
