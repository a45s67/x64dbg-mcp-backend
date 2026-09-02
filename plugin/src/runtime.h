#pragma once

#include <Windows.h>

#include <atomic>
#include <array>
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
#include "trace_policy.h"

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
    std::uint32_t threadId{0};
    std::uint8_t breakpointType{0};
    bool hasAddress{false};
    bool hasExceptionCode{false};
    bool firstChance{false};
    bool hasThreadId{false};
};

enum class EventKind : std::uint8_t {
    debugInitialized, processCreated, systemBreakpoint, breakpoint, exception,
    paused, stepped, resumed, attached, detached, stopping, processExited,
    debugStopped, threadCreated, threadExited, dllLoaded, dllUnloaded,
    debugString, rip
};

struct EventRecord {
    std::uint64_t sequence{0};
    std::uint64_t generation{0};
    EventKind kind{EventKind::debugInitialized};
    std::uint32_t processId{0};
    std::uint32_t threadId{0};
    std::uint64_t address{0};
    std::uint64_t code{0};
    std::uint32_t auxiliary{0};
    std::uint8_t breakpointType{0};
    bool hasProcessId{false};
    bool hasThreadId{false};
    bool hasAddress{false};
    bool hasCode{false};
    bool firstChance{false};
};

struct PendingExceptionObservation {
    std::uint32_t processId{0};
    std::uint32_t threadId{0};
    std::uint32_t code{0};
    std::uint64_t address{0};
    bool firstChance{false};
    bool valid{false};
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
    [[nodiscard]] std::vector<EventRecord> EventsForTesting() noexcept;
    [[nodiscard]] bool StartTraceForTesting() noexcept;
    [[nodiscard]] TraceReason TraceReasonForTesting() noexcept;
#endif

private:
    bool CreateEndpoint();
    bool LaunchSidecar();
    void Worker() noexcept;
    void TraceSupervisor() noexcept;
    void CloseHandleValue(HANDLE& handle) noexcept;
    std::string StateResponse(const std::string& requestId);
    std::string ScyllaHideProfileResponse(const std::string& requestId,
                                          const std::string& operationId,
                                          const std::string& action,
                                          const std::string& profile,
                                          const std::string& expectedGeneration);
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
    void RecordEventLocked(EventRecord event) noexcept;

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
    std::atomic<bool> pauseInterruptPending_{false};
    HANDLE instanceMutex_{nullptr};
    HANDLE pipe_{INVALID_HANDLE_VALUE};
    HANDLE nonceWriter_{nullptr};
    HANDLE sidecarProcess_{nullptr};
    HANDLE sidecarJob_{nullptr};
    std::thread worker_;
    std::thread traceSupervisor_;
    DebuggerExecutor executor_;
    CommandFence commandFence_;
    std::mutex stateMutex_;
    std::condition_variable stateChanged_;
    std::mutex traceMutex_;
    std::condition_variable traceChanged_;
    TracePolicy trace_;
    bool traceSupervisorStopping_{false};
    bool tracePauseSubmitted_{false};
    PauseObservation latestPause_;
    PendingExceptionObservation pendingException_;
    static constexpr std::size_t kEventCapacity = 256U;
    std::array<EventRecord, kEventCapacity> eventRing_{};
    std::size_t eventStart_{0U};
    std::size_t eventCount_{0U};
    std::uint64_t nextEventSequence_{1U};
    std::wstring pipeName_;
    std::string nonce_;
    std::string instanceId_;
    std::string startupScyllaGeneration_;
    std::string startupScyllaProfile_;
};

} // namespace mcp
