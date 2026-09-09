#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace mcp {

enum class TraceMode : std::uint8_t { into, over };
enum class TraceState : std::uint8_t { starting, running, completed, cancelled, timedOut, interrupted };
enum class TraceReason : std::uint8_t {
    none,
    maxSteps,
    cancelled,
    timeout,
    breakpoint,
    exception,
    userPause,
    processExit,
    backendShutdown,
    interrupted
};

struct TraceModule {
    std::uint64_t base{0U};
    std::uint64_t size{0U};
    std::string name;
};

struct TracePoint {
    std::uint64_t address{0U};
};

class TracePolicy final {
public:
    static constexpr std::size_t kMaxSteps = 4096U;
    static constexpr std::size_t kMaxPoints = kMaxSteps + 1U;

    bool Start(std::string id, TraceMode mode, std::size_t maxSteps,
               std::chrono::steady_clock::time_point deadline,
               std::uint64_t initialAddress, std::vector<TraceModule> modules);
    [[nodiscard]] bool Active() const noexcept;
    [[nodiscard]] bool Terminal() const noexcept;
    [[nodiscard]] bool Matches(const std::string& id) const noexcept;
    [[nodiscard]] bool OnStep(std::uint64_t address, bool nativeStop,
                              std::chrono::steady_clock::time_point now) noexcept;
    [[nodiscard]] bool RequestStop(TraceReason reason) noexcept;
    [[nodiscard]] bool Finalize(TraceReason fallback) noexcept;
    void Submitted() noexcept;

    [[nodiscard]] const std::string& Id() const noexcept { return id_; }
    [[nodiscard]] TraceMode Mode() const noexcept { return mode_; }
    [[nodiscard]] TraceState State() const noexcept { return state_; }
    [[nodiscard]] TraceReason Reason() const noexcept { return reason_; }
    [[nodiscard]] std::size_t MaxSteps() const noexcept { return maxSteps_; }
    [[nodiscard]] std::size_t StepsExecuted() const noexcept { return stepsExecuted_; }
    [[nodiscard]] std::chrono::steady_clock::time_point Deadline() const noexcept {
        return deadline_;
    }
    [[nodiscard]] const std::vector<TracePoint>& Points() const noexcept { return points_; }
    [[nodiscard]] const std::vector<TraceModule>& Modules() const noexcept { return modules_; }

private:
    std::string id_;
    TraceMode mode_{TraceMode::into};
    TraceState state_{TraceState::interrupted};
    TraceReason reason_{TraceReason::none};
    TraceReason pendingReason_{TraceReason::none};
    std::size_t maxSteps_{0U};
    std::size_t stepsExecuted_{0U};
    std::chrono::steady_clock::time_point deadline_{};
    std::vector<TracePoint> points_;
    std::vector<TraceModule> modules_;
};

// Serialized by Runtime::traceMutex_. Tickets fence both native submission and
// the out-of-lock interrupt operation; a pause alone cannot retire an interrupt.
class TraceStopCoordinator final {
public:
    using Clock = std::chrono::steady_clock;
    struct Ticket {
        std::uint64_t trace{0U};
        std::uint64_t process{0U};
        bool operator==(const Ticket&) const = default;
    };
    static constexpr auto kCooperativeGrace = std::chrono::milliseconds(50);

    Ticket Begin(std::uint64_t processEpoch, std::uint32_t processId) noexcept;
    void Submitted(TracePolicy& trace, Ticket ticket, bool accepted) noexcept;
    void Request(TracePolicy& trace, TraceReason reason, Clock::time_point now) noexcept;
    bool Step(TracePolicy& trace, std::uint64_t address, bool nativeStop,
              Clock::time_point now) noexcept;
    std::optional<Ticket> Reserve(TracePolicy& trace, Clock::time_point now) noexcept;
    bool Issue(Ticket ticket, std::uint32_t threadId, std::uint64_t address) noexcept;
    void AbandonIssue(Ticket ticket) noexcept;
    void FinishInterrupt(TracePolicy& trace, Ticket ticket, bool safelyRetired) noexcept;
    bool ThreadCreated(std::uint64_t processEpoch, std::uint32_t processId,
                       std::uint32_t threadId, bool rawCreateThread,
                       std::uint64_t address) noexcept;
    void Resumed() noexcept;
    void PauseCommitted(TracePolicy& trace, TraceReason fallback) noexcept;
    void ProcessExited(TracePolicy& trace) noexcept;
    [[nodiscard]] bool Current(Ticket ticket) const noexcept;
    [[nodiscard]] bool Unresolved() const noexcept { return issued_ && !consumed_ && !exited_; }
    [[nodiscard]] bool InFlight() const noexcept { return interruptInFlight_; }
    [[nodiscard]] bool Blocked() const noexcept { return paused_ && Unresolved(); }
    [[nodiscard]] bool LateResume() const noexcept { return paused_ && !submitted_; }
    [[nodiscard]] Clock::time_point WakeAt(const TracePolicy& trace) const noexcept;
    [[nodiscard]] Ticket Identity() const noexcept { return ticket_; }

private:
    void Finalize(TracePolicy& trace) noexcept;
    Ticket ticket_{};
    std::uint32_t processId_{0U};
    std::uint32_t threadId_{0U};
    std::uint64_t address_{0U};
    Clock::time_point requestedAt_{};
    TraceReason fallback_{TraceReason::interrupted};
    bool submitted_{false};
    bool resumed_{false};
    bool requested_{false};
    bool cooperative_{false};
    bool paused_{false};
    bool exited_{false};
    bool interruptInFlight_{false};
    bool attempted_{false};
    bool issued_{false};
    bool consumed_{false};
    bool issueAbandoned_{false};
};

// A helper pause is not an application breakpoint-management boundary. Keep
// the release-data write and explicit recovery controls, not arbitrary mutation.
[[nodiscard]] bool TraceHelperAllowsMutation(std::string_view method) noexcept;

[[nodiscard]] const char* TraceModeName(TraceMode mode) noexcept;
[[nodiscard]] const char* TraceStateName(TraceState state) noexcept;
[[nodiscard]] const char* TraceReasonName(TraceReason reason) noexcept;

} // namespace mcp
