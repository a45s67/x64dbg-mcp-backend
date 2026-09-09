#include "trace_policy.h"

#include <utility>

namespace mcp {

bool TracePolicy::Start(std::string id, const TraceMode mode, const std::size_t maxSteps,
                        const std::chrono::steady_clock::time_point deadline,
                        const std::uint64_t initialAddress,
                        std::vector<TraceModule> modules) {
    if (id.empty() || Active() || maxSteps == 0U || maxSteps > kMaxSteps ||
        initialAddress == 0U) return false;
    std::vector<TracePoint> points;
    try {
        points.reserve(maxSteps + 1U);
        points.push_back({initialAddress});
    } catch (...) {
        return false;
    }
    id_ = std::move(id);
    mode_ = mode;
    state_ = TraceState::starting;
    reason_ = TraceReason::none;
    pendingReason_ = TraceReason::none;
    maxSteps_ = maxSteps;
    stepsExecuted_ = 0U;
    deadline_ = deadline;
    points_ = std::move(points);
    modules_ = std::move(modules);
    return true;
}

bool TracePolicy::Active() const noexcept {
    return state_ == TraceState::starting || state_ == TraceState::running;
}

bool TracePolicy::Terminal() const noexcept { return !id_.empty() && !Active(); }

bool TracePolicy::Matches(const std::string& id) const noexcept { return id_ == id; }

void TracePolicy::Submitted() noexcept {
    if (state_ == TraceState::starting) state_ = TraceState::running;
}

bool TracePolicy::OnStep(const std::uint64_t address, const bool nativeStop,
                         const std::chrono::steady_clock::time_point now) noexcept {
    if (!Active()) return true;
    state_ = TraceState::running;
    if (points_.size() < kMaxPoints && points_.size() < maxSteps_ + 1U) {
        points_.push_back({address});
    }
    if (stepsExecuted_ < maxSteps_) ++stepsExecuted_;
    if (pendingReason_ == TraceReason::none && now >= deadline_) {
        pendingReason_ = TraceReason::timeout;
    }
    if (pendingReason_ == TraceReason::none && stepsExecuted_ >= maxSteps_) {
        pendingReason_ = TraceReason::maxSteps;
    }
    if (pendingReason_ == TraceReason::none && nativeStop) {
        pendingReason_ = TraceReason::interrupted;
    }
    return pendingReason_ != TraceReason::none;
}

bool TracePolicy::RequestStop(const TraceReason reason) noexcept {
    if (!Active() || reason == TraceReason::none) return false;
    if (pendingReason_ == TraceReason::none ||
        (pendingReason_ == TraceReason::timeout && reason == TraceReason::backendShutdown)) {
        pendingReason_ = reason;
    }
    return true;
}

bool TracePolicy::Finalize(const TraceReason fallback) noexcept {
    if (!Active()) return false;
    reason_ = pendingReason_ == TraceReason::none ? fallback : pendingReason_;
    if (reason_ == TraceReason::none) reason_ = TraceReason::interrupted;
    switch (reason_) {
    case TraceReason::maxSteps: state_ = TraceState::completed; break;
    case TraceReason::cancelled: state_ = TraceState::cancelled; break;
    case TraceReason::timeout: state_ = TraceState::timedOut; break;
    default: state_ = TraceState::interrupted; break;
    }
    pendingReason_ = TraceReason::none;
    return true;
}

TraceStopCoordinator::Ticket TraceStopCoordinator::Begin(
    const std::uint64_t processEpoch, const std::uint32_t processId) noexcept {
    const auto serial = ticket_.trace + 1U;
    *this = TraceStopCoordinator{};
    ticket_ = {serial, processEpoch};
    processId_ = processId;
    return ticket_;
}

bool TraceStopCoordinator::Current(const Ticket ticket) const noexcept {
    return ticket == ticket_ && !exited_;
}

void TraceStopCoordinator::Submitted(TracePolicy& trace, const Ticket ticket,
                                      const bool accepted) noexcept {
    if (ticket != ticket_) return;
    submitted_ = true;
    if (accepted) trace.Submitted();
    // A synchronous rejection with no resume has no native work left behind.
    else if (!resumed_) paused_ = true;
    Finalize(trace);
}

void TraceStopCoordinator::Request(TracePolicy& trace, const TraceReason reason,
                                    const Clock::time_point now) noexcept {
    if (!trace.RequestStop(reason)) return;
    if (!requested_) {
        requested_ = true;
        requestedAt_ = now;
    }
}

bool TraceStopCoordinator::Step(TracePolicy& trace, const std::uint64_t address,
                                const bool nativeStop, const Clock::time_point now) noexcept {
    resumed_ = true;
    const bool stop = trace.OnStep(address, nativeStop, now);
    // Once issued, let the owned create-thread pause win instead of requesting a second
    // independent pause. A native/user stop cannot safely be overridden.
    if (issued_) return nativeStop;
    if (stop) cooperative_ = true;
    return stop;
}

TraceStopCoordinator::Clock::time_point TraceStopCoordinator::WakeAt(
    const TracePolicy& trace) const noexcept {
    if (!resumed_ || attempted_ || cooperative_ || paused_ || exited_) {
        return Clock::time_point::max();
    }
    return requested_ ? requestedAt_ + kCooperativeGrace : trace.Deadline();
}

std::optional<TraceStopCoordinator::Ticket> TraceStopCoordinator::Reserve(
    TracePolicy& trace, const Clock::time_point now) noexcept {
    if (!trace.Active() || exited_) return std::nullopt;
    if (now >= trace.Deadline()) Request(trace, TraceReason::timeout, now);
    if (!requested_ || now < WakeAt(trace) || !resumed_) return std::nullopt;
    attempted_ = true;
    interruptInFlight_ = true;
    return ticket_;
}

bool TraceStopCoordinator::Issue(const Ticket ticket, const std::uint32_t threadId,
                                 const std::uint64_t address) noexcept {
    if (!Current(ticket) || !interruptInFlight_ || issued_ || issueAbandoned_ || cooperative_ || paused_ ||
        threadId == 0U || address == 0U) return false;
    threadId_ = threadId;
    address_ = address;
    issued_ = true;
    return true;
}

void TraceStopCoordinator::AbandonIssue(const Ticket ticket) noexcept {
    if (Current(ticket) && !issued_) issueAbandoned_ = true;
}

void TraceStopCoordinator::FinishInterrupt(TracePolicy& trace, const Ticket ticket,
                                           const bool safelyRetired) noexcept {
    if (ticket != ticket_ || !interruptInFlight_) return;
    interruptInFlight_ = false;
    if (safelyRetired) issued_ = false;
    else if (!issued_) issued_ = true; // Failed retirement is deliberately fail-closed.
    Finalize(trace);
}

bool TraceStopCoordinator::ThreadCreated(const std::uint64_t processEpoch,
    const std::uint32_t processId, const std::uint32_t threadId,
    const bool rawCreateThread, const std::uint64_t address) noexcept {
    if (!issued_ || consumed_ || exited_ || ticket_.process != processEpoch ||
        processId_ != processId || threadId_ != threadId || !rawCreateThread ||
        address_ != address) return false;
    consumed_ = true;
    return true;
}

bool TraceHelperAllowsMutation(const std::string_view method) noexcept {
    return method == "debugger.resume" || method == "debugger.stop" ||
        method == "memory.write" || method == "trace.cancel" || method == "scyllahide.profile";
}

void TraceStopCoordinator::Resumed() noexcept {
    if (LateResume()) return;
    resumed_ = true;
    paused_ = false;
}

void TraceStopCoordinator::PauseCommitted(TracePolicy& trace, const TraceReason fallback) noexcept {
    if (exited_) return;
    paused_ = true;
    fallback_ = fallback;
    Finalize(trace);
}

void TraceStopCoordinator::ProcessExited(TracePolicy& trace) noexcept {
    exited_ = true;
    fallback_ = TraceReason::processExit;
    Finalize(trace);
}

void TraceStopCoordinator::Finalize(TracePolicy& trace) noexcept {
    if (submitted_ && !interruptInFlight_ && (paused_ || exited_) && !Unresolved()) {
        (void)trace.Finalize(fallback_);
    }
}

const char* TraceModeName(const TraceMode mode) noexcept {
    return mode == TraceMode::into ? "into" : "over";
}

const char* TraceStateName(const TraceState state) noexcept {
    switch (state) {
    case TraceState::starting: return "starting";
    case TraceState::running: return "running";
    case TraceState::completed: return "completed";
    case TraceState::cancelled: return "cancelled";
    case TraceState::timedOut: return "timed_out";
    case TraceState::interrupted: return "interrupted";
    }
    return "interrupted";
}

const char* TraceReasonName(const TraceReason reason) noexcept {
    switch (reason) {
    case TraceReason::none: return "none";
    case TraceReason::maxSteps: return "max_steps";
    case TraceReason::cancelled: return "cancelled";
    case TraceReason::timeout: return "timeout";
    case TraceReason::breakpoint: return "breakpoint";
    case TraceReason::exception: return "exception";
    case TraceReason::userPause: return "user_pause";
    case TraceReason::processExit: return "process_exit";
    case TraceReason::backendShutdown: return "backend_shutdown";
    case TraceReason::interrupted: return "interrupted";
    }
    return "interrupted";
}

} // namespace mcp
