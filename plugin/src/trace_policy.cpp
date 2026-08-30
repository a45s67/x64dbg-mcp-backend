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
