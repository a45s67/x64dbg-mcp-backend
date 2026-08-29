#include "command_fence.h"

namespace mcp {

bool CommandFence::Start() noexcept {
    std::lock_guard lock(mutex_);
    if (accepting_ || pending_) return false;
    accepting_ = true;
    completed_ = false;
    return true;
}

void CommandFence::Stop() noexcept {
    {
        std::lock_guard lock(mutex_);
        accepting_ = false;
        pending_.reset();
        completed_ = false;
    }
    changed_.notify_all();
}

bool CommandFence::Arm(const std::uint64_t token) noexcept {
    std::lock_guard lock(mutex_);
    if (!accepting_ || token == 0U || pending_) return false;
    pending_ = token;
    completed_ = false;
    return true;
}

bool CommandFence::Signal(const std::uint64_t token) noexcept {
    {
        std::lock_guard lock(mutex_);
        if (!accepting_ || !pending_ || *pending_ != token) return false;
        completed_ = true;
    }
    changed_.notify_all();
    return true;
}

void CommandFence::Cancel(const std::uint64_t token) noexcept {
    {
        std::lock_guard lock(mutex_);
        if (!pending_ || *pending_ != token) return;
        pending_.reset();
        completed_ = false;
    }
    changed_.notify_all();
}

CommandFenceWait CommandFence::Wait(
    const std::uint64_t token,
    const std::chrono::steady_clock::time_point deadline) noexcept {
    std::unique_lock lock(mutex_);
    const bool observed = changed_.wait_until(lock, deadline, [this, token] {
        return !accepting_ || (pending_ && *pending_ == token && completed_);
    });
    if (!accepting_) return CommandFenceWait::stopped;
    if (!observed || !pending_ || *pending_ != token || !completed_) {
        if (pending_ && *pending_ == token) pending_.reset();
        completed_ = false;
        return CommandFenceWait::timedOut;
    }
    pending_.reset();
    completed_ = false;
    return CommandFenceWait::completed;
}

} // namespace mcp
