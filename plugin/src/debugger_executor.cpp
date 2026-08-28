#include "debugger_executor.h"

#include <utility>

namespace mcp {

DebuggerExecutor::~DebuggerExecutor() { Stop(); }

bool DebuggerExecutor::Start() {
    std::scoped_lock lock(mutex_);
    if (accepting_ || worker_.joinable()) {
        return false;
    }
    stopping_ = false;
    accepting_ = true;
    try {
        worker_ = std::thread(&DebuggerExecutor::Worker, this);
    } catch (...) {
        accepting_ = false;
        return false;
    }
    return true;
}

ExecutionResult DebuggerExecutor::Execute(
    std::function<std::string()> operation, const std::chrono::steady_clock::time_point deadline) {
    auto work = std::make_shared<Work>();
    work->operation = std::move(operation);
    std::future<std::string> completion = work->completion.get_future();
    {
        std::scoped_lock lock(mutex_);
        if (!accepting_) {
            return {ExecutionStatus::stopped, {}};
        }
        if (queue_.size() >= kCapacity) {
            return {ExecutionStatus::busy, {}};
        }
        queue_.push_back(work);
    }
    changed_.notify_one();
    if (completion.wait_until(deadline) == std::future_status::ready) {
        return {ExecutionStatus::completed, completion.get()};
    }
    work->cancelled.store(true);
    return {work->started.load() ? ExecutionStatus::timedOutStarted
                                 : ExecutionStatus::timedOutQueued,
            {}};
}

void DebuggerExecutor::Worker() noexcept {
    for (;;) {
        std::shared_ptr<Work> work;
        {
            std::unique_lock lock(mutex_);
            changed_.wait(lock, [this] { return stopping_ || !queue_.empty(); });
            if (stopping_ && queue_.empty()) {
                return;
            }
            work = std::move(queue_.front());
            queue_.pop_front();
        }
        if (work->cancelled.load()) {
            work->completion.set_value({});
            continue;
        }
        work->started.store(true);
        try {
            work->completion.set_value(work->operation());
        } catch (...) {
            work->completion.set_value({});
        }
    }
}

void DebuggerExecutor::Stop() noexcept {
    {
        std::scoped_lock lock(mutex_);
        accepting_ = false;
        stopping_ = true;
        for (const auto& work : queue_) {
            work->cancelled.store(true);
        }
    }
    changed_.notify_all();
    if (worker_.joinable()) {
        worker_.join();
    }
    {
        std::scoped_lock lock(mutex_);
        queue_.clear();
        stopping_ = false;
    }
}

} // namespace mcp
