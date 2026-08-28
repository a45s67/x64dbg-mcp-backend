#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <deque>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

namespace mcp {

enum class ExecutionStatus { completed, busy, timedOutQueued, timedOutStarted, stopped };

struct ExecutionResult {
    ExecutionStatus status{ExecutionStatus::stopped};
    std::string value;
};

class DebuggerExecutor final {
public:
    static constexpr std::size_t kCapacity = 32U;

    DebuggerExecutor() = default;
    DebuggerExecutor(const DebuggerExecutor&) = delete;
    DebuggerExecutor& operator=(const DebuggerExecutor&) = delete;
    ~DebuggerExecutor();

    bool Start();
    void Stop() noexcept;
    ExecutionResult Execute(std::function<std::string()> operation,
                            std::chrono::steady_clock::time_point deadline);

private:
    struct Work {
        std::function<std::string()> operation;
        std::promise<std::string> completion;
        std::atomic<bool> started{false};
        std::atomic<bool> cancelled{false};
    };

    void Worker() noexcept;

    std::mutex mutex_;
    std::condition_variable changed_;
    std::deque<std::shared_ptr<Work>> queue_;
    bool accepting_{false};
    bool stopping_{false};
    std::thread worker_;
};

} // namespace mcp
