#pragma once

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <optional>

namespace mcp {

enum class CommandFenceWait { completed, timedOut, stopped };

// Correlates one serialized native operation with a command-loop fence without
// creating a helper thread or retaining an unbounded token collection.
class CommandFence final {
public:
    bool Start() noexcept;
    void Stop() noexcept;
    bool Arm(std::uint64_t token) noexcept;
    bool Signal(std::uint64_t token) noexcept;
    void Cancel(std::uint64_t token) noexcept;
    CommandFenceWait Wait(std::uint64_t token,
                          std::chrono::steady_clock::time_point deadline) noexcept;

private:
    std::mutex mutex_;
    std::condition_variable changed_;
    std::optional<std::uint64_t> pending_;
    bool accepting_{false};
    bool completed_{false};
};

} // namespace mcp
