#pragma once

#include <Windows.h>

#include <array>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <thread>

namespace mcp {
enum class EventKind : std::uint8_t {
    debugInitialized, processCreated, systemBreakpoint, breakpoint, exception,
    paused, stepped, resumed, attached, detached, stopping, processExited,
    debugStopped, threadCreated, threadExited, dllLoaded, dllUnloaded,
    debugString, rip
};

struct EventRecord {
    std::array<char, 80> sessionId{};
    std::uint64_t timestampUnixMs{0};
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

[[nodiscard]] std::string EventJson(const EventRecord& event);

class EventStream final {
public:
    EventStream() = default;
    EventStream(const EventStream&) = delete;
    EventStream& operator=(const EventStream&) = delete;
    ~EventStream();

    [[nodiscard]] bool Start(const std::wstring& pipeName, const std::string& nonce);
    void SetInstanceId(const std::string& instanceId) noexcept;
    void Enqueue(const EventRecord& event) noexcept;
    void Stop() noexcept;

private:
    void Worker() noexcept;

    static constexpr std::size_t kMaxQueuedEvents = 4096U;
    static_assert(sizeof(EventRecord) * kMaxQueuedEvents <= 8U * 1024U * 1024U);
    HANDLE pipe_{INVALID_HANDLE_VALUE};
    std::thread worker_;
    std::mutex mutex_;
    std::condition_variable changed_;
    std::deque<EventRecord> queue_;
    std::string nonce_;
    std::string instanceId_;
    std::uint64_t dropped_{0U};
    bool stopping_{false};
};
}
