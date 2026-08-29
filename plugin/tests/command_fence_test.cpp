#include "command_fence.h"

#include <chrono>
#include <future>
#include <iostream>
#include <thread>

namespace {
using namespace std::chrono_literals;

bool Check(const bool condition, const char* message) {
    if (!condition) std::cerr << message << '\n';
    return condition;
}
} // namespace

int main() {
    mcp::CommandFence fence;
    if (!Check(fence.Start(), "start failed") ||
        !Check(!fence.Arm(0U), "zero token was accepted") ||
        !Check(fence.Arm(0x1122334455667788ULL), "arm failed") ||
        !Check(!fence.Signal(0x8877665544332211ULL), "mismatched token signalled") ||
        !Check(fence.Signal(0x1122334455667788ULL), "matching token did not signal") ||
        !Check(fence.Wait(0x1122334455667788ULL, std::chrono::steady_clock::now() + 1s) ==
                   mcp::CommandFenceWait::completed,
               "completed fence was not observed")) {
        return 1;
    }

    if (!Check(fence.Arm(7U), "timeout arm failed") ||
        !Check(fence.Wait(7U, std::chrono::steady_clock::now() + 5ms) ==
                   mcp::CommandFenceWait::timedOut,
               "deadline did not time out") ||
        !Check(fence.Arm(8U), "timed-out token was not released")) {
        return 1;
    }
    fence.Cancel(8U);

    if (!Check(fence.Arm(9U), "stop arm failed")) return 1;
    auto waiter = std::async(std::launch::async, [&fence] {
        return fence.Wait(9U, std::chrono::steady_clock::now() + 5s);
    });
    std::this_thread::sleep_for(5ms);
    fence.Stop();
    if (!Check(waiter.get() == mcp::CommandFenceWait::stopped,
               "stop did not wake the fence waiter") ||
        !Check(fence.Start(), "restart failed")) {
        return 1;
    }
    fence.Stop();
    return 0;
}
