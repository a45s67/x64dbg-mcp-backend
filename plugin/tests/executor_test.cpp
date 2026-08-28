#include <chrono>
#include <iostream>
#include <string>
#include <thread>

#include "debugger_executor.h"

int main() {
    using namespace std::chrono_literals;
    mcp::DebuggerExecutor executor;
    if (!executor.Start()) {
        return 1;
    }
    const auto completed = executor.Execute([] { return std::string("ok"); },
                                            std::chrono::steady_clock::now() + 1s);
    if (completed.status != mcp::ExecutionStatus::completed || completed.value != "ok") {
        return 2;
    }
    const auto timedOut = executor.Execute(
        [] {
            std::this_thread::sleep_for(50ms);
            return std::string("late");
        },
        std::chrono::steady_clock::now() + 5ms);
    if (timedOut.status != mcp::ExecutionStatus::timedOutStarted) {
        std::cerr << "started work did not preserve ambiguous timeout status\n";
        return 3;
    }
    const auto queuedTimeout = executor.Execute(
        [] { return std::string("must-not-run"); }, std::chrono::steady_clock::now() + 5ms);
    if (queuedTimeout.status != mcp::ExecutionStatus::timedOutQueued) {
        std::cerr << "queued work did not cancel before execution\n";
        return 4;
    }
    executor.Stop();
    const auto stopped = executor.Execute([] { return std::string("bad"); },
                                          std::chrono::steady_clock::now() + 1s);
    return stopped.status == mcp::ExecutionStatus::stopped ? 0 : 5;
}
