#include <chrono>
#include <future>
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
    std::promise<void> enteredPromise;
    auto entered = enteredPromise.get_future();
    std::promise<void> releasePromise;
    const auto release = releasePromise.get_future().share();
    auto startedExecution = std::async(std::launch::async, [&executor, &enteredPromise, release] {
        return executor.Execute(
            [&enteredPromise, release] {
                enteredPromise.set_value();
                release.wait();
                return std::string("late");
            },
            std::chrono::steady_clock::now() + 250ms);
    });
    if (entered.wait_for(1s) != std::future_status::ready) {
        releasePromise.set_value();
        std::cerr << "worker did not start blocking operation\n";
        return 3;
    }
    const auto timedOut = startedExecution.get();
    const auto queuedTimeout = executor.Execute(
        [] { return std::string("must-not-run"); }, std::chrono::steady_clock::now() + 25ms);
    releasePromise.set_value();
    if (timedOut.status != mcp::ExecutionStatus::timedOutStarted) {
        std::cerr << "started work did not preserve ambiguous timeout status\n";
        return 4;
    }
    if (queuedTimeout.status != mcp::ExecutionStatus::timedOutQueued) {
        std::cerr << "queued work did not cancel before execution\n";
        return 5;
    }
    executor.Stop();
    const auto stopped = executor.Execute([] { return std::string("bad"); },
                                          std::chrono::steady_clock::now() + 1s);
    return stopped.status == mcp::ExecutionStatus::stopped ? 0 : 6;
}
