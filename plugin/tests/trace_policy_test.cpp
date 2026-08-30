#include "trace_policy.h"

#include <cassert>
#include <chrono>
#include <string>
#include <vector>

int main() {
    using namespace std::chrono_literals;
    const auto now = std::chrono::steady_clock::now();
    mcp::TracePolicy trace;
    assert(trace.Start("11111111-2222-4333-8444-555555555555", mcp::TraceMode::into,
                       2U, now + 1s, 0x401000U,
                       {{0x400000U, 0x10000U, "fixture.exe"}}));
    assert(trace.Active());
    assert(!trace.Start("other", mcp::TraceMode::over, 1U, now + 1s, 1U, {}));
    assert(!trace.OnStep(0x401001U, false, now));
    assert(trace.State() == mcp::TraceState::running);
    assert(trace.OnStep(0x401003U, false, now));
    assert(trace.StepsExecuted() == 2U);
    assert(trace.Points().size() == 3U);
    assert(trace.Finalize(mcp::TraceReason::interrupted));
    assert(trace.State() == mcp::TraceState::completed);
    assert(trace.Reason() == mcp::TraceReason::maxSteps);

    assert(trace.Start("22222222-2222-4333-8444-555555555555", mcp::TraceMode::over,
                       mcp::TracePolicy::kMaxSteps, now + 1s, 0x501000U, {}));
    assert(trace.RequestStop(mcp::TraceReason::cancelled));
    assert(trace.OnStep(0x501001U, false, now));
    assert(trace.Finalize(mcp::TraceReason::userPause));
    assert(trace.State() == mcp::TraceState::cancelled);

    assert(trace.Start("33333333-2222-4333-8444-555555555555", mcp::TraceMode::into,
                       8U, now, 0x601000U, {}));
    assert(trace.OnStep(0x601001U, false, now));
    assert(trace.Finalize(mcp::TraceReason::interrupted));
    assert(trace.State() == mcp::TraceState::timedOut);

    assert(trace.Start("44444444-2222-4333-8444-555555555555", mcp::TraceMode::into,
                       8U, now + 1s, 0x701000U, {}));
    assert(trace.OnStep(0x701001U, true, now));
    assert(trace.Finalize(mcp::TraceReason::userPause));
    assert(trace.Reason() == mcp::TraceReason::interrupted);

    assert(!trace.Start("bad", mcp::TraceMode::into, 0U, now, 1U, {}));
    assert(!trace.Start("bad", mcp::TraceMode::into, 4097U, now, 1U, {}));
    assert(!trace.Start("bad", mcp::TraceMode::into, 1U, now, 0U, {}));
    return 0;
}
