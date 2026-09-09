#include "trace_policy.h"

#include <cassert>
#include <chrono>
#include <string>
#include <vector>

namespace {
void StopSchedules() {
    using namespace std::chrono_literals;
    using mcp::TraceReason;
    using mcp::TraceState;
    const mcp::TraceStopCoordinator::Clock::time_point now{};
    mcp::TracePolicy trace;
    mcp::TraceStopCoordinator stop;
    const auto begin = [&](bool submit = true) {
        assert(trace.Start("trace", mcp::TraceMode::over, 10U, now + 1s, 0x401000U, {}));
        const auto ticket = stop.Begin(7U, 42U);
        stop.Resumed();
        if (submit) stop.Submitted(trace, ticket, true);
        return ticket;
    };

    // Reservation is not permission to issue after cooperative acknowledgment.
    auto ticket = begin();
    stop.Request(trace, TraceReason::cancelled, now);
    assert(!stop.Reserve(trace, now + 49ms));
    assert(stop.Reserve(trace, now + 50ms) == ticket);
    assert(stop.Step(trace, 0x401001U, false, now + 51ms));
    assert(!stop.Issue(ticket, 99U, 0x77000000U));
    stop.PauseCommitted(trace, TraceReason::userPause);
    assert(trace.Active()); // Reserved external creation has not been retired.
    assert(!trace.Start("next", mcp::TraceMode::into, 1U, now + 1s, 1U, {}));
    stop.FinishInterrupt(trace, ticket, true);
    assert(trace.State() == TraceState::cancelled);

    // A callback and committed pause can occur before direct submission returns.
    const auto stale = ticket;
    ticket = begin(false);
    stop.Request(trace, TraceReason::cancelled, now);
    assert(stop.Step(trace, 0x401001U, false, now));
    assert(!stop.Reserve(trace, now + 1s));
    assert(trace.Active()); // A cooperative stop is not a committed pause.
    stop.PauseCommitted(trace, TraceReason::userPause);
    assert(trace.Active()); // Nor is submission allowed to be outstanding.
    assert(stop.LateResume());
    stop.Resumed(); // Late native resume callback cannot erase this pause.
    stop.Submitted(trace, stale, true);
    assert(trace.Active());
    stop.Submitted(trace, ticket, true);
    assert(trace.Terminal());

    // The independently scheduled deadline fires with no CB_TRACEEXECUTE at all.
    ticket = begin();
    assert(trace.State() == TraceState::running);
    assert(trace.StepsExecuted() == 0U);
    assert(!stop.Reserve(trace, now + 999ms));
    assert(!stop.Reserve(trace, now + 1s));
    assert(stop.WakeAt(trace) == now + 1050ms);
    assert(stop.Reserve(trace, now + 1050ms) == ticket);
    stop.Request(trace, TraceReason::cancelled, now + 1051ms);
    assert(!stop.Reserve(trace, now + 2s));
    assert(!stop.Issue(stale, 99U, 0x77000000U));
    assert(stop.Issue(ticket, 99U, 0x77000000U));
    assert(!stop.Issue(ticket, 99U, 0x77000000U));
    stop.FinishInterrupt(trace, stale, true);
    assert(stop.InFlight());
    stop.FinishInterrupt(trace, ticket, false);
    // Do not compete with the issued interrupt with another cooperative stop.
    assert(!stop.Step(trace, 0x401002U, false, now + 2s));
    assert(stop.Step(trace, 0x401002U, true, now + 2s)); // Native stops are never swallowed.
    assert(!stop.ThreadCreated(8U, 42U, 99U, true, 0x77000000U));
    assert(!stop.ThreadCreated(7U, 43U, 99U, true, 0x77000000U));
    assert(!stop.ThreadCreated(7U, 42U, 98U, true, 0x77000000U));
    assert(!stop.ThreadCreated(7U, 42U, 99U, false, 0x77000000U));
    assert(!stop.ThreadCreated(7U, 42U, 99U, true, 0x77000001U));
    // An unrelated breakpoint wins. No terminal/reuse, no automatic resume.
    stop.PauseCommitted(trace, TraceReason::breakpoint);
    assert(stop.Blocked());
    assert(trace.Active());
    assert(!trace.Start("next", mcp::TraceMode::into, 1U, now + 1s, 1U, {}));
    stop.ProcessExited(trace);
    assert(!stop.Unresolved());
    assert(trace.State() == TraceState::timedOut); // First stop reason wins.
    assert(!stop.ThreadCreated(7U, 42U, 99U, true, 0x77000000U));

    // Interrupt delivery before ResumeThread returns is correlated, but does
    // not publish until both the operation returns and pause state is committed.
    ticket = begin();
    stop.Request(trace, TraceReason::cancelled, now);
    assert(stop.Reserve(trace, now + 50ms) == ticket);
    assert(stop.Issue(ticket, 100U, 0x77000000U));
    assert(stop.ThreadCreated(7U, 42U, 100U, true, 0x77000000U));
    assert(!stop.ThreadCreated(7U, 42U, 100U, true, 0x77000000U));
    stop.PauseCommitted(trace, TraceReason::userPause);
    assert(trace.Active());
    stop.FinishInterrupt(trace, ticket, false);
    assert(trace.State() == TraceState::cancelled);

    ticket = begin();
    stop.Request(trace, TraceReason::cancelled, now);
    stop.Request(trace, TraceReason::timeout, now + 1s);
    assert(stop.Reserve(trace, now + 1s) == ticket);
    assert(stop.Issue(ticket, 101U, 0x77000000U));
    stop.FinishInterrupt(trace, ticket, false);
    assert(stop.ThreadCreated(7U, 42U, 101U, true, 0x77000000U));
    assert(trace.Active()); // Consumed interrupt alone is not a pause commit.
    stop.PauseCommitted(trace, TraceReason::userPause);
    assert(trace.State() == TraceState::cancelled);

    ticket = begin(false);
    stop.Request(trace, TraceReason::timeout, now);
    assert(stop.Reserve(trace, now + 50ms) == ticket);
    stop.ProcessExited(trace);
    assert(!stop.Current(ticket));
    assert(!stop.Issue(ticket, 102U, 0x77000000U));
    assert(trace.Active());
    stop.FinishInterrupt(trace, ticket, true);
    assert(trace.Active());
    stop.Submitted(trace, ticket, true);
    assert(trace.Terminal());

    // Rejected starts have no queued command capable of starting the next trace.
    assert(trace.Start("rejected", mcp::TraceMode::into, 1U, now + 1s, 1U, {}));
    ticket = stop.Begin(8U, 42U); // Reused PID, distinct process epoch.
    stop.Submitted(trace, ticket, false);
    assert(trace.Terminal());

    // Failed retirement of a never-run helper must also fail closed.
    ticket = begin();
    stop.Request(trace, TraceReason::cancelled, now);
    assert(stop.Reserve(trace, now + 50ms) == ticket);
    assert(stop.Step(trace, 1U, false, now + 51ms));
    assert(!stop.Issue(ticket, 103U, 0x77000000U));
    stop.FinishInterrupt(trace, ticket, false);
    stop.PauseCommitted(trace, TraceReason::userPause);
    assert(stop.Blocked());
    stop.ProcessExited(trace);
    assert(trace.Terminal());

    // If creation's ownership handshake cannot finish in the callback, a
    // later creator return must retire the suspended helper, not issue it.
    ticket = begin();
    stop.Request(trace, TraceReason::cancelled, now);
    assert(stop.Reserve(trace, now + 50ms) == ticket);
    stop.AbandonIssue(stale);
    stop.AbandonIssue(ticket);
    assert(!stop.Issue(ticket, 104U, 0x77000000U));
    stop.FinishInterrupt(trace, ticket, true);
    assert(!stop.ThreadCreated(7U, 42U, 104U, true, 0x77000000U));
    assert(trace.Active());
    stop.ProcessExited(trace);
    assert(trace.Terminal());

    for (const auto method : {"debugger.resume", "debugger.stop", "memory.write",
                              "trace.cancel", "scyllahide.profile"}) {
        assert(mcp::TraceHelperAllowsMutation(method));
    }
    for (const auto method : {"trace.start", "debugger.run_to_address", "debugger.step_into",
                              "debugger.step_over", "debugger.step_out",
                              "debugger.continue_exception", "debuggee.detach",
                              "breakpoints.set", "breakpoints.remove", "breakpoints.enable",
                              "breakpoints.disable", "breakpoints.hardware.set",
                              "breakpoints.hardware.remove", "breakpoints.memory.set",
                              "breakpoints.memory.remove", "breakpoints.conditional.set",
                              "breakpoints.conditional.remove", "breakpoints.exception.set",
                              "breakpoints.exception.remove", "assembly.patch", "patches.restore",
                              "registers.write", "analysis.function", "debuggee.launch",
                              "debuggee.launch_dll", "debuggee.attach", "future.mutation"}) {
        assert(!mcp::TraceHelperAllowsMutation(method));
    }
}
} // namespace

int main() {
    StopSchedules();
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
