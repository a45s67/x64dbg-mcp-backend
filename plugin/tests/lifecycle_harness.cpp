#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>

#include <array>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <thread>

#include <string>
#include <string_view>

#include "runtime.h"
#include "_plugins.h"
#include "jansson/jansson.h"

namespace {
struct JsonDeleter {
    void operator()(json_t* value) const noexcept { json_decref(value); }
};
using Json = std::unique_ptr<json_t, JsonDeleter>;

bool JsonStringEquals(const json_t* value, const std::string_view expected) {
    return json_is_string(value) &&
           std::string_view(json_string_value(value), json_string_length(value)) == expected;
}

bool JsonIntegerEquals(const json_t* value, const std::uint64_t expected) {
    return json_is_integer(value) && json_integer_value(value) >= 0 &&
           static_cast<std::uint64_t>(json_integer_value(value)) == expected;
}

Json DecodeToolResult(const std::string_view response, const std::uint64_t requestId,
                      const bool expectError = false) {
    const auto separator = response.find("\r\n\r\n");
    if (!response.starts_with("HTTP/1.1 200 ") || separator == std::string_view::npos) {
        return {};
    }
    const auto body = response.substr(separator + 4U);
    const Json envelope(json_loadb(body.data(), body.size(), JSON_REJECT_DUPLICATES, nullptr));
    const json_t* result = json_object_get(envelope.get(), "result");
    const json_t* content = json_object_get(result, "content");
    const json_t* block = json_array_get(content, 0U);
    const json_t* text = json_object_get(block, "text");
    // Enforce the content-only contract, including no structuredContent mirror.
    if (!json_is_object(envelope.get()) || json_object_size(envelope.get()) != 3U ||
        !JsonStringEquals(json_object_get(envelope.get(), "jsonrpc"), "2.0") ||
        !JsonIntegerEquals(json_object_get(envelope.get(), "id"), requestId) ||
        !json_is_object(result) || json_object_size(result) != 2U ||
        (expectError ? !json_is_true(json_object_get(result, "isError"))
                     : !json_is_false(json_object_get(result, "isError"))) ||
        !json_is_array(content) || json_array_size(content) != 1U ||
        !json_is_object(block) || json_object_size(block) != 2U ||
        !JsonStringEquals(json_object_get(block, "type"), "text") || !json_is_string(text)) {
        return {};
    }
    Json payload(json_loadb(json_string_value(text), json_string_length(text),
                            JSON_REJECT_DUPLICATES, nullptr));
    if (!json_is_object(payload.get())) return {};
    return payload;
}

bool ExerciseContentDecoding() {
    const auto response = [](const std::string_view result) {
        return "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
               "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":" + std::string(result) + "}";
    };
    constexpr std::string_view valid =
        R"({"content":[{"type":"text","text":"{ \"debuggee_state\": \"abse\u006et\" }"}],"isError":false})";
    const Json decoded = DecodeToolResult(response(valid), 1U);
    if (!JsonStringEquals(json_object_get(decoded.get(), "debuggee_state"), "absent") ||
        DecodeToolResult(response(valid), 2U)) return false;
    for (const auto invalid : {
             R"({"content":[{"type":"text","text":"{}"}],"isError":false,"structuredContent":{}})",
             R"({"content":[{"type":"text","text":"{}"}],"isError":true})",
             R"({"content":[{"type":"text","text":"{}"}],"isError":0})",
             R"({"content":[{"type":"text","text":"{}"}]})",
             R"({"content":[],"isError":false})",
             R"({"content":[{"type":"text","text":"{}"},{"type":"text","text":"{}"}],"isError":false})",
             R"({"content":[{"type":"image","text":"{}"}],"isError":false})",
             R"({"content":[{"type":"text","text":{}}],"isError":false})",
             R"({"content":[{"type":"text","text":"not JSON"}],"isError":false})",
             R"({"content":[{"type":"text","text":"[]"}],"isError":false})",
             R"({"content":[{"type":"text","text":"{} trailing"}],"isError":false})",
             R"({"content":[{"type":"text","text":"{\"x\":1,\"x\":2}"}],"isError":false})",
             R"({"content":[{"type":"text","text":"{}"}],"isError":true,"isError":false})"}) {
        if (DecodeToolResult(response(invalid), 1U)) return false;
    }
    return !DecodeToolResult("HTTP/1.1 500 Error\r\n\r\n{}", 1U) &&
           !DecodeToolResult("HTTP/1.1 200 OK\r\n\r\n{", 1U) &&
           !DecodeToolResult(response(valid) + " trailing", 1U);
}

std::string PostMcp(const unsigned short port, const std::string_view body) {
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
        return {};
    }
    SOCKET socketValue = INVALID_SOCKET;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (std::chrono::steady_clock::now() < deadline) {
        socketValue = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (socketValue == INVALID_SOCKET) {
            break;
        }
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(port);
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (connect(socketValue, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == 0) {
            break;
        }
        closesocket(socketValue);
        socketValue = INVALID_SOCKET;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    if (socketValue == INVALID_SOCKET) {
        WSACleanup();
        return {};
    }
    const std::string request =
        "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer "
        "0123456789abcdef0123456789abcdef\r\nContent-Type: application/json\r\n"
        "Accept: application/json\r\nConnection: close\r\nContent-Length: " +
        std::to_string(body.size()) + "\r\n\r\n" + std::string(body);
    std::size_t sent = 0;
    while (sent < request.size()) {
        const int chunk = send(socketValue, request.data() + sent,
                               static_cast<int>(request.size() - sent), 0);
        if (chunk <= 0) {
            closesocket(socketValue);
            WSACleanup();
            return {};
        }
        sent += static_cast<std::size_t>(chunk);
    }
    std::string response;
    std::array<char, 4096> buffer{};
    for (;;) {
        const int count = recv(socketValue, buffer.data(), static_cast<int>(buffer.size()), 0);
        if (count <= 0) {
            break;
        }
        response.append(buffer.data(), static_cast<std::size_t>(count));
        if (response.size() > 65536U) {
            break;
        }
    }
    closesocket(socketValue);
    WSACleanup();
    return response;
}

bool ExerciseStateTool(const unsigned short port) {
    constexpr std::string_view body =
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"debugger.state\",\"arguments\":{}}}";
    const Json result = DecodeToolResult(PostMcp(port, body), 1U);
    return JsonStringEquals(json_object_get(result.get(), "debuggee_state"), "absent") &&
           JsonStringEquals(json_object_get(result.get(), "plugin_state"), "ready") &&
           JsonStringEquals(json_object_get(result.get(), "diagnostic_code"), "NO_DEBUGGEE") &&
           json_is_null(json_object_get(result.get(), "process_id"));
}

bool ExerciseActiveWaitShutdown(mcp::Runtime& runtime, const unsigned short port) {
    runtime.OnDebuggerEvent(CB_RESUMEDEBUG, nullptr);
    std::atomic_bool completed{false};
    std::thread request([port, &completed] {
        constexpr std::string_view body =
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"debugger.wait_for_pause\",\"arguments\":{\"after_generation\":9007199254740991,\"timeout_ms\":9000}}}";
        (void)PostMcp(port, body);
        completed.store(true);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    const auto start = std::chrono::steady_clock::now();
    runtime.Stop();
    request.join();
    return completed.load() &&
           std::chrono::steady_clock::now() - start < std::chrono::seconds(3);
}

bool ExerciseActiveTraceShutdown(mcp::Runtime& runtime) {
    runtime.OnDebuggerEvent(CB_RESUMEDEBUG, nullptr);
    runtime.OnDebuggerEvent(CB_PAUSEDEBUG, nullptr);
    if (!runtime.StartTraceForTesting()) return false;
    const auto start = std::chrono::steady_clock::now();
    runtime.Stop();
    return runtime.TraceReasonForTesting() == mcp::TraceReason::backendShutdown &&
           std::chrono::steady_clock::now() - start < std::chrono::seconds(3);
}

bool ExerciseTraceCommitCallbacks(mcp::Runtime& runtime) {
    runtime.OnDebuggerEvent(CB_RESUMEDEBUG, nullptr);
    DEBUG_EVENT raw{};
    raw.dwDebugEventCode = EXCEPTION_DEBUG_EVENT;
    raw.dwProcessId = 42U;
    raw.dwThreadId = 99U;
    raw.u.Exception.ExceptionRecord.ExceptionCode = EXCEPTION_BREAKPOINT;
    raw.u.Exception.dwFirstChance = 1U;
    PLUG_CB_DEBUGEVENT rawInfo{&raw};
    runtime.OnDebuggerEvent(CB_DEBUGEVENT, &rawInfo);
    BRIDGEBP breakpoint{};
    breakpoint.type = bp_normal;
    breakpoint.addr = 0x401000U;
    PLUG_CB_BREAKPOINT bpInfo{&breakpoint};
    runtime.OnDebuggerEvent(CB_BREAKPOINT, &bpInfo);
    // CB_BREAKPOINT exposes a paused snapshot before handleBreakCondition
    // clears native tracing. Only this raw event's CB_PAUSEDEBUG admits a trace.
    if (!runtime.BeginPausedSnapshotForTesting() || runtime.StartTraceForTesting()) return false;
    runtime.OnDebuggerEvent(CB_PAUSEDEBUG, nullptr);
    runtime.OnDebuggerEvent(CB_DEBUGEVENT, &rawInfo);
    runtime.OnDebuggerEvent(CB_BREAKPOINT, &bpInfo);
    if (runtime.StartTraceForTesting()) return false; // Previous raw event's commit is stale.
    runtime.OnDebuggerEvent(CB_PAUSEDEBUG, nullptr);
    const auto before = runtime.PauseForTesting().generation;
    if (!runtime.StartTraceForTesting(true)) return false;
    if (runtime.CanUnload()) return false;
    PLUG_CB_TRACEEXECUTE step{};
    step.cip = 0x401001U;
    step.stop = true;
    runtime.OnDebuggerEvent(CB_TRACEEXECUTE, &step);
    if (runtime.TraceReasonForTesting() != mcp::TraceReason::none ||
        runtime.StartTraceForTesting()) return false;
    // The debug loop can pause before native run emits CB_RESUMEDEBUG.
    runtime.OnDebuggerEvent(CB_PAUSEDEBUG, nullptr);
    const auto paused = runtime.PauseForTesting().generation;
    if (paused <= before || runtime.StartTraceForTesting()) return false;
    runtime.OnDebuggerEvent(CB_RESUMEDEBUG, nullptr);
    if (!runtime.BeginPausedSnapshotForTesting() ||
        runtime.TraceReasonForTesting() != mcp::TraceReason::none) return false;
    runtime.SubmitTraceForTesting();
    if (runtime.TraceReasonForTesting() != mcp::TraceReason::interrupted ||
        !runtime.BeginPausedSnapshotForTesting() || !runtime.StartTraceForTesting()) return false;
    // A refinement still on the preceding pause's callback stack cannot
    // finalize or change the newly admitted trace's state/generation.
    runtime.OnDebuggerEvent(CB_STEPPED, nullptr);
    runtime.OnDebuggerEvent(CB_EXCEPTION, nullptr);
    runtime.OnDebuggerEvent(CB_BREAKPOINT, nullptr);
    if (runtime.TraceReasonForTesting() != mcp::TraceReason::none ||
        runtime.PauseForTesting().generation != paused || runtime.StartTraceForTesting()) return false;
    runtime.OnDebuggerEvent(CB_STOPPINGDEBUG, nullptr);
    if (runtime.TraceReasonForTesting() != mcp::TraceReason::none) return false;
    runtime.OnDebuggerEvent(CB_STOPDEBUG, nullptr);
    return runtime.TraceReasonForTesting() == mcp::TraceReason::processExit && runtime.CanUnload();
}

bool ExerciseOwnedTraceCreatePause(mcp::Runtime& runtime, const unsigned short port) {
    DEBUG_EVENT raw{};
    raw.dwDebugEventCode = EXCEPTION_DEBUG_EVENT;
    raw.dwProcessId = 42U;
    raw.dwThreadId = 98U;
    PLUG_CB_DEBUGEVENT rawInfo{&raw};
    runtime.OnDebuggerEvent(CB_DEBUGEVENT, &rawInfo);
    runtime.OnDebuggerEvent(CB_RESUMEDEBUG, nullptr);
    runtime.OnDebuggerEvent(CB_PAUSEDEBUG, nullptr);
    if (!runtime.StartTraceForTesting()) return false;
    runtime.IssueTraceInterruptForTesting(99U, 0x77000001U);
    const auto before = runtime.PauseForTesting().generation;
    CREATE_THREAD_DEBUG_INFO created{};
    created.lpStartAddress = reinterpret_cast<LPTHREAD_START_ROUTINE>(0x77000001U);
    PLUG_CB_CREATETHREAD createdInfo{&created, 99U};
    // Even a matching raw INT3 must never consume ownership or change exception
    // disposition. The new interrupt has no dependency on exception filters.
    raw.dwThreadId = 99U;
    raw.u.Exception.ExceptionRecord.ExceptionCode = EXCEPTION_BREAKPOINT;
    raw.u.Exception.ExceptionRecord.ExceptionAddress = reinterpret_cast<void*>(0x77000001U);
    raw.u.Exception.dwFirstChance = 1U;
    runtime.OnDebuggerEvent(CB_DEBUGEVENT, &rawInfo);
    runtime.OnDebuggerEvent(CB_CREATETHREAD, &createdInfo);
    if (runtime.TraceReasonForTesting() != mcp::TraceReason::none ||
        runtime.PauseForTesting().generation != before) return false;
    raw.dwDebugEventCode = CREATE_THREAD_DEBUG_EVENT;
    raw.u.CreateThread = created;
    raw.dwProcessId = 43U;
    runtime.OnDebuggerEvent(CB_DEBUGEVENT, &rawInfo);
    runtime.OnDebuggerEvent(CB_CREATETHREAD, &createdInfo);
    if (runtime.TraceReasonForTesting() != mcp::TraceReason::none) return false;
    raw.dwProcessId = 42U;
    raw.dwThreadId = 100U;
    runtime.OnDebuggerEvent(CB_DEBUGEVENT, &rawInfo);
    runtime.OnDebuggerEvent(CB_CREATETHREAD, &createdInfo);
    if (runtime.TraceReasonForTesting() != mcp::TraceReason::none) return false;
    raw.dwThreadId = 99U;
    runtime.OnDebuggerEvent(CB_DEBUGEVENT, &rawInfo);
    if (runtime.TraceReasonForTesting() != mcp::TraceReason::none) return false;
    std::thread callback([&] { runtime.OnDebuggerEvent(CB_CREATETHREAD, &createdInfo); });
    const auto pauseDeadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (runtime.TraceReasonForTesting() == mcp::TraceReason::none &&
           std::chrono::steady_clock::now() < pauseDeadline) std::this_thread::yield();
    const auto paused = runtime.PauseForTesting();
    const bool committed = runtime.TraceReasonForTesting() == mcp::TraceReason::timeout &&
        paused.generation > before && paused.kind == mcp::PauseReasonKind::userPause &&
        !paused.hasExceptionCode && runtime.BeginPausedSnapshotForTesting() && !runtime.CanUnload();
    const Json state = DecodeToolResult(PostMcp(port,
        "{\"jsonrpc\":\"2.0\",\"id\":69,\"method\":\"tools/call\",\"params\":{\"name\":\"debugger.state\",\"arguments\":{}}}"), 69U);
    const char* instance = json_string_value(json_object_get(state.get(), "instance_id"));
    bool rejectedBeforeDispatch = committed && instance != nullptr;
    const HANDLE entered = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    const HANDLE release = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (entered && release) {
        std::atomic_bool executorFinished{false};
        std::thread blocker([&] {
            runtime.HoldExecutorForTesting(entered, release);
            executorFinished.store(true);
        });
        rejectedBeforeDispatch = rejectedBeforeDispatch && WaitForSingleObject(entered, 2000U) == WAIT_OBJECT_0;
        for (unsigned index = 0U; rejectedBeforeDispatch && index < 2U; ++index) {
            const std::string method = index == 0U ? "breakpoints.set" : "breakpoints.remove";
            const std::string body =
                "{\"jsonrpc\":\"2.0\",\"id\":" + std::to_string(70U + index) +
                ",\"method\":\"tools/call\",\"params\":{\"name\":\"" + method +
                "\",\"arguments\":{\"operation_id\":\"00000000-0000-4000-8000-00000000007" +
                std::to_string(index) + "\",\"instance_id\":\"" + instance +
                "\",\"address\":\"0x401005\"}}}";
            const std::string response = PostMcp(port, body);
            const Json rejected = DecodeToolResult(response, 70U + index, true);
            const auto* error = json_object_get(rejected.get(), "error");
            const auto* details = json_object_get(error, "details");
            // This response must arrive while the executor is still occupied,
            // with no SDK/command admission, no unknown outcome and no mutation.
            rejectedBeforeDispatch = !executorFinished.load() &&
                JsonStringEquals(json_object_get(error, "code"), "INVALID_DEBUGGER_STATE") &&
                json_is_false(json_object_get(error, "safeToRetry")) && json_is_object(details) &&
                json_object_size(details) == 1U && json_is_string(json_object_get(details, "debugger_message")) &&
                json_object_get(details, "outcome") == nullptr &&
                runtime.PauseForTesting().generation == paused.generation;
            if (!rejectedBeforeDispatch) std::cerr << "helper admission response: " << response << '\n';
        }
        SetEvent(release);
        blocker.join();
    } else {
        rejectedBeforeDispatch = false;
    }
    if (entered) CloseHandle(entered);
    if (release) CloseHandle(release);
    // _plugin_debugpause's native stack frame remains live until explicit run.
    runtime.OnDebuggerEvent(CB_RESUMEDEBUG, nullptr);
    callback.join();
    if (!committed || !rejectedBeforeDispatch || !runtime.CanUnload()) return false;
    runtime.OnDebuggerEvent(CB_CREATETHREAD, &createdInfo);
    if (runtime.PauseForTesting().generation != paused.generation) return false;
    runtime.OnDebuggerEvent(CB_STOPDEBUG, nullptr);
    return true;
}

bool ExerciseTraceReloadReconciliation() {
    std::array<wchar_t, 32768U> executable{};
    if (!GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()))) return false;
    std::wstring command = L"\"" + std::wstring(executable.data()) + L"\" trace-exit-probe";
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(nullptr, command.data(), nullptr, nullptr, FALSE,
                        CREATE_SUSPENDED | CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process)) return false;
    bool valid = false;
    {
        mcp::Runtime retained;
        retained.SetTraceProcessForTesting(process.hProcess);
        retained.OnDebuggerEvent(CB_RESUMEDEBUG, nullptr);
        retained.OnDebuggerEvent(CB_PAUSEDEBUG, nullptr);
        valid = retained.StartTraceForTesting();
        retained.IssueTraceInterruptForTesting(99U, 0x77000001U);
        // Model a retained DLL with its callbacks unregistered. Alive means no
        // reload; actual process-handle death must be reconciled by Start itself.
        valid = valid && !retained.Start() && !retained.CanUnload();
        const DWORD resumed = ResumeThread(process.hThread);
        valid = valid && resumed != static_cast<DWORD>(-1);
        const DWORD exited = WaitForSingleObject(process.hProcess, 5000U);
        valid = valid && exited == WAIT_OBJECT_0;
        if (valid) {
            valid = retained.Start() && retained.TraceReasonForTesting() == mcp::TraceReason::timeout &&
                retained.CanUnload();
            const auto readyDeadline = std::chrono::steady_clock::now() + std::chrono::seconds(7);
            while (valid && !retained.IsReady() && std::chrono::steady_clock::now() < readyDeadline) {
                std::this_thread::yield();
            }
            valid = valid && retained.IsReady();
        }
        retained.Stop();
    }
    if (valid) {
        mcp::Runtime newer;
        newer.SetTraceProcessForTesting(process.hProcess);
        newer.OnDebuggerEvent(CB_RESUMEDEBUG, nullptr);
        newer.OnDebuggerEvent(CB_PAUSEDEBUG, nullptr);
        valid = newer.StartTraceForTesting();
        newer.IssueTraceInterruptForTesting(99U, 0x77000001U);
        // Same PID but a new process epoch must not be erased by reconciliation.
        PLUG_CB_CREATEPROCESS created{};
        created.fdProcessInfo = &process;
        newer.OnDebuggerEvent(CB_CREATEPROCESS, &created);
        newer.ReconcileTraceProcessForTesting();
        valid = valid && newer.SessionOriginForTesting() == mcp::SessionOrigin::launched &&
            newer.PauseForTesting().kind == mcp::PauseReasonKind::processCreated &&
            newer.TraceReasonForTesting() == mcp::TraceReason::timeout;
    }
    if (WaitForSingleObject(process.hProcess, 0U) != WAIT_OBJECT_0) {
        TerminateProcess(process.hProcess, ERROR_CANCELLED);
        WaitForSingleObject(process.hProcess, 5000U);
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return valid;
}

bool ExercisePauseCallbacks(mcp::Runtime& runtime) {
    runtime.OnDebuggerEvent(CB_RESUMEDEBUG, nullptr);
    BRIDGEBP breakpoint{};
    breakpoint.type = bp_normal;
    breakpoint.addr = static_cast<duint>(0x401000U);
    breakpoint.hitCount = 3U;
    PLUG_CB_BREAKPOINT breakpointInfo{&breakpoint};
    runtime.OnDebuggerEvent(CB_BREAKPOINT, &breakpointInfo);
    const mcp::PauseObservation specific = runtime.PauseForTesting();
    const std::optional<std::uint64_t> snapshot = runtime.BeginPausedSnapshotForTesting();
    if (!snapshot || !runtime.PausedSnapshotCurrentForTesting(*snapshot)) {
        return false;
    }
    runtime.OnDebuggerEvent(CB_PAUSEDEBUG, nullptr);
    const mcp::PauseObservation afterGeneric = runtime.PauseForTesting();
    if (specific.kind != mcp::PauseReasonKind::breakpoint || !specific.hasAddress ||
        specific.address != 0x401000U || specific.hitCount != 3U ||
        specific.generation == 0U || afterGeneric.generation != specific.generation ||
        afterGeneric.kind != mcp::PauseReasonKind::breakpoint) {
        return false;
    }

    runtime.OnDebuggerEvent(CB_RESUMEDEBUG, nullptr);
    DEBUG_EVENT rawException{};
    rawException.dwDebugEventCode = EXCEPTION_DEBUG_EVENT;
    rawException.dwProcessId = 0x1234U;
    rawException.dwThreadId = 0x5678U;
    rawException.u.Exception.ExceptionRecord.ExceptionCode = 0xe0424242U;
    rawException.u.Exception.ExceptionRecord.ExceptionAddress =
        reinterpret_cast<void*>(0x401234U);
    rawException.u.Exception.dwFirstChance = 1U;
    PLUG_CB_DEBUGEVENT rawExceptionInfo{&rawException};
    runtime.OnDebuggerEvent(CB_DEBUGEVENT, &rawExceptionInfo);
    BRIDGEBP exceptionBreakpoint{};
    exceptionBreakpoint.type = bp_exception;
    exceptionBreakpoint.addr = static_cast<duint>(0xe0424242U);
    exceptionBreakpoint.hitCount = 1U;
    PLUG_CB_BREAKPOINT exceptionBreakpointInfo{&exceptionBreakpoint};
    runtime.OnDebuggerEvent(CB_BREAKPOINT, &exceptionBreakpointInfo);
    const mcp::PauseObservation correlatedException = runtime.PauseForTesting();
    if (correlatedException.kind != mcp::PauseReasonKind::exception ||
        !correlatedException.hasExceptionCode ||
        correlatedException.exceptionCode != 0xe0424242U ||
        !correlatedException.hasAddress || correlatedException.address != 0x401234U ||
        !correlatedException.firstChance) {
        return false;
    }

    runtime.OnDebuggerEvent(CB_RESUMEDEBUG, nullptr);
    if (runtime.PausedSnapshotCurrentForTesting(*snapshot)) {
        return false;
    }
    EXCEPTION_DEBUG_INFO exception{};
    exception.ExceptionRecord.ExceptionCode = EXCEPTION_ACCESS_VIOLATION;
    exception.ExceptionRecord.ExceptionAddress = reinterpret_cast<void*>(0x402000U);
    exception.dwFirstChance = 1U;
    PLUG_CB_EXCEPTION exceptionInfo{&exception};
    runtime.OnDebuggerEvent(CB_EXCEPTION, &exceptionInfo);
    const mcp::PauseObservation capturedException = runtime.PauseForTesting();
    const std::vector<mcp::EventRecord> events = runtime.EventsForTesting();
    const mcp::EventRecord& capturedEvent = events.back();
    return capturedException.kind == mcp::PauseReasonKind::exception &&
           capturedException.hasExceptionCode &&
           capturedException.exceptionCode == EXCEPTION_ACCESS_VIOLATION &&
           capturedException.hasAddress && capturedException.address == 0x402000U &&
           capturedException.firstChance && capturedException.generation > specific.generation &&
           capturedEvent.kind == mcp::EventKind::exception && capturedEvent.hasCode &&
           capturedEvent.code == EXCEPTION_ACCESS_VIOLATION && capturedEvent.hasAddress &&
           capturedEvent.address == 0x402000U && capturedEvent.firstChance;
}

bool ExerciseSessionOriginCallbacks(mcp::Runtime& runtime) {
    runtime.OnDebuggerEvent(CB_STOPDEBUG, nullptr);
    runtime.OnDebuggerEvent(CB_INITDEBUG, nullptr);
    if (runtime.SessionOriginForTesting() != mcp::SessionOrigin::none) return false;
    PLUG_CB_ATTACH attach{0x1234U};
    runtime.OnDebuggerEvent(CB_ATTACH, &attach);
    if (runtime.SessionOriginForTesting() != mcp::SessionOrigin::attached) return false;
    PROCESS_INFORMATION process{};
    process.dwProcessId = attach.dwProcessId;
    PLUG_CB_DETACH detach{&process};
    runtime.OnDebuggerEvent(CB_DETACH, &detach);
    if (runtime.SessionOriginForTesting() != mcp::SessionOrigin::attached) return false;
    runtime.OnDebuggerEvent(CB_STOPDEBUG, nullptr);
    return runtime.SessionOriginForTesting() == mcp::SessionOrigin::none;
}

bool ExerciseEventHistory(mcp::Runtime& runtime, const unsigned short port) {
    mcp::Runtime emptyRuntime;
    if (!emptyRuntime.EventsForTesting().empty()) return false;
    const auto preceding = runtime.EventsForTesting();
    runtime.OnDebuggerEvent(CB_INITDEBUG, nullptr);
    // A failed launch attempt must not invalidate the retained session.
    if (runtime.EventsForTesting().size() != preceding.size()) return false;
    runtime.OnDebuggerEvent(CB_CREATEPROCESS, nullptr);
    const auto established = runtime.EventsForTesting();
    if (established.size() != 2U || established[0].kind != mcp::EventKind::debugInitialized ||
        established[1].kind != mcp::EventKind::processCreated ||
        established[0].sessionId != established[1].sessionId) return false;
    const std::string session(established[0].sessionId.data());
    const std::uint64_t previousLatest = established.back().sequence;
    for (std::uint64_t sequence = 1U; sequence <= 300U; ++sequence) {
        runtime.OnDebuggerEvent(CB_RESUMEDEBUG, nullptr);
    }
    const std::vector<mcp::EventRecord> events = runtime.EventsForTesting();
    if (events.size() != 302U || events.front().kind != mcp::EventKind::debugInitialized ||
        events.back().sequence != previousLatest + 300U) {
        return false;
    }
    for (std::size_t index = 2U; index < events.size(); ++index) {
        if (events[index].kind != mcp::EventKind::resumed ||
            events[index].sequence != previousLatest + static_cast<std::uint64_t>(index) - 1U ||
            (index > 0U && events[index - 1U].generation >= events[index].generation)) {
            return false;
        }
    }
    constexpr std::string_view body =
        "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"events.list\",\"arguments\":{\"types\":[\"resumed\"],\"limit\":256}}}";
    const Json result = DecodeToolResult(PostMcp(port, body), 3U);
    const json_t* items = json_object_get(result.get(), "items");
    const json_t* cursor = json_object_get(result.get(), "next_cursor");
    if (!json_is_array(items) || json_array_size(items) != 256U || !json_is_string(cursor) ||
        !json_is_true(json_object_get(result.get(), "history_complete")) ||
        !JsonStringEquals(json_object_get(result.get(), "session_id"), session)) return false;
    const std::string secondBody =
        "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{"
        "\"name\":\"events.list\",\"arguments\":{\"cursor\":\"" +
        std::string(json_string_value(cursor), json_string_length(cursor)) +
        "\",\"types\":[\"resumed\"],\"limit\":256}}}";
    const Json second = DecodeToolResult(PostMcp(port, secondBody), 4U);
    const json_t* secondItems = json_object_get(second.get(), "items");
    if (!json_is_array(secondItems) || json_array_size(secondItems) != 44U ||
        !json_is_null(json_object_get(second.get(), "next_cursor"))) return false;

    constexpr std::string_view futureWaitBody =
        "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\",\"params\":{"
        "\"name\":\"events.wait\",\"arguments\":{}}}";
    std::string futureWaitResponse;
    std::thread futureWait([port, &futureWaitBody, &futureWaitResponse] {
        futureWaitResponse = PostMcp(port, futureWaitBody);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    runtime.OnDebuggerEvent(CB_PAUSEDEBUG, nullptr);
    futureWait.join();
    const Json futureWaitResult = DecodeToolResult(futureWaitResponse, 5U);
    const json_t* futureEvent = json_object_get(futureWaitResult.get(), "event");
    const bool futureWaitValid = JsonStringEquals(json_object_get(futureEvent, "type"), "paused") &&
        JsonIntegerEquals(json_object_get(futureEvent, "sequence"), events.back().sequence + 1U);
    runtime.OnDebuggerEvent(CB_STOPDEBUG, nullptr);
    const auto stopped = runtime.EventsForTesting();
    if (!futureWaitValid || stopped.empty() || stopped.back().kind != mcp::EventKind::debugStopped) return false;
    runtime.OnDebuggerEvent(CB_INITDEBUG, nullptr);
    if (runtime.EventsForTesting().size() != stopped.size()) return false;
    runtime.OnDebuggerEvent(CB_CREATEPROCESS, nullptr);
    const auto reset = runtime.EventsForTesting();
    return reset.size() == 2U && std::string(reset.front().sessionId.data()) != session;
}
} // namespace

int wmain(const int argc, wchar_t** argv) {
    if (argc == 2 && std::wstring_view(argv[1]) == L"trace-exit-probe") return 0;
    if (argc < 3 || argc > 4) {
        std::cerr << "usage: lifecycle_harness <server-exe> <unused-port> "
                     "[sidecar-crash|installed-config|active-wait-shutdown|active-trace-shutdown]\n";
        return 2;
    }
    if (!ExerciseContentDecoding()) {
        std::cerr << "content-only JSON decoding contract failed\n";
        return 14;
    }
    const bool installedConfig = argc == 4 && std::wstring_view(argv[3]) == L"installed-config";
    std::filesystem::path serverPath = argv[1];
    std::filesystem::path temporaryDirectory;
    std::filesystem::path configPath;
    if (installedConfig) {
#ifdef _WIN64
        constexpr wchar_t configName[] = L"x64dbg-mcp-server-x64.toml";
#else
        constexpr wchar_t configName[] = L"x64dbg-mcp-server-x32.toml";
#endif
        temporaryDirectory = std::filesystem::temp_directory_path() /
                             (L"x64dbg-mcp-installed-config-" +
                              std::to_wstring(GetCurrentProcessId()));
        std::filesystem::create_directory(temporaryDirectory);
        serverPath = temporaryDirectory / std::filesystem::path(argv[1]).filename();
        std::filesystem::copy_file(argv[1], serverPath,
                                   std::filesystem::copy_options::overwrite_existing);
        configPath = temporaryDirectory / configName;
        std::ofstream config(configPath, std::ios::binary | std::ios::trunc);
        config << "bind = \"127.0.0.1\"\nport = " << std::filesystem::path(argv[2]).string()
               << "\nbearer_token = \"0123456789abcdef0123456789abcdef\"\n";
        if (!config) {
            std::cerr << "could not create installed-layout config\n";
            return 3;
        }
        SetEnvironmentVariableW(L"X64DBG_MCP_PORT", nullptr);
        SetEnvironmentVariableW(L"X64DBG_MCP_TOKEN", nullptr);
    }
    struct ConfigCleanup {
        std::filesystem::path directory;
        ~ConfigCleanup() {
            if (!directory.empty()) {
                std::error_code error;
                std::filesystem::remove_all(directory, error);
            }
        }
    } cleanup{temporaryDirectory};
    if (SetEnvironmentVariableW(L"X64DBG_MCP_SERVER_PATH", serverPath.c_str()) == FALSE ||
        (!installedConfig &&
         (SetEnvironmentVariableW(L"X64DBG_MCP_PORT", argv[2]) == FALSE ||
          SetEnvironmentVariableW(L"X64DBG_MCP_TOKEN",
                                  L"0123456789abcdef0123456789abcdef") == FALSE))) {
        return 3;
    }

    if (!ExerciseTraceReloadReconciliation()) {
        std::cerr << "retained trace process reconciliation failed\n";
        return 15;
    }
    mcp::Runtime runtime;
    if (!runtime.Start()) {
        std::cerr << "runtime startup failed\n";
        return 4;
    }
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(7);
    while (!runtime.IsReady() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    if (!runtime.IsReady()) {
        runtime.Stop();
        std::cerr << "authenticated handshake did not complete\n";
        return 5;
    }
    const unsigned long parsedPort = wcstoul(argv[2], nullptr, 10);
    if (parsedPort == 0UL || parsedPort > 65535UL ||
        !ExerciseStateTool(static_cast<unsigned short>(parsedPort))) {
        runtime.Stop();
        std::cerr << "end-to-end debugger.state call failed\n";
        return 7;
    }
    if (!ExercisePauseCallbacks(runtime)) {
        runtime.Stop();
        std::cerr << "callback pause observation contract failed\n";
        return 9;
    }
    if (!ExerciseSessionOriginCallbacks(runtime)) {
        runtime.Stop();
        std::cerr << "attach/detach session-origin callback contract failed\n";
        return 11;
    }
    if (!ExerciseTraceCommitCallbacks(runtime)) {
        runtime.Stop();
        std::cerr << "trace pause/submission publication contract failed\n";
        return 14;
    }
    if (!ExerciseOwnedTraceCreatePause(runtime, static_cast<unsigned short>(parsedPort))) {
        runtime.Stop();
        std::cerr << "owned create-thread pause contract failed\n";
        return 16;
    }
    if (!ExerciseEventHistory(runtime, static_cast<unsigned short>(parsedPort))) {
        runtime.Stop();
        std::cerr << "debugger-event history contract failed\n";
        return 12;
    }
    if (argc == 4 && std::wstring_view(argv[3]) == L"active-wait-shutdown") {
        if (!ExerciseActiveWaitShutdown(runtime, static_cast<unsigned short>(parsedPort))) {
            std::cerr << "active callback wait delayed runtime shutdown\n";
            return 10;
        }
        return 0;
    }
    if (argc == 4 && std::wstring_view(argv[3]) == L"active-trace-shutdown") {
        if (!ExerciseActiveTraceShutdown(runtime)) {
            std::cerr << "active trace delayed runtime shutdown or lost its terminal reason\n";
            return 13;
        }
        return 0;
    }
    if (argc == 4 && std::wstring_view(argv[3]) == L"sidecar-crash") {
        const DWORD sidecarId = runtime.SidecarProcessIdForTesting();
        HANDLE process = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, sidecarId);
        if (process == nullptr || TerminateProcess(process, ERROR_PROCESS_ABORTED) == FALSE ||
            WaitForSingleObject(process, 2000U) != WAIT_OBJECT_0) {
            if (process != nullptr) {
                CloseHandle(process);
            }
            runtime.Stop();
            std::cerr << "could not inject sidecar crash\n";
            return 8;
        }
        CloseHandle(process);
    }
    const auto start = std::chrono::steady_clock::now();
    runtime.Stop();
    if (std::chrono::steady_clock::now() - start > std::chrono::seconds(7)) {
        std::cerr << "runtime shutdown exceeded deadline\n";
        return 6;
    }
    return 0;
}
