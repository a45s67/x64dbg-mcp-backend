#include <Windows.h>

#include <charconv>
#include <cstdint>
#include <string_view>

#include "_plugins.h"
#include "runtime.h"

namespace {
constexpr char kPluginName[] = "x64dbg-mcp-backend";
constexpr char kFenceCommand[] = "x64dbg_mcp_fence_internal";
constexpr int kPluginVersion = 1;
int g_pluginHandle = 0;
mcp::Runtime g_runtime;

void DebuggerCallback(const CBTYPE callbackType, void* callbackInfo) {
    g_runtime.OnDebuggerEvent(static_cast<int>(callbackType), callbackInfo);
}

bool CommandFenceCallback(const int argc, char** argv) {
    if (argc != 2 || argv == nullptr || argv[1] == nullptr) return false;
    const std::string_view encoded(argv[1]);
    if (encoded.size() != 16U) return false;
    std::uint64_t token = 0U;
    const auto parsed = std::from_chars(encoded.data(), encoded.data() + encoded.size(), token, 16);
    return parsed.ec == std::errc{} && parsed.ptr == encoded.data() + encoded.size() &&
           token != 0U && g_runtime.OnCommandFence(token);
}
} // namespace

extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT* initStruct) {
    if (initStruct == nullptr) {
        return false;
    }
    initStruct->pluginVersion = kPluginVersion;
    initStruct->sdkVersion = PLUG_SDKVERSION;
    strcpy_s(initStruct->pluginName, kPluginName);
    g_pluginHandle = initStruct->pluginHandle;
    constexpr CBTYPE callbacks[] = {CB_INITDEBUG, CB_STOPDEBUG, CB_CREATEPROCESS,
                                    CB_EXITPROCESS, CB_PAUSEDEBUG, CB_RESUMEDEBUG,
                                    CB_STEPPED, CB_ATTACH, CB_DETACH, CB_STOPPINGDEBUG, CB_DEBUGEVENT,
                                    CB_SYSTEMBREAKPOINT, CB_BREAKPOINT, CB_EXCEPTION,
                                    CB_TRACEEXECUTE};
    for (const CBTYPE callback : callbacks) {
        _plugin_registercallback(g_pluginHandle, callback, DebuggerCallback);
    }
    if (!_plugin_registercommand(g_pluginHandle, kFenceCommand, CommandFenceCallback, true)) {
        for (const CBTYPE callback : callbacks) {
            _plugin_unregistercallback(g_pluginHandle, callback);
        }
        _plugin_logputs("[x64dbg-mcp-backend] private command fence registration failed");
        g_pluginHandle = 0;
        return false;
    }
    _plugin_logputs("[x64dbg-mcp-backend] plugin initialized");
    return true;
}

extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT* setupStruct) {
    (void)setupStruct;
    if (g_runtime.Start()) {
        _plugin_logputs(
            "[x64dbg-mcp-backend] sidecar process started; awaiting authenticated handshake");
    } else {
        _plugin_logputs("[x64dbg-mcp-backend] sidecar startup failed; check configuration and path");
    }
}

extern "C" __declspec(dllexport) bool plugstop() {
    g_runtime.Stop();
    _plugin_unregistercommand(g_pluginHandle, kFenceCommand);
    constexpr CBTYPE callbacks[] = {CB_INITDEBUG, CB_STOPDEBUG, CB_CREATEPROCESS,
                                    CB_EXITPROCESS, CB_PAUSEDEBUG, CB_RESUMEDEBUG,
                                    CB_STEPPED, CB_ATTACH, CB_DETACH, CB_STOPPINGDEBUG, CB_DEBUGEVENT,
                                    CB_SYSTEMBREAKPOINT, CB_BREAKPOINT, CB_EXCEPTION,
                                    CB_TRACEEXECUTE};
    for (const CBTYPE callback : callbacks) {
        _plugin_unregistercallback(g_pluginHandle, callback);
    }
    _plugin_logputs("[x64dbg-mcp-backend] plugin stopped");
    g_pluginHandle = 0;
    return true;
}
