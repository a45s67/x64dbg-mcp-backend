#include <Windows.h>

#include "_plugins.h"
#include "runtime.h"

namespace {
constexpr char kPluginName[] = "x64dbg-mcp-backend";
constexpr int kPluginVersion = 1;
int g_pluginHandle = 0;
mcp::Runtime g_runtime;

void DebuggerCallback(const CBTYPE callbackType, void* callbackInfo) {
    g_runtime.OnDebuggerEvent(static_cast<int>(callbackType), callbackInfo);
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
                                    CB_STEPPED, CB_STOPPINGDEBUG, CB_DEBUGEVENT};
    for (const CBTYPE callback : callbacks) {
        _plugin_registercallback(g_pluginHandle, callback, DebuggerCallback);
    }
    _plugin_logputs("[x64dbg-mcp-backend] plugin initialized");
    return true;
}

extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT* setupStruct) {
    (void)setupStruct;
    if (g_runtime.Start()) {
        _plugin_logputs("[x64dbg-mcp-backend] sidecar supervision started");
    } else {
        _plugin_logputs("[x64dbg-mcp-backend] sidecar startup failed; check configuration and path");
    }
}

extern "C" __declspec(dllexport) bool plugstop() {
    g_runtime.Stop();
    constexpr CBTYPE callbacks[] = {CB_INITDEBUG, CB_STOPDEBUG, CB_CREATEPROCESS,
                                    CB_EXITPROCESS, CB_PAUSEDEBUG, CB_RESUMEDEBUG,
                                    CB_STEPPED, CB_STOPPINGDEBUG, CB_DEBUGEVENT};
    for (const CBTYPE callback : callbacks) {
        _plugin_unregistercallback(g_pluginHandle, callback);
    }
    _plugin_logputs("[x64dbg-mcp-backend] plugin stopped");
    g_pluginHandle = 0;
    return true;
}
