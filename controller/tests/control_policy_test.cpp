#include "control_policy.h"

#include <cassert>
#include <string>

int main() {
    std::string error;
    const auto config = mcp::control::ParseServerConfig(
        "bind = \"127.0.0.1\"\r\nport = 43164\r\n"
        "bearer_token = \"0123456789abcdef0123456789abcdef\"",
        error);
    assert(config);
    assert(config->port == 43164U);
    assert(config->bearerToken.size() == 32U);
    assert(!mcp::control::ParseServerConfig(
        "bind=\"0.0.0.0\"\nport=1\nbearer_token=\"0123456789abcdef0123456789abcdef\"",
        error));
    assert(!mcp::control::ParseServerConfig(
        "bind=\"127.0.0.1\"\nport=1\nbearer_token=\"0123456789abcdef0123456789abcdef\"\nextra=1",
        error));

    constexpr std::string_view ini =
        "[SETTINGS]\r\nCurrentProfile=Basic\r\n[Basic]\r\nPebBeingDebugged=1\r\n"
        "[VMProtect x86/x64]\r\nPebBeingDebugged=1\r\n";
    const auto parsed = mcp::control::ParseScyllaHideConfig(ini, error);
    assert(parsed);
    assert(parsed->currentProfile == "Basic");
    assert(parsed->availableProfiles.size() == 2U);
    const auto updated =
        mcp::control::SetScyllaHideProfile(ini, "vmprotect x86/x64", error);
    assert(updated);
    assert(updated->canonicalProfile == "VMProtect x86/x64");
    assert(updated->text.find("CurrentProfile=VMProtect x86/x64\r\n") != std::string::npos);
    assert(updated->text.find("[Basic]\r\n") != std::string::npos);
    assert(!mcp::control::SetScyllaHideProfile(ini, "Missing", error));
    assert(!mcp::control::SetScyllaHideProfile(ini, "bad\nname", error));

    assert(mcp::control::IsCanonicalUuid("01234567-89ab-4cde-8fab-0123456789ab"));
    assert(!mcp::control::IsCanonicalUuid("01234567-89AB-4CDE-8FAB-0123456789AB"));
    return 0;
}
