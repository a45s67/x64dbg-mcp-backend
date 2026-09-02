#include "register_policy.h"

#include <iostream>
#include <vector>

int main() {
#ifdef _WIN64
    const auto core = mcp::FindWritableRegister("r15");
    if (!core || core->bits != 64U || mcp::FindWritableRegister("eax")) {
        std::cerr << "x64 register policy failed\n";
        return 1;
    }
    CONTEXT windowsContext{};
    windowsContext.Rax = 0x1111222233334444ULL;
    windowsContext.Rsp = 0x5555666677778888ULL;
    windowsContext.Rip = 0x9999aaaabbbbccccULL;
    windowsContext.R15 = 0xddddeeeeffff0000ULL;
    windowsContext.EFlags = 0x202U;
    const REGISTERCONTEXT_AVX512 converted = mcp::CoreRegisterContext(windowsContext);
    if (converted.cax != windowsContext.Rax || converted.csp != windowsContext.Rsp ||
        converted.cip != windowsContext.Rip || converted.r15 != windowsContext.R15 ||
        converted.eflags != windowsContext.EFlags) {
        std::cerr << "x64 Windows context conversion failed\n";
        return 4;
    }
    const std::vector<mcp::RegisterAssignment> validAssignments{
        {"rdi", 0x771e0000ULL}, {"rip", 0x1e42d0cULL}};
    const std::vector<mcp::RegisterAssignment> wrongArchitecture{{"edi", 1U}};
#else
    const auto core = mcp::FindWritableRegister("edi");
    if (!core || core->bits != 32U || mcp::FindWritableRegister("rax")) {
        std::cerr << "x86 register policy failed\n";
        return 1;
    }
    CONTEXT windowsContext{};
    windowsContext.Eax = 0x11223344U;
    windowsContext.Esp = 0x55667788U;
    windowsContext.Eip = 0x99aabbccU;
    windowsContext.Edi = 0xddeeff00U;
    windowsContext.EFlags = 0x202U;
    const REGISTERCONTEXT_AVX512 converted = mcp::CoreRegisterContext(windowsContext);
    if (converted.cax != windowsContext.Eax || converted.csp != windowsContext.Esp ||
        converted.cip != windowsContext.Eip || converted.cdi != windowsContext.Edi ||
        converted.eflags != windowsContext.EFlags) {
        std::cerr << "x86 Windows context conversion failed\n";
        return 4;
    }
    const std::vector<mcp::RegisterAssignment> validAssignments{
        {"edi", 0x771e0000U}, {"eip", 0x1e42d0cU}};
    const std::vector<mcp::RegisterAssignment> wrongArchitecture{{"rdi", 1U}};
#endif
    const auto handledCommand =
        mcp::BuildExceptionContinueCommand(validAssignments, true);
    const auto notHandledCommand =
        mcp::BuildExceptionContinueCommand(validAssignments, false);
    if (!handledCommand || !notHandledCommand ||
#ifdef _WIN64
        *handledCommand != "mov rdi, 0x771e0000;mov rip, 0x1e42d0c;serun" ||
        *notHandledCommand != "mov rdi, 0x771e0000;mov rip, 0x1e42d0c;erun" ||
#else
        *handledCommand != "mov edi, 0x771e0000;mov eip, 0x1e42d0c;serun" ||
        *notHandledCommand != "mov edi, 0x771e0000;mov eip, 0x1e42d0c;erun" ||
#endif
        mcp::BuildExceptionContinueCommand(wrongArchitecture, true) ||
        mcp::BuildExceptionContinueCommand({{"eip", 1U}, {"eip", 2U}}, true) ||
        mcp::BuildExceptionContinueCommand({{"eip", 0x100000000ULL}}, true) ||
        mcp::BuildExceptionContinueCommand(
            {{"eax", 1U}, {"ebx", 2U}, {"ecx", 3U}, {"edx", 4U}, {"esi", 5U}}, true)) {
        std::cerr << "exception continuation command policy failed\n";
        return 5;
    }
    CONTEXT mutableContext{};
    mutableContext.EFlags = 0x202U;
#ifdef _WIN64
    mutableContext.Rdi = 1U;
    mutableContext.Rip = 2U;
    if (!mcp::ApplyRegisterAssignments(mutableContext, validAssignments) ||
        mutableContext.Rdi != 0x771e0000ULL || mutableContext.Rip != 0x1e42d0cULL ||
        mutableContext.EFlags != 0x202U) {
#else
    mutableContext.Edi = 1U;
    mutableContext.Eip = 2U;
    if (!mcp::ApplyRegisterAssignments(mutableContext, validAssignments) ||
        mutableContext.Edi != 0x771e0000U || mutableContext.Eip != 0x1e42d0cU ||
        mutableContext.EFlags != 0x202U) {
#endif
        std::cerr << "Windows context mutation failed\n";
        return 6;
    }
    if (mcp::ApplyRegisterAssignments(mutableContext, {}) ||
        mcp::ApplyRegisterAssignments(mutableContext, wrongArchitecture) ||
        mcp::ApplyRegisterAssignments(mutableContext, {{"eip", 1U}, {"eip", 2U}})) {
        std::cerr << "invalid Windows context mutation was accepted\n";
        return 7;
    }
    const auto flags = mcp::FindWritableRegister("eflags");
    if (!flags || flags->bits != 32U || mcp::FindWritableRegister("al") ||
        mcp::FindWritableRegister("dr0") || mcp::FindWritableRegister("RAX")) {
        std::cerr << "restricted register policy failed\n";
        return 2;
    }
    if (!mcp::IsReturnInstruction("ret") || !mcp::IsReturnInstruction("  RET 0x10") ||
        !mcp::IsReturnInstruction("retf") || mcp::IsReturnInstruction("retry") ||
        mcp::IsReturnInstruction("jmp ret")) {
        std::cerr << "return instruction classification failed\n";
        return 3;
    }
    return 0;
}
