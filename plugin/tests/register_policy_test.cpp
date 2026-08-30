#include "register_policy.h"

#include <iostream>

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
#endif
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
