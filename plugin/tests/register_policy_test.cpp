#include "register_policy.h"

#include <iostream>

int main() {
#ifdef _WIN64
    const auto core = mcp::FindWritableRegister("r15");
    if (!core || core->bits != 64U || mcp::FindWritableRegister("eax")) {
        std::cerr << "x64 register policy failed\n";
        return 1;
    }
#else
    const auto core = mcp::FindWritableRegister("edi");
    if (!core || core->bits != 32U || mcp::FindWritableRegister("rax")) {
        std::cerr << "x86 register policy failed\n";
        return 1;
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
