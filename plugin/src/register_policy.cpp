#include "register_policy.h"

#include <cctype>

namespace mcp {

std::optional<WritableRegister> FindWritableRegister(const std::string_view name) noexcept {
    using enum Script::Register::RegisterEnum;
#ifdef _WIN64
    if (name == "rax") return WritableRegister{RAX, 64U};
    if (name == "rbx") return WritableRegister{RBX, 64U};
    if (name == "rcx") return WritableRegister{RCX, 64U};
    if (name == "rdx") return WritableRegister{RDX, 64U};
    if (name == "rsi") return WritableRegister{RSI, 64U};
    if (name == "rdi") return WritableRegister{RDI, 64U};
    if (name == "rbp") return WritableRegister{RBP, 64U};
    if (name == "rsp") return WritableRegister{RSP, 64U};
    if (name == "rip") return WritableRegister{RIP, 64U};
    if (name == "r8") return WritableRegister{R8, 64U};
    if (name == "r9") return WritableRegister{R9, 64U};
    if (name == "r10") return WritableRegister{R10, 64U};
    if (name == "r11") return WritableRegister{R11, 64U};
    if (name == "r12") return WritableRegister{R12, 64U};
    if (name == "r13") return WritableRegister{R13, 64U};
    if (name == "r14") return WritableRegister{R14, 64U};
    if (name == "r15") return WritableRegister{R15, 64U};
#else
    if (name == "eax") return WritableRegister{EAX, 32U};
    if (name == "ebx") return WritableRegister{EBX, 32U};
    if (name == "ecx") return WritableRegister{ECX, 32U};
    if (name == "edx") return WritableRegister{EDX, 32U};
    if (name == "esi") return WritableRegister{ESI, 32U};
    if (name == "edi") return WritableRegister{EDI, 32U};
    if (name == "ebp") return WritableRegister{EBP, 32U};
    if (name == "esp") return WritableRegister{ESP, 32U};
    if (name == "eip") return WritableRegister{EIP, 32U};
#endif
    if (name == "eflags") return WritableRegister{CFLAGS, 32U};
    return std::nullopt;
}

bool IsReturnInstruction(const std::string_view instruction) noexcept {
    const std::size_t start = instruction.find_first_not_of(" \t");
    if (start == std::string_view::npos) return false;
    const std::size_t end = instruction.find_first_of(" \t", start);
    const std::string_view mnemonic = instruction.substr(start, end - start);
    if (mnemonic.size() < 3U || mnemonic.size() > 4U) return false;
    char lowered[4]{};
    for (std::size_t index = 0; index < mnemonic.size(); ++index) {
        lowered[index] = static_cast<char>(
            std::tolower(static_cast<unsigned char>(mnemonic[index])));
    }
    const std::string_view normalized(lowered, mnemonic.size());
    return normalized == "ret" || normalized == "retn" || normalized == "retf";
}

} // namespace mcp
