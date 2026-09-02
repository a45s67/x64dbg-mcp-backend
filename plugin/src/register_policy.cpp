#include "register_policy.h"

#include <algorithm>
#include <charconv>
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

std::optional<std::string> BuildExceptionContinueCommand(
    const std::vector<RegisterAssignment>& assignments, const bool handled) noexcept {
    if (assignments.size() > 4U) return std::nullopt;
    std::string command;
    command.reserve(assignments.size() * 32U + 5U);
    for (std::size_t index = 0U; index < assignments.size(); ++index) {
        const RegisterAssignment& assignment = assignments[index];
        const std::optional<WritableRegister> spec = FindWritableRegister(assignment.name);
        if (!spec ||
            (spec->bits < 64U && assignment.value >= (std::uint64_t{1U} << spec->bits)) ||
            std::find_if(assignments.begin(), assignments.begin() + index,
                         [&assignment](const RegisterAssignment& earlier) {
                             return earlier.name == assignment.name;
                         }) != assignments.begin() + index) {
            return std::nullopt;
        }
        char encoded[16]{};
        const auto result =
            std::to_chars(encoded, encoded + sizeof(encoded), assignment.value, 16);
        if (result.ec != std::errc{}) return std::nullopt;
        command += "mov ";
        command += assignment.name;
        command += ", 0x";
        command.append(encoded, result.ptr);
        command += ';';
    }
    command += handled ? "serun" : "erun";
    return command;
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

REGISTERCONTEXT_AVX512 CoreRegisterContext(const CONTEXT& context) noexcept {
    REGISTERCONTEXT_AVX512 result{};
#ifdef _WIN64
    result.cax = context.Rax;
    result.ccx = context.Rcx;
    result.cdx = context.Rdx;
    result.cbx = context.Rbx;
    result.csp = context.Rsp;
    result.cbp = context.Rbp;
    result.csi = context.Rsi;
    result.cdi = context.Rdi;
    result.r8 = context.R8;
    result.r9 = context.R9;
    result.r10 = context.R10;
    result.r11 = context.R11;
    result.r12 = context.R12;
    result.r13 = context.R13;
    result.r14 = context.R14;
    result.r15 = context.R15;
    result.cip = context.Rip;
#else
    result.cax = context.Eax;
    result.ccx = context.Ecx;
    result.cdx = context.Edx;
    result.cbx = context.Ebx;
    result.csp = context.Esp;
    result.cbp = context.Ebp;
    result.csi = context.Esi;
    result.cdi = context.Edi;
    result.cip = context.Eip;
#endif
    result.eflags = context.EFlags;
    return result;
}

} // namespace mcp
