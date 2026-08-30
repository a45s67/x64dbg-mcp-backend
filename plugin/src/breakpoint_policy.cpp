#include "breakpoint_policy.h"

#include <cstring>
#include <iomanip>
#include <limits>
#include <sstream>

namespace mcp {
namespace {

std::optional<BPHWSIZE> NativeHardwareSize(const std::size_t size) noexcept {
    switch (size) {
    case 1U: return hw_byte;
    case 2U: return hw_word;
    case 4U: return hw_dword;
#ifdef _WIN64
    case 8U: return hw_qword;
#endif
    default: return std::nullopt;
    }
}

BPHWTYPE NativeHardwareAccess(const HardwareAccess access) noexcept {
    switch (access) {
    case HardwareAccess::execute: return hw_execute;
    case HardwareAccess::write: return hw_write;
    case HardwareAccess::readWrite: return hw_access;
    }
    return hw_execute;
}

BPMEMTYPE NativeMemoryAccess(const MemoryAccess access) noexcept {
    switch (access) {
    case MemoryAccess::access: return mem_access;
    case MemoryAccess::read: return mem_read;
    case MemoryAccess::write: return mem_write;
    case MemoryAccess::execute: return mem_execute;
    }
    return mem_access;
}

BPEXTYPE NativeExceptionChance(const ExceptionChance chance) noexcept {
    switch (chance) {
    case ExceptionChance::first: return ex_firstchance;
    case ExceptionChance::second: return ex_secondchance;
    case ExceptionChance::both: return ex_all;
    }
    return ex_firstchance;
}

bool CanonicalManagedId(const std::string_view value) noexcept {
    if (value.size() != 36U) return false;
    for (std::size_t index = 0U; index < value.size(); ++index) {
        const char character = value[index];
        if (index == 8U || index == 13U || index == 18U || index == 23U) {
            if (character != '-') return false;
        } else if (!((character >= '0' && character <= '9') ||
                     (character >= 'a' && character <= 'f'))) {
            return false;
        }
    }
    return true;
}

bool BoundedFieldEquals(const char* field, const std::size_t capacity,
                        const std::string_view expected) noexcept {
    const std::size_t length = strnlen_s(field, capacity);
    return length < capacity && std::string_view(field, length) == expected;
}

bool EmptyActionFields(const BRIDGEBP& breakpoint) noexcept {
    return breakpoint.logText[0] == '\0' && breakpoint.logCondition[0] == '\0' &&
           breakpoint.commandText[0] == '\0' && breakpoint.commandCondition[0] == '\0';
}

const char* ConditionalOperatorToken(const ConditionalOperator operation) noexcept {
    switch (operation) {
    case ConditionalOperator::equal: return "==";
    case ConditionalOperator::notEqual: return "!=";
    case ConditionalOperator::less: return "<";
    case ConditionalOperator::lessEqual: return "<=";
    case ConditionalOperator::greater: return ">";
    case ConditionalOperator::greaterEqual: return ">=";
    case ConditionalOperator::multipleOf: return "%";
    }
    return nullptr;
}

std::string HexConstant(const std::uint64_t value) {
    std::ostringstream output;
    output << "0x" << std::hex << std::nouppercase << value;
    return output.str();
}

} // namespace

std::optional<HardwareAccess> ParseHardwareAccess(const std::string_view value) noexcept {
    if (value == "execute") return HardwareAccess::execute;
    if (value == "write") return HardwareAccess::write;
    if (value == "read_write") return HardwareAccess::readWrite;
    return std::nullopt;
}

const char* HardwareAccessName(const HardwareAccess value) noexcept {
    switch (value) {
    case HardwareAccess::execute: return "execute";
    case HardwareAccess::write: return "write";
    case HardwareAccess::readWrite: return "read_write";
    }
    return "unknown";
}

const char* HardwareAccessNameFromNative(const unsigned char value) noexcept {
    switch (static_cast<BPHWTYPE>(value)) {
    case hw_execute: return "execute";
    case hw_write: return "write";
    case hw_access: return "read_write";
    }
    return "unknown";
}

std::size_t HardwareSizeFromNative(const unsigned char value) noexcept {
    switch (static_cast<BPHWSIZE>(value)) {
    case hw_byte: return 1U;
    case hw_word: return 2U;
    case hw_dword: return 4U;
    case hw_qword: return 8U;
    }
    return 0U;
}

char HardwareAccessCommand(const HardwareAccess value) noexcept {
    switch (value) {
    case HardwareAccess::execute: return 'x';
    case HardwareAccess::write: return 'w';
    case HardwareAccess::readWrite: return 'r';
    }
    return '?';
}

bool HardwareRequestValid(const HardwareAccess access,
                          const std::size_t size,
                          const duint address) noexcept {
    if (!NativeHardwareSize(size)) return false;
    if (access == HardwareAccess::execute && size != 1U) return false;
    return address % static_cast<duint>(size) == 0U;
}

bool HardwareBreakpointMatches(const BRIDGEBP& breakpoint,
                               const HardwareAccess access,
                               const std::size_t size,
                               const bool requireEnabled) noexcept {
    const auto nativeSize = NativeHardwareSize(size);
    return nativeSize && breakpoint.type == bp_hardware &&
           (!requireEnabled || (breakpoint.enabled && breakpoint.slot < 4U)) &&
           breakpoint.typeEx == static_cast<unsigned char>(NativeHardwareAccess(access)) &&
           breakpoint.hwSize == static_cast<unsigned char>(*nativeSize);
}

bool HardwareSlotsExhausted(const BRIDGEBP* breakpoints, const std::size_t count) noexcept {
    if (breakpoints == nullptr && count != 0U) return false;
    bool represented[4]{false, false, false, false};
    for (std::size_t index = 0; index < count; ++index) {
        const BRIDGEBP& breakpoint = breakpoints[index];
        if (breakpoint.type == bp_hardware && breakpoint.enabled && breakpoint.slot < 4U) {
            represented[breakpoint.slot] = true;
        }
    }
    return represented[0] && represented[1] && represented[2] && represented[3];
}

std::optional<MemoryAccess> ParseMemoryAccess(const std::string_view value) noexcept {
    if (value == "access") return MemoryAccess::access;
    if (value == "read") return MemoryAccess::read;
    if (value == "write") return MemoryAccess::write;
    if (value == "execute") return MemoryAccess::execute;
    return std::nullopt;
}

const char* MemoryAccessName(const MemoryAccess value) noexcept {
    switch (value) {
    case MemoryAccess::access: return "access";
    case MemoryAccess::read: return "read";
    case MemoryAccess::write: return "write";
    case MemoryAccess::execute: return "execute";
    }
    return "unknown";
}

const char* MemoryAccessNameFromNative(const unsigned char value) noexcept {
    switch (static_cast<BPMEMTYPE>(value)) {
    case mem_access: return "access";
    case mem_read: return "read";
    case mem_write: return "write";
    case mem_execute: return "execute";
    }
    return "unknown";
}

char MemoryAccessCommand(const MemoryAccess value) noexcept {
    switch (value) {
    case MemoryAccess::access: return 'a';
    case MemoryAccess::read: return 'r';
    case MemoryAccess::write: return 'w';
    case MemoryAccess::execute: return 'x';
    }
    return '?';
}

bool MemoryRangeContained(const duint address,
                          const std::size_t size,
                          const duint regionBase,
                          const duint regionSize) noexcept {
    if (size == 0U || size > 65'536U || regionSize == 0U || address < regionBase) return false;
    const duint offset = address - regionBase;
    if (offset >= regionSize) return false;
    return static_cast<duint>(size) <= regionSize - offset;
}

bool MemoryBreakpointMatches(const BRIDGEBP& breakpoint,
                             const MemoryAccess access,
                             const std::size_t size,
                             const duint observedSize,
                             const bool requireEnabled) noexcept {
    return breakpoint.type == bp_memory && (!requireEnabled || breakpoint.enabled) &&
           breakpoint.typeEx == static_cast<unsigned char>(NativeMemoryAccess(access)) &&
           observedSize == static_cast<duint>(size);
}

std::optional<ExceptionChance> ParseExceptionChance(const std::string_view value) noexcept {
    if (value == "first") return ExceptionChance::first;
    if (value == "second") return ExceptionChance::second;
    if (value == "both") return ExceptionChance::both;
    return std::nullopt;
}

const char* ExceptionChanceName(const ExceptionChance value) noexcept {
    switch (value) {
    case ExceptionChance::first: return "first";
    case ExceptionChance::second: return "second";
    case ExceptionChance::both: return "both";
    }
    return "unknown";
}

const char* ExceptionChanceCommand(const ExceptionChance value) noexcept {
    switch (value) {
    case ExceptionChance::first: return "first";
    case ExceptionChance::second: return "second";
    case ExceptionChance::both: return "all";
    }
    return "unknown";
}

std::string ManagedBreakpointName(const std::string_view family,
                                  const std::string_view managedId) {
    if ((family != "exception" && family != "conditional") ||
        !CanonicalManagedId(managedId)) {
        return {};
    }
    return "__x64dbg_mcp_" + std::string(family) + "_" + std::string(managedId);
}

std::optional<std::string> ManagedBreakpointId(const BRIDGEBP& breakpoint,
                                               const std::string_view family) {
    const std::string prefix = "__x64dbg_mcp_" + std::string(family) + "_";
    const std::size_t length = strnlen_s(breakpoint.name, sizeof(breakpoint.name));
    if (length >= sizeof(breakpoint.name)) return std::nullopt;
    const std::string_view name(breakpoint.name, length);
    if (!name.starts_with(prefix)) return std::nullopt;
    const std::string_view id = name.substr(prefix.size());
    if (!CanonicalManagedId(id)) return std::nullopt;
    return std::string(id);
}

bool ExceptionBreakpointMatches(const BRIDGEBP& breakpoint,
                                const std::uint32_t code,
                                const ExceptionChance chance,
                                const std::string_view managedId) noexcept {
    const std::string expectedName = ManagedBreakpointName("exception", managedId);
    return !expectedName.empty() && breakpoint.type == bp_exception &&
           breakpoint.addr == static_cast<duint>(code) && breakpoint.enabled &&
           breakpoint.typeEx == static_cast<unsigned char>(NativeExceptionChance(chance)) &&
           BoundedFieldEquals(breakpoint.name, sizeof(breakpoint.name), expectedName) &&
           breakpoint.breakCondition[0] == '\0' && EmptyActionFields(breakpoint);
}

std::optional<ConditionalOperator>
ParseConditionalOperator(const std::string_view value) noexcept {
    if (value == "eq") return ConditionalOperator::equal;
    if (value == "ne") return ConditionalOperator::notEqual;
    if (value == "lt") return ConditionalOperator::less;
    if (value == "le") return ConditionalOperator::lessEqual;
    if (value == "gt") return ConditionalOperator::greater;
    if (value == "ge") return ConditionalOperator::greaterEqual;
    if (value == "multiple_of") return ConditionalOperator::multipleOf;
    return std::nullopt;
}

bool PortableConditionalRegister(const std::string_view value) noexcept {
    return value == "cax" || value == "cbx" || value == "ccx" || value == "cdx" ||
           value == "csi" || value == "cdi" || value == "cbp" || value == "csp" ||
           value == "cip";
}

std::optional<std::string> CompileConditionalExpression(const ConditionalSpec& condition) {
    if (condition.predicates.empty() || condition.predicates.size() > 4U) return std::nullopt;
    std::string expression;
    for (std::size_t index = 0U; index < condition.predicates.size(); ++index) {
        const ConditionalPredicate& predicate = condition.predicates[index];
        if (index != 0U) {
            expression += condition.mode == ConditionalMode::all ? "&&" : "||";
        }
        const char* token = ConditionalOperatorToken(predicate.operation);
        if (token == nullptr) return std::nullopt;
        std::string source;
        switch (predicate.source) {
        case ConditionalSource::registerValue:
            if (!PortableConditionalRegister(predicate.registerName) ||
                predicate.operation == ConditionalOperator::multipleOf ||
                predicate.value > static_cast<std::uint64_t>((std::numeric_limits<duint>::max)())) {
                return std::nullopt;
            }
            source = predicate.registerName;
            break;
        case ConditionalSource::threadId:
            if (!predicate.registerName.empty() ||
                (predicate.operation != ConditionalOperator::equal &&
                 predicate.operation != ConditionalOperator::notEqual) ||
                predicate.value > (std::numeric_limits<std::uint32_t>::max)()) {
                return std::nullopt;
            }
            source = "tid()";
            break;
        case ConditionalSource::hitCount:
            if (!predicate.registerName.empty() || predicate.value == 0U ||
                predicate.value > (std::numeric_limits<std::uint32_t>::max)()) {
                return std::nullopt;
            }
            source = "$breakpointcounter";
            break;
        }
        const std::string value = HexConstant(predicate.value);
        if (predicate.operation == ConditionalOperator::multipleOf) {
            expression += "((" + source + "%" + value + ")==0)";
        } else {
            expression += "(" + source + token + value + ")";
        }
        if (expression.size() >= MAX_CONDITIONAL_EXPR_SIZE) return std::nullopt;
    }
    return expression;
}

bool ConditionalBreakpointOwned(const BRIDGEBP& breakpoint,
                                const duint address,
                                const std::string_view managedId) noexcept {
    const std::string expectedName = ManagedBreakpointName("conditional", managedId);
    return !expectedName.empty() && breakpoint.type == bp_normal && breakpoint.addr == address &&
           BoundedFieldEquals(breakpoint.name, sizeof(breakpoint.name), expectedName);
}

bool ConditionalBreakpointMatches(const BRIDGEBP& breakpoint,
                                  const duint address,
                                  const std::string_view managedId,
                                  const std::string_view expression) noexcept {
    return ConditionalBreakpointOwned(breakpoint, address, managedId) && breakpoint.enabled &&
           breakpoint.active && !breakpoint.singleshoot && breakpoint.fastResume &&
           BoundedFieldEquals(breakpoint.breakCondition, sizeof(breakpoint.breakCondition),
                              expression) &&
           EmptyActionFields(breakpoint);
}

std::string RunToBreakpointName(const std::string_view operationId) {
    return "__x64dbg_mcp_run_to_" + std::string(operationId);
}

std::string RunToBreakpointSetCommand(const duint target,
                                      const std::string_view ownedName) {
    std::ostringstream command;
    command << "bp 0x" << std::hex << std::nouppercase << target << ", \""
            << ownedName << "\", ss";
    return command.str();
}

bool RunToBreakpointOwned(const BRIDGEBP& breakpoint,
                          const duint target,
                          const std::string_view expectedName) noexcept {
    const std::size_t length = strnlen_s(breakpoint.name, sizeof(breakpoint.name));
    return breakpoint.type == bp_normal && breakpoint.addr == target &&
           breakpoint.singleshoot && length < sizeof(breakpoint.name) &&
           std::string_view(breakpoint.name, length) == expectedName;
}

} // namespace mcp
