#include "breakpoint_policy.h"

#include <cstring>
#include <iomanip>
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
