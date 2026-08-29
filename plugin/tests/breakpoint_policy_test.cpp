#include "breakpoint_policy.h"

#include <iostream>
#include <limits>

int main() {
    const auto execute = mcp::ParseHardwareAccess("execute");
    const auto write = mcp::ParseHardwareAccess("write");
    const auto readWrite = mcp::ParseHardwareAccess("read_write");
    if (!execute || !write || !readWrite || mcp::ParseHardwareAccess("read") ||
        mcp::HardwareAccessCommand(*readWrite) != 'r' ||
        !mcp::HardwareRequestValid(*execute, 1U, 0x1001U) ||
        mcp::HardwareRequestValid(*execute, 2U, 0x1000U) ||
        mcp::HardwareRequestValid(*write, 4U, 0x1002U)) {
        std::cerr << "hardware request policy failed\n";
        return 1;
    }
#ifdef _WIN64
    if (!mcp::HardwareRequestValid(*write, 8U, 0x1000U)) {
        std::cerr << "x64 hardware size policy failed\n";
        return 2;
    }
#else
    if (mcp::HardwareRequestValid(*write, 8U, 0x1000U)) {
        std::cerr << "x86 hardware size policy failed\n";
        return 2;
    }
#endif

    BRIDGEBP hardware{};
    hardware.type = bp_hardware;
    hardware.enabled = true;
    hardware.slot = 2U;
    hardware.typeEx = static_cast<unsigned char>(hw_write);
    hardware.hwSize = static_cast<unsigned char>(hw_dword);
    if (!mcp::HardwareBreakpointMatches(hardware, *write, 4U, true) ||
        mcp::HardwareBreakpointMatches(hardware, *readWrite, 4U, true)) {
        std::cerr << "hardware read-back policy failed\n";
        return 3;
    }
    hardware.enabled = false;
    hardware.slot = 0xffffU;
    if (!mcp::HardwareBreakpointMatches(hardware, *write, 4U, false) ||
        mcp::HardwareBreakpointMatches(hardware, *write, 4U, true)) {
        std::cerr << "disabled hardware removal policy failed\n";
        return 3;
    }
    BRIDGEBP slots[5]{};
    for (unsigned short index = 0U; index < 4U; ++index) {
        slots[index].type = bp_hardware;
        slots[index].enabled = true;
        slots[index].slot = index;
    }
    slots[4].type = bp_hardware;
    slots[4].enabled = false;
    slots[4].slot = 0U;
    if (!mcp::HardwareSlotsExhausted(slots, 5U)) {
        std::cerr << "hardware slot exhaustion policy failed\n";
        return 4;
    }
    slots[3].enabled = false;
    if (mcp::HardwareSlotsExhausted(slots, 5U)) {
        std::cerr << "disabled hardware slot policy failed\n";
        return 4;
    }

    const auto memoryWrite = mcp::ParseMemoryAccess("write");
    if (!memoryWrite || mcp::ParseMemoryAccess("read_write") ||
        !mcp::MemoryRangeContained(0x1100U, 0x100U, 0x1000U, 0x1000U) ||
        mcp::MemoryRangeContained(0x1ff0U, 0x20U, 0x1000U, 0x1000U) ||
        mcp::MemoryRangeContained(std::numeric_limits<duint>::max(), 2U,
                                  std::numeric_limits<duint>::max(), 1U)) {
        std::cerr << "memory range policy failed\n";
        return 5;
    }
    BRIDGEBP memory{};
    memory.type = bp_memory;
    memory.enabled = true;
    memory.typeEx = static_cast<unsigned char>(mem_write);
    if (!mcp::MemoryBreakpointMatches(memory, *memoryWrite, 16U, 16U, true) ||
        mcp::MemoryBreakpointMatches(memory, *memoryWrite, 16U, 8U, true)) {
        std::cerr << "memory read-back policy failed\n";
        return 6;
    }
    return 0;
}
