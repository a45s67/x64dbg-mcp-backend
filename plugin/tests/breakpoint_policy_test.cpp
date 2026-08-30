#include "breakpoint_policy.h"

#include <iostream>
#include <limits>
#include <cstring>

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

    const std::string runToName =
        mcp::RunToBreakpointName("01234567-89ab-4cde-8fab-0123456789ab");
    if (runToName != "__x64dbg_mcp_run_to_01234567-89ab-4cde-8fab-0123456789ab" ||
        mcp::RunToBreakpointSetCommand(0x1234U, runToName) !=
            "bp 0x1234, \"__x64dbg_mcp_run_to_01234567-89ab-4cde-8fab-0123456789ab\", ss") {
        std::cerr << "run-to fixed command policy failed\n";
        return 7;
    }
    BRIDGEBP runTo{};
    runTo.type = bp_normal;
    runTo.addr = 0x1234U;
    runTo.singleshoot = true;
    memcpy_s(runTo.name, sizeof(runTo.name), runToName.data(), runToName.size());
    if (!mcp::RunToBreakpointOwned(runTo, 0x1234U, runToName)) {
        std::cerr << "run-to ownership policy failed\n";
        return 7;
    }
    runTo.singleshoot = false;
    if (mcp::RunToBreakpointOwned(runTo, 0x1234U, runToName)) {
        std::cerr << "run-to single-shot policy failed\n";
        return 7;
    }
    runTo.singleshoot = true;
    if (mcp::RunToBreakpointOwned(runTo, 0x1235U, runToName) ||
        mcp::RunToBreakpointOwned(runTo, 0x1234U, runToName + "-changed")) {
        std::cerr << "run-to exact identity policy failed\n";
        return 7;
    }

    constexpr std::string_view managedId = "01234567-89ab-4cde-8fab-0123456789ab";
    const auto first = mcp::ParseExceptionChance("first");
    const auto second = mcp::ParseExceptionChance("second");
    const auto both = mcp::ParseExceptionChance("both");
    if (!first || !second || !both || mcp::ParseExceptionChance("all") ||
        std::string_view(mcp::ExceptionChanceCommand(*both)) != "all" ||
        std::string_view(mcp::ExceptionChanceName(*both)) != "both") {
        std::cerr << "exception chance policy failed\n";
        return 8;
    }
    const std::string exceptionName = mcp::ManagedBreakpointName("exception", managedId);
    if (exceptionName != "__x64dbg_mcp_exception_01234567-89ab-4cde-8fab-0123456789ab" ||
        !mcp::ManagedBreakpointName("other", managedId).empty() ||
        !mcp::ManagedBreakpointName("exception", "not-a-uuid").empty()) {
        std::cerr << "managed breakpoint naming policy failed\n";
        return 8;
    }
    BRIDGEBP exception{};
    exception.type = bp_exception;
    exception.addr = 0xe0424242U;
    exception.enabled = true;
    exception.typeEx = static_cast<unsigned char>(ex_firstchance);
    memcpy_s(exception.name, sizeof(exception.name), exceptionName.data(), exceptionName.size());
    if (!mcp::ExceptionBreakpointMatches(exception, 0xe0424242U, *first, managedId) ||
        mcp::ExceptionBreakpointMatches(exception, 0xe0424242U, *second, managedId) ||
        !mcp::ManagedBreakpointId(exception, "exception") ||
        *mcp::ManagedBreakpointId(exception, "exception") != managedId) {
        std::cerr << "exception ownership policy failed\n";
        return 8;
    }
    exception.commandText[0] = 'r';
    if (mcp::ExceptionBreakpointMatches(exception, 0xe0424242U, *first, managedId)) {
        std::cerr << "exception action-field policy failed\n";
        return 8;
    }

    mcp::ConditionalSpec condition;
    condition.mode = mcp::ConditionalMode::all;
    condition.predicates = {
        {mcp::ConditionalSource::registerValue, mcp::ConditionalOperator::equal, "cax", 1U},
        {mcp::ConditionalSource::threadId, mcp::ConditionalOperator::notEqual, "", 0x20U},
        {mcp::ConditionalSource::hitCount, mcp::ConditionalOperator::multipleOf, "", 3U},
    };
    const auto expression = mcp::CompileConditionalExpression(condition);
    if (!expression ||
        *expression != "(cax==0x1)&&(tid()!=0x20)&&(($breakpointcounter%0x3)==0)") {
        std::cerr << "conditional compiler policy failed\n";
        return 9;
    }
    condition.predicates[0].registerName = "rax";
    if (mcp::CompileConditionalExpression(condition)) {
        std::cerr << "architecture-specific condition register was accepted\n";
        return 9;
    }
    condition.predicates[0].registerName = "cax";
    condition.predicates[2].value = 0U;
    if (mcp::CompileConditionalExpression(condition)) {
        std::cerr << "zero conditional divisor was accepted\n";
        return 9;
    }
    condition.predicates = {
        {mcp::ConditionalSource::hitCount, mcp::ConditionalOperator::equal, "", 2U},
    };
    const auto hitExpression = mcp::CompileConditionalExpression(condition);
    if (!hitExpression) {
        std::cerr << "hit-count conditional compiler failed\n";
        return 9;
    }
    const std::string conditionalName = mcp::ManagedBreakpointName("conditional", managedId);
    BRIDGEBP conditional{};
    conditional.type = bp_normal;
    conditional.addr = 0x1234U;
    conditional.enabled = true;
    conditional.active = true;
    conditional.fastResume = true;
    memcpy_s(conditional.name, sizeof(conditional.name), conditionalName.data(),
             conditionalName.size());
    memcpy_s(conditional.breakCondition, sizeof(conditional.breakCondition),
             hitExpression->data(), hitExpression->size());
    if (!mcp::ConditionalBreakpointMatches(conditional, 0x1234U, managedId, *hitExpression) ||
        !mcp::ConditionalBreakpointOwned(conditional, 0x1234U, managedId) ||
        !mcp::ManagedBreakpointId(conditional, "conditional") ||
        *mcp::ManagedBreakpointId(conditional, "conditional") != managedId) {
        std::cerr << "conditional ownership policy failed\n";
        return 9;
    }
    conditional.fastResume = false;
    if (mcp::ConditionalBreakpointMatches(conditional, 0x1234U, managedId, *hitExpression)) {
        std::cerr << "conditional fast-resume policy failed\n";
        return 9;
    }
    return 0;
}
