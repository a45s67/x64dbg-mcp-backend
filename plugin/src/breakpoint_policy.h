#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "bridgemain.h"

namespace mcp {

enum class HardwareAccess { execute, write, readWrite };
enum class MemoryAccess { access, read, write, execute };
enum class ExceptionChance { first, second, both };
enum class ConditionalMode { all, any };
enum class ConditionalSource { registerValue, threadId, hitCount };
enum class ConditionalOperator { equal, notEqual, less, lessEqual, greater, greaterEqual,
                                 multipleOf };
enum class BreakpointTransitionKind { software, hardware, memory, conditional, exception };

struct ConditionalPredicate {
    ConditionalSource source{ConditionalSource::hitCount};
    ConditionalOperator operation{ConditionalOperator::equal};
    std::string registerName;
    std::uint64_t value{0U};
};

struct ConditionalSpec {
    ConditionalMode mode{ConditionalMode::all};
    std::vector<ConditionalPredicate> predicates;
};

[[nodiscard]] std::optional<HardwareAccess>
ParseHardwareAccess(std::string_view value) noexcept;
[[nodiscard]] const char* HardwareAccessName(HardwareAccess value) noexcept;
[[nodiscard]] const char* HardwareAccessNameFromNative(unsigned char value) noexcept;
[[nodiscard]] std::size_t HardwareSizeFromNative(unsigned char value) noexcept;
[[nodiscard]] char HardwareAccessCommand(HardwareAccess value) noexcept;
[[nodiscard]] bool HardwareRequestValid(HardwareAccess access,
                                        std::size_t size,
                                        duint address) noexcept;
[[nodiscard]] bool HardwareBreakpointMatches(const BRIDGEBP& breakpoint,
                                             HardwareAccess access,
                                             std::size_t size,
                                             bool requireEnabled) noexcept;
[[nodiscard]] bool HardwareSlotsExhausted(const BRIDGEBP* breakpoints,
                                          std::size_t count) noexcept;

[[nodiscard]] std::optional<MemoryAccess>
ParseMemoryAccess(std::string_view value) noexcept;
[[nodiscard]] const char* MemoryAccessName(MemoryAccess value) noexcept;
[[nodiscard]] const char* MemoryAccessNameFromNative(unsigned char value) noexcept;
[[nodiscard]] char MemoryAccessCommand(MemoryAccess value) noexcept;
[[nodiscard]] bool MemoryRangeContained(duint address,
                                        std::size_t size,
                                        duint regionBase,
                                        duint regionSize) noexcept;
[[nodiscard]] bool MemoryBreakpointMatches(const BRIDGEBP& breakpoint,
                                           MemoryAccess access,
                                           std::size_t size,
                                           duint observedSize,
                                           bool requireEnabled) noexcept;

[[nodiscard]] std::optional<ExceptionChance>
ParseExceptionChance(std::string_view value) noexcept;
[[nodiscard]] const char* ExceptionChanceName(ExceptionChance value) noexcept;
[[nodiscard]] const char* ExceptionChanceCommand(ExceptionChance value) noexcept;
[[nodiscard]] bool ExceptionBreakpointMatches(const BRIDGEBP& breakpoint,
                                              std::uint32_t code,
                                              ExceptionChance chance,
                                              std::string_view managedId) noexcept;
[[nodiscard]] bool ExceptionBreakpointOwned(const BRIDGEBP& breakpoint,
                                            std::uint32_t code,
                                            ExceptionChance chance,
                                            std::string_view managedId) noexcept;

[[nodiscard]] std::optional<ConditionalOperator>
ParseConditionalOperator(std::string_view value) noexcept;
[[nodiscard]] bool PortableConditionalRegister(std::string_view value) noexcept;
[[nodiscard]] std::optional<std::string>
CompileConditionalExpression(const ConditionalSpec& condition);
[[nodiscard]] std::string ManagedBreakpointName(std::string_view family,
                                                std::string_view managedId);
[[nodiscard]] std::optional<std::string>
ManagedBreakpointId(const BRIDGEBP& breakpoint, std::string_view family);
[[nodiscard]] bool ConditionalBreakpointMatches(const BRIDGEBP& breakpoint,
                                                duint address,
                                                std::string_view managedId,
                                                std::string_view expression) noexcept;
[[nodiscard]] bool ConditionalBreakpointOwned(const BRIDGEBP& breakpoint,
                                              duint address,
                                              std::string_view managedId) noexcept;

[[nodiscard]] bool PlainSoftwareBreakpointSelectable(const BRIDGEBP& breakpoint,
                                                     duint address);
[[nodiscard]] bool BreakpointConfigurationUnchanged(const BRIDGEBP& before,
                                                    const BRIDGEBP& after,
                                                    bool allowSlotChange) noexcept;
[[nodiscard]] std::string BreakpointToggleCommand(BreakpointTransitionKind kind,
                                                  duint identity,
                                                  bool enable);

[[nodiscard]] std::string RunToBreakpointName(std::string_view operationId);
[[nodiscard]] std::string RunToBreakpointSetCommand(duint target,
                                                    std::string_view ownedName);
[[nodiscard]] bool RunToBreakpointOwned(const BRIDGEBP& breakpoint,
                                        duint target,
                                        std::string_view expectedName) noexcept;

} // namespace mcp
