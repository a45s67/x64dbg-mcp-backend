#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

#include "bridgemain.h"

namespace mcp {

enum class HardwareAccess { execute, write, readWrite };
enum class MemoryAccess { access, read, write, execute };

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

[[nodiscard]] std::string RunToBreakpointName(std::string_view operationId);
[[nodiscard]] std::string RunToBreakpointSetCommand(duint target,
                                                    std::string_view ownedName);
[[nodiscard]] bool RunToBreakpointOwned(const BRIDGEBP& breakpoint,
                                        duint target,
                                        std::string_view expectedName) noexcept;

} // namespace mcp
