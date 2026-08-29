#pragma once

#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace mcp {

[[nodiscard]] bool SafeInstruction(std::string_view value) noexcept;
[[nodiscard]] std::optional<std::vector<unsigned char>>
ParsePatchBytes(std::string_view value);
[[nodiscard]] std::optional<std::vector<unsigned char>>
PreparePatchBytes(std::span<const unsigned char> assembled,
                  std::span<const unsigned char> expected,
                  bool fillNop);
[[nodiscard]] bool PatchRangeValid(duint address, std::size_t size) noexcept;
[[nodiscard]] bool PatchRecordMatches(const DBGPATCHINFO& record,
                                      duint address,
                                      unsigned char original,
                                      unsigned char patched) noexcept;

} // namespace mcp
