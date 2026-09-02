#pragma once

#include <Windows.h>

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "_scriptapi_register.h"
#include "bridgemain.h"

namespace mcp {

struct WritableRegister {
    Script::Register::RegisterEnum id;
    unsigned int bits;
};

struct RegisterAssignment {
    std::string name;
    std::uint64_t value{0U};
};

[[nodiscard]] std::optional<WritableRegister>
FindWritableRegister(std::string_view name) noexcept;

[[nodiscard]] std::optional<std::string> BuildExceptionContinueCommand(
    const std::vector<RegisterAssignment>& assignments, bool handled) noexcept;

[[nodiscard]] bool IsReturnInstruction(std::string_view instruction) noexcept;

[[nodiscard]] REGISTERCONTEXT_AVX512
CoreRegisterContext(const CONTEXT& context) noexcept;

} // namespace mcp
