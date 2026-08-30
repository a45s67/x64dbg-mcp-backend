#pragma once

#include <Windows.h>

#include <optional>
#include <string_view>

#include "_scriptapi_register.h"
#include "bridgemain.h"

namespace mcp {

struct WritableRegister {
    Script::Register::RegisterEnum id;
    unsigned int bits;
};

[[nodiscard]] std::optional<WritableRegister>
FindWritableRegister(std::string_view name) noexcept;

[[nodiscard]] bool IsReturnInstruction(std::string_view instruction) noexcept;

[[nodiscard]] REGISTERCONTEXT_AVX512
CoreRegisterContext(const CONTEXT& context) noexcept;

} // namespace mcp
